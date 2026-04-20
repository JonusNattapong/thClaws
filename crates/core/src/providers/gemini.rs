//! Google Gemini provider — `generativelanguage.googleapis.com/v1beta` with
//! SSE streaming.
//!
//! Wire shape (different enough from Anthropic/OpenAI to warrant its own adapter):
//! - Endpoint: `{base}/v1beta/models/{model}:streamGenerateContent?alt=sse`.
//!   Auth via `x-goog-api-key` header.
//! - Body uses `contents` instead of `messages`, with `user`/`model` roles.
//!   System prompt goes in a top-level `systemInstruction` field.
//! - Each content message has `parts: [{text}|{functionCall}|{functionResponse}]`.
//! - Tool declarations live under `tools: [{functionDeclarations: [...]}]`.
//! - Tool results come back as `user` messages containing a `functionResponse`
//!   part. There's no explicit tool_use_id — we track id→name locally for
//!   round-tripping.
//! - SSE format: `data: {json}\n\n`. No event: lines. No [DONE] terminator.
//!   Tool calls are **not streamed**: a functionCall part arrives in a single
//!   chunk with the full `args` object.
//!
//! Model name handling: the `gemini-*` prefix is passed through directly.

use super::{EventStream, ModelInfo, Provider, ProviderEvent, StreamRequest, Usage};
use crate::error::{Error, Result};
use crate::types::{ContentBlock, Role};
use async_stream::try_stream;
use async_trait::async_trait;
use futures::StreamExt;
use reqwest::Client;
use serde_json::{json, Value};
use std::collections::HashMap;

pub const DEFAULT_BASE_URL: &str = "https://generativelanguage.googleapis.com";

/// If `THCLAWS_DEBUG_GEMINI` is set, open the log file (creating dirs as
/// needed) and write a separator + the request body. Returns the file handle
/// so the streaming loop can append raw chunks to it.
fn open_debug_log(body: &Value, model: &str) -> Option<std::fs::File> {
    let setting = std::env::var("THCLAWS_DEBUG_GEMINI").ok()?;
    if setting.is_empty() || setting == "0" {
        return None;
    }
    let path = if setting == "1" || setting.eq_ignore_ascii_case("true") {
        std::env::current_dir()
            .ok()?
            .join(".thclaws/logs/gemini-raw.log")
    } else {
        std::path::PathBuf::from(setting)
    };
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .ok()?;
    use std::io::Write;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let _ = writeln!(f, "\n===== {now} model={model} =====");
    let _ = writeln!(
        f,
        "REQUEST: {}",
        serde_json::to_string(body).unwrap_or_default()
    );
    let _ = writeln!(f, "RAW STREAM:");
    let _ = f.flush();
    eprintln!(
        "\x1b[35m[gemini debug] logging raw response → {}\x1b[0m",
        path.display()
    );
    Some(f)
}

pub struct GeminiProvider {
    client: Client,
    api_key: String,
    base_url: String,
}

impl GeminiProvider {
    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            client: Client::new(),
            api_key: api_key.into(),
            base_url: DEFAULT_BASE_URL.to_string(),
        }
    }

    pub fn with_base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = url.into();
        self
    }

    /// Convert canonical messages → Gemini `contents` array.
    /// Gemini uses `user`/`model` roles (not `assistant`), inlines tool_use
    /// as `functionCall` parts, and inlines tool_result as `functionResponse`
    /// parts in a `user` message. System messages are skipped (they go in
    /// the top-level `systemInstruction` via `build_body`).
    fn messages_to_gemini(req: &StreamRequest) -> Vec<Value> {
        // Build id→tool name map so ToolResult blocks can resolve the right
        // function name (Gemini's functionResponse needs `name`, not an id).
        let mut id_to_name: HashMap<String, String> = HashMap::new();
        for m in &req.messages {
            if matches!(m.role, Role::Assistant) {
                for block in &m.content {
                    if let ContentBlock::ToolUse { id, name, .. } = block {
                        id_to_name.insert(id.clone(), name.clone());
                    }
                }
            }
        }

        let mut out: Vec<Value> = Vec::new();
        for m in &req.messages {
            if matches!(m.role, Role::System) {
                continue;
            }
            let role = match m.role {
                Role::User => "user",
                Role::Assistant => "model",
                Role::System => unreachable!(),
            };
            let mut parts: Vec<Value> = Vec::new();
            for block in &m.content {
                match block {
                    ContentBlock::Text { text } => {
                        if !text.is_empty() {
                            parts.push(json!({"text": text}));
                        }
                    }
                    ContentBlock::ToolUse { name, input, .. } => {
                        parts.push(json!({
                            "functionCall": { "name": name, "args": input }
                        }));
                    }
                    ContentBlock::ToolResult {
                        tool_use_id,
                        content,
                        ..
                    } => {
                        let name = id_to_name
                            .get(tool_use_id)
                            .cloned()
                            .unwrap_or_else(|| "unknown".to_string());
                        parts.push(json!({
                            "functionResponse": {
                                "name": name,
                                "response": { "content": content }
                            }
                        }));
                    }
                }
            }
            if !parts.is_empty() {
                out.push(json!({"role": role, "parts": parts}));
            }
        }
        out
    }

    fn build_body(req: &StreamRequest) -> Value {
        let contents = Self::messages_to_gemini(req);
        let mut body = json!({
            "contents": contents,
            "generationConfig": {
                "maxOutputTokens": req.max_tokens,
            },
        });
        // Gemma open-weights models are served via the same API but don't
        // support `systemInstruction` ("Developer instruction is not enabled")
        // or function calling ("Function calling is not enabled"). For Gemma
        // we inline the system prompt as the first user turn and skip tools.
        //
        // Gemma also does chain-of-thought in plain prose by default. Ask it
        // to wrap reasoning in `<thinking>...</thinking>` so we can visually
        // demote it downstream.
        let is_gemma = req.model.starts_with("gemma-");
        if is_gemma {
            let thinking_rule = "Format rule (mandatory): wrap any internal \
                reasoning, planning, or self-talk in <thinking>...</thinking> \
                tags. Put ONLY the final user-facing answer outside those \
                tags. Do not reveal raw chain-of-thought as plain text.";
            let sys = req.system.as_deref().unwrap_or("").to_string();
            let combined = if sys.is_empty() {
                thinking_rule.to_string()
            } else {
                format!("{sys}\n\n{thinking_rule}")
            };
            let prefixed = json!({
                "role": "user",
                "parts": [{"text": combined}]
            });
            if let Some(arr) = body["contents"].as_array_mut() {
                arr.insert(0, prefixed);
            }
        } else if let Some(sys) = &req.system {
            if !sys.is_empty() {
                body["systemInstruction"] = json!({
                    "parts": [{"text": sys}]
                });
            }
        }
        let supports_tools = !is_gemma;
        if supports_tools && !req.tools.is_empty() {
            let decls: Vec<Value> = req
                .tools
                .iter()
                .map(|t| {
                    json!({
                        "name": t.name,
                        "description": t.description,
                        "parameters": t.input_schema,
                    })
                })
                .collect();
            body["tools"] = json!([{ "functionDeclarations": decls }]);
        }
        body
    }
}

#[async_trait]
impl Provider for GeminiProvider {
    async fn list_models(&self) -> Result<Vec<ModelInfo>> {
        let url = format!("{}/v1beta/models", self.base_url.trim_end_matches('/'));
        let resp = self
            .client
            .get(&url)
            .header("x-goog-api-key", &self.api_key)
            .send()
            .await
            .map_err(|e| Error::Provider(format!("http: {e}")))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(Error::Provider(format!(
                "http {status}: {}",
                super::redact_key(&text, &self.api_key)
            )));
        }
        let v: Value = resp
            .json()
            .await
            .map_err(|e| Error::Provider(format!("json: {e}")))?;
        let mut out: Vec<ModelInfo> = v
            .get("models")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(|m| {
                        // `name` comes back as `models/gemini-2.0-flash` — strip the prefix
                        // so users can paste it straight into /model.
                        let raw = m.get("name").and_then(Value::as_str)?;
                        let id = raw.strip_prefix("models/").unwrap_or(raw).to_string();
                        let display_name = m
                            .get("displayName")
                            .and_then(Value::as_str)
                            .map(String::from);
                        Some(ModelInfo { id, display_name })
                    })
                    .collect()
            })
            .unwrap_or_default();
        out.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(out)
    }

    async fn stream(&self, req: StreamRequest) -> Result<EventStream> {
        let body = Self::build_body(&req);
        let url = format!(
            "{}/v1beta/models/{}:streamGenerateContent?alt=sse",
            self.base_url.trim_end_matches('/'),
            req.model
        );

        let resp = self
            .client
            .post(&url)
            .header("x-goog-api-key", &self.api_key)
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| Error::Provider(format!("http: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(Error::Provider(format!(
                "http {status}: {}",
                super::redact_key(&text, &self.api_key)
            )));
        }

        let byte_stream = resp.bytes_stream();

        let is_gemma = req.model.starts_with("gemma-");
        // Optional raw-response logging / inline dump:
        //   THCLAWS_DEBUG_GEMINI=1              → log to ./.thclaws/logs/gemini-raw.log
        //   THCLAWS_DEBUG_GEMINI=/path/to/file  → log to that exact path
        //   THCLAWS_SHOW_RAW=1                  → dump the assistant's raw text
        //                                          to stderr after each turn
        // The two are independent — set both for file + inline. The inline
        // dump is dim-formatted and fenced so it's easy to scan for
        // protocol/formatting issues without leaving the terminal.
        let debug_log = open_debug_log(&body, &req.model);
        let raw_dump = super::RawDump::new(format!("gemini {}", req.model));
        let event_stream = try_stream! {
            let mut buffer = String::new();
            let mut byte_stream = Box::pin(byte_stream);
            let mut state = ParseState::default();
            // For Gemma: track whether we're currently inside a
            // `<thinking>...</thinking>` block across chunk boundaries so we
            // can wrap inner text with ANSI dim codes.
            let mut think = ThinkFilter::new();
            let mut log = debug_log;
            let mut raw = raw_dump;

            while let Some(chunk) = byte_stream.next().await {
                let chunk = chunk.map_err(|e| Error::Provider(format!("stream: {e}")))?;
                if let Some(f) = log.as_mut() {
                    use std::io::Write;
                    let _ = f.write_all(&chunk);
                    let _ = f.flush();
                }
                buffer.push_str(&String::from_utf8_lossy(&chunk));

                // SSE event boundaries can be either `\n\n` (unix) or
                // `\r\n\r\n` (HTTP-spec). Google Gen Lang returns CRLF on
                // streamGenerateContent, so a plain `\n\n` search silently
                // buffers forever and yields zero events.
                while let Some((boundary, sep_len)) = buffer
                    .find("\r\n\r\n").map(|p| (p, 4))
                    .or_else(|| buffer.find("\n\n").map(|p| (p, 2)))
                {
                    let event_text: String = buffer.drain(..boundary + sep_len).collect();
                    let trimmed = event_text
                        .trim_end_matches(|c: char| c == '\n' || c == '\r');
                    for event in parse_sse_event(trimmed, &mut state)? {
                        if let ProviderEvent::TextDelta(ref s) = event {
                            raw.push(s);
                        }
                        if is_gemma {
                            if let ProviderEvent::TextDelta(s) = event {
                                let transformed = think.push(&s);
                                if !transformed.is_empty() {
                                    yield ProviderEvent::TextDelta(transformed);
                                }
                                continue;
                            }
                        }
                        yield event;
                    }
                }
            }
            if is_gemma {
                let tail = think.flush();
                if !tail.is_empty() {
                    yield ProviderEvent::TextDelta(tail);
                }
            }
            raw.flush();
        };

        Ok(Box::pin(event_stream))
    }
}

#[derive(Default, Debug)]
pub struct ParseState {
    pub seen_message_start: bool,
    pub next_tool_id: u64,
}

/// Parse one SSE event from the Gemini stream. Stateful across events.
pub fn parse_sse_event(raw: &str, state: &mut ParseState) -> Result<Vec<ProviderEvent>> {
    let mut out = Vec::new();

    // Find the `data:` line.
    let mut data_line: Option<&str> = None;
    for line in raw.lines() {
        if let Some(rest) = line.strip_prefix("data: ") {
            data_line = Some(rest);
        } else if let Some(rest) = line.strip_prefix("data:") {
            data_line = Some(rest);
        }
    }
    let Some(data) = data_line else {
        return Ok(out);
    };
    let v: Value = serde_json::from_str(data)?;

    if !state.seen_message_start {
        let model = v
            .get("modelVersion")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        out.push(ProviderEvent::MessageStart { model });
        state.seen_message_start = true;
    }

    let Some(candidates) = v.get("candidates").and_then(Value::as_array) else {
        return Ok(out);
    };
    let Some(candidate) = candidates.first() else {
        return Ok(out);
    };

    // Emit text deltas and tool calls from parts.
    if let Some(parts) = candidate
        .pointer("/content/parts")
        .and_then(Value::as_array)
    {
        for part in parts {
            if let Some(text) = part.get("text").and_then(Value::as_str) {
                if !text.is_empty() {
                    out.push(ProviderEvent::TextDelta(text.to_string()));
                }
            } else if let Some(fc) = part.get("functionCall") {
                let name = fc
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                let args = fc.get("args").cloned().unwrap_or_else(|| json!({}));
                let id = format!("gemini-call-{}", state.next_tool_id);
                state.next_tool_id += 1;
                out.push(ProviderEvent::ToolUseStart { id, name });
                out.push(ProviderEvent::ToolUseDelta {
                    partial_json: args.to_string(),
                });
                out.push(ProviderEvent::ContentBlockStop);
            }
        }
    }

    // finishReason → MessageStop
    if let Some(reason) = candidate.get("finishReason").and_then(Value::as_str) {
        let usage = v.get("usageMetadata").map(|u| Usage {
            input_tokens: u
                .get("promptTokenCount")
                .and_then(Value::as_u64)
                .unwrap_or(0) as u32,
            output_tokens: u
                .get("candidatesTokenCount")
                .and_then(Value::as_u64)
                .unwrap_or(0) as u32,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        });
        out.push(ProviderEvent::MessageStop {
            stop_reason: Some(reason.to_string()),
            usage,
        });
    }

    Ok(out)
}

/// Streaming filter for Gemma's `<thinking>...</thinking>` blocks.
///
/// We ask Gemma in its system prompt to wrap chain-of-thought in those tags,
/// then this filter translates them to ANSI dim sequences inline. Tags can
/// straddle chunk boundaries, so we hold back partial-tag tail bytes between
/// pushes.
struct ThinkFilter {
    inside: bool,
    /// Bytes we've buffered because they *might* be the start of a tag.
    pending: String,
}

impl ThinkFilter {
    fn new() -> Self {
        Self {
            inside: false,
            pending: String::new(),
        }
    }

    /// Feed a chunk of raw text from the model. Returns the transformed text
    /// (may include ANSI escapes; may be empty if everything is buffered).
    fn push(&mut self, chunk: &str) -> String {
        let mut input = std::mem::take(&mut self.pending);
        input.push_str(chunk);
        let mut out = String::new();
        let mut idx = 0;
        let bytes = input.as_bytes();
        const OPEN: &str = "<thinking>";
        const CLOSE: &str = "</thinking>";

        // Styling:
        //   inside  <thinking>...</thinking>   → dim white   (\x1b[2;37m)
        //   outside (the user-facing answer)   → bright green (\x1b[1;32m)
        // Each emitted span is wrapped with its open code + reset, so the
        // terminal returns to default after the stream ends.
        const STYLE_THINK: &str = "\x1b[2;37m";
        const STYLE_ANSWER: &str = "\x1b[1;32m";
        const RESET: &str = "\x1b[0m";

        while idx < bytes.len() {
            let needle = if self.inside { CLOSE } else { OPEN };
            if let Some(rel) = input[idx..].find(needle) {
                // Emit the text before the tag with the appropriate styling.
                let before = &input[idx..idx + rel];
                if !before.is_empty() {
                    let style = if self.inside {
                        STYLE_THINK
                    } else {
                        STYLE_ANSWER
                    };
                    out.push_str(style);
                    out.push_str(before);
                    out.push_str(RESET);
                }
                idx += rel + needle.len();
                let was_inside = self.inside;
                self.inside = !self.inside;
                // After closing a thinking block, drop the model's first
                // newline (if any) and emit our own so the user-facing answer
                // always starts on a clean fresh line under the reasoning.
                if was_inside && !self.inside {
                    let after = &input[idx..];
                    if let Some(s) = after.strip_prefix('\n') {
                        idx += 1;
                        if s.starts_with('\n') {
                            idx += 1;
                        }
                    }
                    out.push('\n');
                }
            } else {
                // No complete tag in remaining input. Hold back the LONGEST
                // suffix of the tail that's a prefix of `needle` so a tag
                // straddling the chunk boundary still resolves correctly.
                //
                // CAREFUL: tag bytes are ASCII, but the surrounding text may
                // include multi-byte chars (Thai, CJK, emoji). Only consider
                // suffix lengths that land on a char boundary, otherwise
                // string slicing panics and takes the whole agent thread —
                // and the GUI window — down with it.
                let tail = &input[idx..];
                let max_partial = needle.len().saturating_sub(1);
                let limit = tail.len().min(max_partial);
                let mut keepback = 0;
                for n in 1..=limit {
                    let start = tail.len() - n;
                    if !tail.is_char_boundary(start) {
                        continue;
                    }
                    if needle.starts_with(&tail[start..]) {
                        keepback = n;
                    }
                }
                let split_at = tail.len() - keepback;
                debug_assert!(tail.is_char_boundary(split_at));
                let emit = &tail[..split_at];
                if !emit.is_empty() {
                    let style = if self.inside {
                        STYLE_THINK
                    } else {
                        STYLE_ANSWER
                    };
                    out.push_str(style);
                    out.push_str(emit);
                    out.push_str(RESET);
                }
                self.pending.push_str(&tail[split_at..]);
                break;
            }
        }
        out
    }

    /// Stream ended — emit any held-back bytes with the active style.
    fn flush(&mut self) -> String {
        let pending = std::mem::take(&mut self.pending);
        if pending.is_empty() {
            return String::new();
        }
        let style = if self.inside {
            "\x1b[2;37m"
        } else {
            "\x1b[1;32m"
        };
        format!("{style}{pending}\x1b[0m")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::{assemble, collect_turn};
    use crate::types::Message;

    fn parse_all(events: &[&str]) -> Vec<ProviderEvent> {
        let mut state = ParseState::default();
        let mut out = Vec::new();
        for e in events {
            out.extend(parse_sse_event(e, &mut state).unwrap());
        }
        out
    }

    #[test]
    fn parse_text_stream() {
        let events = parse_all(&[
            "data: {\"candidates\":[{\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"Hello\"}]}}],\"modelVersion\":\"gemini-2.0-flash\"}",
            "data: {\"candidates\":[{\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\" world\"}]},\"finishReason\":\"STOP\"}],\"usageMetadata\":{\"promptTokenCount\":4,\"candidatesTokenCount\":2}}",
        ]);
        assert!(
            matches!(&events[0], ProviderEvent::MessageStart { model } if model == "gemini-2.0-flash")
        );
        assert_eq!(events[1], ProviderEvent::TextDelta("Hello".into()));
        assert_eq!(events[2], ProviderEvent::TextDelta(" world".into()));
        match &events[3] {
            ProviderEvent::MessageStop { stop_reason, usage } => {
                assert_eq!(stop_reason.as_deref(), Some("STOP"));
                let u = usage.as_ref().unwrap();
                assert_eq!(u.input_tokens, 4);
                assert_eq!(u.output_tokens, 2);
            }
            e => panic!("expected MessageStop, got {:?}", e),
        }
    }

    #[test]
    fn parse_function_call_emits_complete_tool_use() {
        let events = parse_all(&[
            "data: {\"candidates\":[{\"content\":{\"role\":\"model\",\"parts\":[{\"functionCall\":{\"name\":\"Read\",\"args\":{\"path\":\"/tmp/x\"}}}]},\"finishReason\":\"STOP\"}],\"modelVersion\":\"gemini-2.0-flash\"}",
        ]);
        assert!(matches!(events[0], ProviderEvent::MessageStart { .. }));
        assert_eq!(
            events[1],
            ProviderEvent::ToolUseStart {
                id: "gemini-call-0".into(),
                name: "Read".into(),
            }
        );
        match &events[2] {
            ProviderEvent::ToolUseDelta { partial_json } => {
                assert!(partial_json.contains("path"));
                assert!(partial_json.contains("/tmp/x"));
            }
            e => panic!("expected ToolUseDelta, got {:?}", e),
        }
        assert_eq!(events[3], ProviderEvent::ContentBlockStop);
        assert!(matches!(events[4], ProviderEvent::MessageStop { .. }));
    }

    #[test]
    fn parse_ignores_events_with_no_data_line() {
        let mut state = ParseState::default();
        let events = parse_sse_event("event: ping", &mut state).unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn messages_to_gemini_maps_tool_result_name_via_id_lookup() {
        let req = StreamRequest {
            model: "gemini-2.0-flash".into(),
            system: Some("be brief".into()),
            messages: vec![
                Message::user("hi"),
                crate::types::Message {
                    role: Role::Assistant,
                    content: vec![ContentBlock::ToolUse {
                        id: "t1".into(),
                        name: "Read".into(),
                        input: json!({"path": "/x"}),
                    }],
                },
                crate::types::Message {
                    role: Role::User,
                    content: vec![ContentBlock::ToolResult {
                        tool_use_id: "t1".into(),
                        content: "file body".into(),
                        is_error: false,
                    }],
                },
            ],
            tools: vec![],
            max_tokens: 100,
            thinking_budget: None,
        };
        let contents = GeminiProvider::messages_to_gemini(&req);
        // user(hi), model(functionCall), user(functionResponse)
        assert_eq!(contents.len(), 3);
        assert_eq!(contents[0]["role"], "user");
        assert_eq!(contents[0]["parts"][0]["text"], "hi");
        assert_eq!(contents[1]["role"], "model");
        assert_eq!(contents[1]["parts"][0]["functionCall"]["name"], "Read");
        assert_eq!(contents[2]["role"], "user");
        // The crucial bit: name is filled from the id→name map, not left as "unknown".
        assert_eq!(contents[2]["parts"][0]["functionResponse"]["name"], "Read");
        assert_eq!(
            contents[2]["parts"][0]["functionResponse"]["response"]["content"],
            "file body"
        );
    }

    #[test]
    fn build_body_places_system_in_systemInstruction() {
        let req = StreamRequest {
            model: "gemini-2.0-flash".into(),
            system: Some("you are helpful".into()),
            messages: vec![Message::user("hi")],
            tools: vec![],
            max_tokens: 1024,
            thinking_budget: None,
        };
        let body = GeminiProvider::build_body(&req);
        assert_eq!(
            body["systemInstruction"]["parts"][0]["text"],
            "you are helpful"
        );
        assert_eq!(body["generationConfig"]["maxOutputTokens"], 1024);
        assert!(body.get("tools").is_none());
    }

    #[test]
    fn build_body_tool_declarations_shape() {
        use crate::types::ToolDef;
        let req = StreamRequest {
            model: "gemini-2.0-flash".into(),
            system: None,
            messages: vec![Message::user("x")],
            tools: vec![ToolDef {
                name: "Read".into(),
                description: "read a file".into(),
                input_schema: json!({
                    "type": "object",
                    "properties": {"path": {"type": "string"}}
                }),
            }],
            max_tokens: 100,
            thinking_budget: None,
        };
        let body = GeminiProvider::build_body(&req);
        assert_eq!(body["tools"][0]["functionDeclarations"][0]["name"], "Read");
        assert_eq!(
            body["tools"][0]["functionDeclarations"][0]["description"],
            "read a file"
        );
        assert_eq!(
            body["tools"][0]["functionDeclarations"][0]["parameters"]["type"],
            "object"
        );
    }

    #[tokio::test]
    async fn list_models_strips_models_prefix() {
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let body = r#"{"models":[
            {"name":"models/gemini-2.0-flash","displayName":"Gemini 2.0 Flash"},
            {"name":"models/gemini-1.5-pro","displayName":"Gemini 1.5 Pro"}
        ]}"#;
        Mock::given(method("GET"))
            .and(path("/v1beta/models"))
            .and(header("x-goog-api-key", "test-key"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(&server)
            .await;

        let provider = GeminiProvider::new("test-key").with_base_url(server.uri());
        let models = provider.list_models().await.expect("list");
        // Sorted + prefix stripped.
        let ids: Vec<_> = models.iter().map(|m| m.id.as_str()).collect();
        assert_eq!(ids, vec!["gemini-1.5-pro", "gemini-2.0-flash"]);
        assert_eq!(models[1].display_name.as_deref(), Some("Gemini 2.0 Flash"));
    }

    #[tokio::test]
    async fn stream_end_to_end_text_via_wiremock() {
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let sse_body = concat!(
            "data: {\"candidates\":[{\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"Hi \"}]}}],\"modelVersion\":\"gemini-2.0-flash\"}\n\n",
            "data: {\"candidates\":[{\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"there\"}]},\"finishReason\":\"STOP\"}],\"usageMetadata\":{\"promptTokenCount\":3,\"candidatesTokenCount\":2}}\n\n",
        );
        Mock::given(method("POST"))
            .and(path(
                "/v1beta/models/gemini-2.0-flash:streamGenerateContent",
            ))
            .and(header("x-goog-api-key", "test-key"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/event-stream")
                    .set_body_raw(sse_body.as_bytes().to_vec(), "text/event-stream"),
            )
            .mount(&server)
            .await;

        let provider = GeminiProvider::new("test-key").with_base_url(server.uri());
        let req = StreamRequest {
            model: "gemini-2.0-flash".into(),
            system: None,
            messages: vec![Message::user("hi")],
            tools: vec![],
            max_tokens: 100,
            thinking_budget: None,
        };
        let raw = provider.stream(req).await.expect("stream");
        let result = collect_turn(assemble(raw)).await.expect("collect");
        assert_eq!(result.text, "Hi there");
        assert_eq!(result.stop_reason.as_deref(), Some("STOP"));
        assert_eq!(result.usage.as_ref().unwrap().output_tokens, 2);
    }

    #[tokio::test]
    async fn stream_end_to_end_function_call_via_wiremock() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let sse_body = "data: {\"candidates\":[{\"content\":{\"role\":\"model\",\"parts\":[{\"functionCall\":{\"name\":\"Read\",\"args\":{\"path\":\"/tmp/x\"}}}]},\"finishReason\":\"STOP\"}],\"modelVersion\":\"gemini-2.0-flash\"}\n\n";
        Mock::given(method("POST"))
            .and(path(
                "/v1beta/models/gemini-2.0-flash:streamGenerateContent",
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/event-stream")
                    .set_body_raw(sse_body.as_bytes().to_vec(), "text/event-stream"),
            )
            .mount(&server)
            .await;

        let provider = GeminiProvider::new("test-key").with_base_url(server.uri());
        let req = StreamRequest {
            model: "gemini-2.0-flash".into(),
            system: None,
            messages: vec![Message::user("read")],
            tools: vec![],
            max_tokens: 100,
            thinking_budget: None,
        };
        let raw = provider.stream(req).await.expect("stream");
        let result = collect_turn(assemble(raw)).await.expect("collect");
        assert_eq!(result.tool_uses.len(), 1);
        if let ContentBlock::ToolUse { name, input, .. } = &result.tool_uses[0] {
            assert_eq!(name, "Read");
            assert_eq!(input, &json!({"path": "/tmp/x"}));
        } else {
            panic!("expected ToolUse");
        }
    }

    #[test]
    fn think_filter_dims_inside_tags_in_one_chunk() {
        let mut f = ThinkFilter::new();
        let out = f.push("hello <thinking>plan stuff</thinking>world");
        // Newline after </thinking> so the user-facing answer starts on its
        // own line under the reasoning.
        assert_eq!(
            out,
            "\x1b[1;32mhello \x1b[0m\x1b[2;37mplan stuff\x1b[0m\n\x1b[1;32mworld\x1b[0m"
        );
        assert_eq!(f.flush(), "");
        assert!(!f.inside);
    }

    #[test]
    fn think_filter_collapses_models_own_trailing_newlines_after_close() {
        let mut f = ThinkFilter::new();
        // Model already emits "</thinking>\n\nanswer" — we should NOT end up
        // with three newlines before "answer".
        let out = f.push("<thinking>plan</thinking>\n\nanswer");
        assert_eq!(out, "\x1b[2;37mplan\x1b[0m\n\x1b[1;32manswer\x1b[0m");
    }

    #[test]
    fn think_filter_handles_split_open_tag_across_chunks() {
        let mut f = ThinkFilter::new();
        // Tag starts at very end of chunk 1, finishes in chunk 2.
        let a = f.push("hello <thi");
        // "hello " emitted as bright-green (the answer style) since we're
        // not yet inside a thinking block; the partial "<thi" is held back.
        assert_eq!(a, "\x1b[1;32mhello \x1b[0m");
        let b = f.push("nking>plan</thinking>done");
        assert_eq!(b, "\x1b[2;37mplan\x1b[0m\n\x1b[1;32mdone\x1b[0m");
        assert_eq!(f.flush(), "");
    }

    #[test]
    fn think_filter_does_not_panic_on_multibyte_chars_at_chunk_end() {
        // "สวัสดี" → mostly 3-byte UTF-8 chars; if the keepback search splits
        // mid-byte the slice indexing panics, taking the agent thread down.
        let mut f = ThinkFilter::new();
        let _ = f.push("สวัสดี");
        let _ = f.push("จาก");
        let _ = f.push(" AI <thi");
        let _ = f.push("nking>plan</thinking>OK");
        let _ = f.flush();
        // No panic = pass.
    }

    #[test]
    fn think_filter_handles_unclosed_thinking_at_eof() {
        // The dim styling is emitted on push; flush only handles the held-back
        // partial-tag tail (none here).
        let mut f = ThinkFilter::new();
        let pushed = f.push("answer <thinking>still planning");
        assert_eq!(
            pushed,
            "\x1b[1;32manswer \x1b[0m\x1b[2;37mstill planning\x1b[0m"
        );
        assert_eq!(f.flush(), "");
        assert!(f.inside);
    }
}
