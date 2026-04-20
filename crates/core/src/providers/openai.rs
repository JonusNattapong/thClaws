//! OpenAI chat/completions streaming provider.
//!
//! Wire format differs meaningfully from Anthropic:
//! - SSE is `data: {chunk_json}\n\n`; no `event:` lines. Terminator is `data: [DONE]`.
//! - Tool calls stream via `choices[0].delta.tool_calls[i].function.arguments`;
//!   a new tool call is marked by a new `index` value (and the first chunk for
//!   that index includes `id` + `function.name`).
//! - `finish_reason` appears on the last content chunk, not as a separate event.
//!
//! Adaptation to the common [`ProviderEvent`] stream uses a small stateful
//! parser ([`ParseState`]) that:
//! - emits a single `MessageStart` on the first parsed chunk,
//! - emits synthetic `ContentBlockStop` events when the tool-call index switches
//!   or when `finish_reason` arrives,
//! - emits `MessageStop` with the OpenAI stop reason and (for now) `None` usage.
//!
//! Downstream [`crate::providers::assemble`] folds this identically to Anthropic.

use super::{EventStream, ModelInfo, Provider, ProviderEvent, StreamRequest, Usage};
use crate::error::{Error, Result};
use crate::types::{ContentBlock, Role};
use async_stream::try_stream;
use async_trait::async_trait;
use futures::StreamExt;
use reqwest::Client;
use serde_json::{json, Value};

pub const DEFAULT_API_URL: &str = "https://api.openai.com/v1/chat/completions";

pub struct OpenAIProvider {
    client: Client,
    api_key: String,
    base_url: String,
    /// Optional prefix stripped from `req.model` before sending to the
    /// remote. Used by aggregator-style providers (e.g. `ap/gemma4-12b` →
    /// `gemma4-12b`) where the prefix exists only to route `detect()` on
    /// our side.
    strip_model_prefix: Option<String>,
}

impl OpenAIProvider {
    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            client: Client::new(),
            api_key: api_key.into(),
            base_url: DEFAULT_API_URL.to_string(),
            strip_model_prefix: None,
        }
    }

    pub fn with_base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = url.into();
        self
    }

    pub fn with_strip_model_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.strip_model_prefix = Some(prefix.into());
        self
    }

    /// Convert canonical `Message`s → OpenAI chat/completions messages array.
    /// Splits ToolResult blocks out as separate `role: "tool"` messages.
    fn messages_to_openai(req: &StreamRequest) -> Vec<Value> {
        let mut out: Vec<Value> = Vec::new();

        if let Some(sys) = &req.system {
            if !sys.is_empty() {
                out.push(json!({"role": "system", "content": sys}));
            }
        }

        for m in &req.messages {
            let role = match m.role {
                Role::User => "user",
                Role::Assistant => "assistant",
                Role::System => "system",
            };

            let mut text_parts: Vec<String> = Vec::new();
            let mut tool_calls: Vec<Value> = Vec::new();
            let mut trailing_tool_results: Vec<(String, String)> = Vec::new();

            for block in &m.content {
                match block {
                    ContentBlock::Text { text } => text_parts.push(text.clone()),
                    ContentBlock::ToolUse { id, name, input } => {
                        let args = serde_json::to_string(input).unwrap_or_else(|_| "{}".into());
                        tool_calls.push(json!({
                            "id": id,
                            "type": "function",
                            "function": { "name": name, "arguments": args },
                        }));
                    }
                    ContentBlock::ToolResult {
                        tool_use_id,
                        content,
                        ..
                    } => {
                        trailing_tool_results.push((tool_use_id.clone(), content.clone()));
                    }
                }
            }

            let content_text = text_parts.join("");
            let has_text = !content_text.is_empty();
            let has_tools = !tool_calls.is_empty();

            if has_text || has_tools {
                let mut msg = json!({"role": role});
                if has_text {
                    msg["content"] = json!(content_text);
                } else if has_tools {
                    msg["content"] = Value::Null;
                }
                if has_tools {
                    msg["tool_calls"] = json!(tool_calls);
                }
                out.push(msg);
            }

            for (tool_call_id, content) in trailing_tool_results {
                out.push(json!({
                    "role": "tool",
                    "tool_call_id": tool_call_id,
                    "content": content,
                }));
            }
        }

        out
    }

    fn build_body(req: &StreamRequest) -> Value {
        let messages = Self::messages_to_openai(req);
        let mut body = json!({
            "model": req.model,
            "max_completion_tokens": req.max_tokens,
            "messages": messages,
            "stream": true,
            "stream_options": {"include_usage": true},
        });
        if !req.tools.is_empty() {
            let tools: Vec<Value> = req
                .tools
                .iter()
                .map(|t| {
                    json!({
                        "type": "function",
                        "function": {
                            "name": t.name,
                            "description": t.description,
                            "parameters": t.input_schema,
                        }
                    })
                })
                .collect();
            body["tools"] = json!(tools);
        }
        body
    }
}

#[async_trait]
impl Provider for OpenAIProvider {
    async fn list_models(&self) -> Result<Vec<ModelInfo>> {
        // /v1/chat/completions → /v1/models
        let models_url = self
            .base_url
            .rsplit_once("/chat/completions")
            .map(|(base, _)| format!("{base}/models"))
            .unwrap_or_else(|| format!("{}/models", self.base_url.trim_end_matches('/')));

        let resp = self
            .client
            .get(&models_url)
            .header("authorization", format!("Bearer {}", self.api_key))
            .send()
            .await
            .map_err(|e| Error::Provider(format!("http: {e}")))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(Error::Provider(format!("http {status}: {}", super::redact_key(&text, &self.api_key))));
        }
        let v: Value = resp
            .json()
            .await
            .map_err(|e| Error::Provider(format!("json: {e}")))?;
        let prefix = self.strip_model_prefix.as_deref().unwrap_or("");
        let mut out: Vec<ModelInfo> = v
            .get("data")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(|m| {
                        let raw = m.get("id").and_then(Value::as_str)?;
                        // Prefix the listing so users can paste IDs straight
                        // into `/model` (e.g. `ap/gemma4-12b`). `detect()`
                        // routes on this prefix; the stream call strips it
                        // before hitting the remote.
                        let id = if prefix.is_empty() || raw.starts_with(prefix) {
                            raw.to_string()
                        } else {
                            format!("{prefix}{raw}")
                        };
                        Some(ModelInfo {
                            id,
                            display_name: None,
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        out.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(out)
    }

    async fn stream(&self, mut req: StreamRequest) -> Result<EventStream> {
        if let Some(prefix) = &self.strip_model_prefix {
            if let Some(rest) = req.model.strip_prefix(prefix.as_str()) {
                req.model = rest.to_string();
            }
        }
        let body = Self::build_body(&req);
        let resp = self
            .client
            .post(&self.base_url)
            .header("authorization", format!("Bearer {}", self.api_key))
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| Error::Provider(format!("http: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(Error::Provider(format!("http {status}: {}", super::redact_key(&text, &self.api_key))));
        }

        let byte_stream = resp.bytes_stream();
        let raw_dump = super::RawDump::new(format!("openai {}", req.model));

        let event_stream = try_stream! {
            let mut buffer = String::new();
            let mut byte_stream = Box::pin(byte_stream);
            let mut state = ParseState::default();
            let mut raw = raw_dump;

            while let Some(chunk) = byte_stream.next().await {
                let chunk = chunk.map_err(|e| Error::Provider(format!("stream: {e}")))?;
                buffer.push_str(&String::from_utf8_lossy(&chunk));

                while let Some(boundary) = buffer.find("\n\n") {
                    let event_text: String = buffer.drain(..boundary + 2).collect();
                    let trimmed = event_text.trim_end_matches('\n');
                    for event in parse_chunk(trimmed, &mut state)? {
                        if let ProviderEvent::TextDelta(ref s) = event { raw.push(s); }
                        yield event;
                    }
                }
            }

            for event in state.flush_eof() {
                yield event;
            }
            raw.flush();
        };

        Ok(Box::pin(event_stream))
    }
}

#[derive(Default, Debug)]
pub struct ParseState {
    pub seen_message_start: bool,
    pub active_tool_index: Option<i64>,
    pub emitted_message_stop: bool,
}

impl ParseState {
    fn flush_eof(&mut self) -> Vec<ProviderEvent> {
        let mut out = Vec::new();
        if self.active_tool_index.is_some() {
            out.push(ProviderEvent::ContentBlockStop);
            self.active_tool_index = None;
        }
        out
    }
}

fn parse_openai_usage(v: &Value) -> Option<Usage> {
    let u = v.get("usage")?;
    let input = u.get("prompt_tokens").and_then(Value::as_u64).unwrap_or(0);
    let output = u
        .get("completion_tokens")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if input == 0 && output == 0 {
        return None;
    }
    Some(Usage {
        input_tokens: input as u32,
        output_tokens: output as u32,
        cache_creation_input_tokens: None,
        cache_read_input_tokens: None,
    })
}

/// Parse a single SSE chunk (one `data: {...}` event). Stateful: call with a
/// persistent `ParseState` across the lifetime of the stream.
pub fn parse_chunk(raw: &str, state: &mut ParseState) -> Result<Vec<ProviderEvent>> {
    let mut out = Vec::new();

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
    if data.trim() == "[DONE]" {
        return Ok(out);
    }

    let v: Value = serde_json::from_str(data)?;

    // Some OpenAI-compatible gateways return HTTP 200 but wrap an upstream
    // error inside a single SSE data frame (e.g. `data: {"error": {...}}`).
    // Surface it as a hard error instead of silently completing with no
    // output.
    if let Some(err) = v.get("error") {
        let msg = err
            .get("message")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| err.to_string());
        return Err(Error::Provider(format!("upstream error: {msg}")));
    }

    if !state.seen_message_start {
        let model = v
            .get("model")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        out.push(ProviderEvent::MessageStart { model });
        state.seen_message_start = true;
    }

    let Some(choices) = v.get("choices").and_then(Value::as_array) else {
        return Ok(out);
    };
    let Some(choice) = choices.first() else {
        // Final `stream_options.include_usage` frame: choices is an empty
        // array and the top-level chunk carries `usage`. DashScope + OpenAI
        // both do this. Emit a MessageStop carrying the usage so the agent's
        // cumulative_usage picks it up — otherwise we report 0in/0out.
        if state.emitted_message_stop {
            if let Some(usage) = parse_openai_usage(&v) {
                out.push(ProviderEvent::MessageStop {
                    stop_reason: Some("stop".into()),
                    usage: Some(usage),
                });
            }
        }
        return Ok(out);
    };

    if let Some(delta) = choice.get("delta") {
        if let Some(content) = delta.get("content").and_then(Value::as_str) {
            if !content.is_empty() {
                out.push(ProviderEvent::TextDelta(content.to_string()));
            }
        }

        if let Some(tool_calls) = delta.get("tool_calls").and_then(Value::as_array) {
            for tc in tool_calls {
                let index = tc.get("index").and_then(Value::as_i64).unwrap_or(0);
                let func = tc.get("function");

                if state.active_tool_index != Some(index) {
                    if state.active_tool_index.is_some() {
                        out.push(ProviderEvent::ContentBlockStop);
                    }
                    state.active_tool_index = Some(index);

                    let id = tc
                        .get("id")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    let name = func
                        .and_then(|f| f.get("name"))
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    out.push(ProviderEvent::ToolUseStart { id, name });
                }

                if let Some(args) = func
                    .and_then(|f| f.get("arguments"))
                    .and_then(Value::as_str)
                {
                    if !args.is_empty() {
                        out.push(ProviderEvent::ToolUseDelta {
                            partial_json: args.to_string(),
                        });
                    }
                }
            }
        }
    }

    if let Some(reason) = choice.get("finish_reason").and_then(Value::as_str) {
        if state.active_tool_index.is_some() {
            out.push(ProviderEvent::ContentBlockStop);
            state.active_tool_index = None;
        }
        out.push(ProviderEvent::MessageStop {
            stop_reason: Some(reason.to_string()),
            usage: parse_openai_usage(&v),
        });
        state.emitted_message_stop = true;
    }

    // With stream_options.include_usage, a final chunk has usage but empty choices.
    // Emit a MessageStop with usage if we already emitted one without.
    if state.emitted_message_stop {
        if let Some(usage) = parse_openai_usage(&v) {
            out.push(ProviderEvent::MessageStop {
                stop_reason: Some("stop".into()),
                usage: Some(usage),
            });
        }
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::{assemble, collect_turn};
    use crate::types::Message;

    fn parse_all(chunks: &[&str]) -> Vec<ProviderEvent> {
        let mut state = ParseState::default();
        let mut out = Vec::new();
        for c in chunks {
            out.extend(parse_chunk(c, &mut state).unwrap());
        }
        out.extend(state.flush_eof());
        out
    }

    #[test]
    fn parse_text_chunk_emits_message_start_and_text_delta() {
        let events = parse_all(&[
            "data: {\"id\":\"1\",\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"\"}}]}",
            "data: {\"id\":\"1\",\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hello\"}}]}",
            "data: {\"id\":\"1\",\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\" world\"}}]}",
            "data: {\"id\":\"1\",\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}",
            "data: [DONE]",
        ]);

        assert_eq!(
            events[0],
            ProviderEvent::MessageStart {
                model: "gpt-4o".into()
            }
        );
        assert_eq!(events[1], ProviderEvent::TextDelta("Hello".into()));
        assert_eq!(events[2], ProviderEvent::TextDelta(" world".into()));
        match &events[3] {
            ProviderEvent::MessageStop { stop_reason, .. } => {
                assert_eq!(stop_reason.as_deref(), Some("stop"));
            }
            e => panic!("expected MessageStop, got {:?}", e),
        }
        assert_eq!(events.len(), 4);
    }

    #[test]
    fn final_empty_choices_chunk_emits_usage_stop() {
        // DashScope (and OpenAI with stream_options.include_usage) send a
        // trailing frame with `choices: []` and the real token counts. We
        // must not drop it — otherwise the turn reports 0in/0out.
        let events = parse_all(&[
            "data: {\"id\":\"1\",\"model\":\"qwen-max\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"hi\"}}]}",
            "data: {\"id\":\"1\",\"model\":\"qwen-max\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}",
            "data: {\"id\":\"1\",\"model\":\"qwen-max\",\"choices\":[],\"usage\":{\"prompt_tokens\":11,\"completion_tokens\":3,\"total_tokens\":14}}",
            "data: [DONE]",
        ]);

        let usage_stops: Vec<_> = events
            .iter()
            .filter_map(|e| match e {
                ProviderEvent::MessageStop { usage: Some(u), .. } => Some(u),
                _ => None,
            })
            .collect();
        assert_eq!(
            usage_stops.len(),
            1,
            "expected a MessageStop carrying usage"
        );
        assert_eq!(usage_stops[0].input_tokens, 11);
        assert_eq!(usage_stops[0].output_tokens, 3);
    }

    #[test]
    fn parse_tool_call_streams_and_flushes_stop_on_finish() {
        let events = parse_all(&[
            "data: {\"id\":\"1\",\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\"}}]}",
            "data: {\"id\":\"1\",\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_abc\",\"type\":\"function\",\"function\":{\"name\":\"read_file\",\"arguments\":\"\"}}]}}]}",
            "data: {\"id\":\"1\",\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"{\\\"pa\"}}]}}]}",
            "data: {\"id\":\"1\",\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"th\\\":\\\"/tmp/x\\\"}\"}}]}}]}",
            "data: {\"id\":\"1\",\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}",
            "data: [DONE]",
        ]);

        // Expected sequence:
        // MessageStart, ToolUseStart(call_abc, read_file),
        // ToolUseDelta('{\"pa'), ToolUseDelta('th\":\"/tmp/x\"}'),
        // ContentBlockStop, MessageStop("tool_calls")
        assert!(matches!(events[0], ProviderEvent::MessageStart { .. }));
        assert_eq!(
            events[1],
            ProviderEvent::ToolUseStart {
                id: "call_abc".into(),
                name: "read_file".into()
            }
        );
        assert_eq!(
            events[2],
            ProviderEvent::ToolUseDelta {
                partial_json: "{\"pa".into()
            }
        );
        assert_eq!(
            events[3],
            ProviderEvent::ToolUseDelta {
                partial_json: "th\":\"/tmp/x\"}".into()
            }
        );
        assert_eq!(events[4], ProviderEvent::ContentBlockStop);
        assert!(matches!(events[5], ProviderEvent::MessageStop { .. }));
        assert_eq!(events.len(), 6);
    }

    #[test]
    fn parse_two_tool_calls_emits_stop_between_indexes() {
        let events = parse_all(&[
            "data: {\"id\":\"1\",\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"a\",\"type\":\"function\",\"function\":{\"name\":\"r\",\"arguments\":\"{}\"}}]}}]}",
            "data: {\"id\":\"1\",\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":1,\"id\":\"b\",\"type\":\"function\",\"function\":{\"name\":\"w\",\"arguments\":\"{}\"}}]}}]}",
            "data: {\"id\":\"1\",\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}",
        ]);

        // MessageStart,
        // ToolUseStart(a), ToolUseDelta({}),
        // ContentBlockStop (index switch 0→1),
        // ToolUseStart(b), ToolUseDelta({}),
        // ContentBlockStop (finish_reason),
        // MessageStop
        assert!(matches!(events[0], ProviderEvent::MessageStart { .. }));
        assert_eq!(
            events[1],
            ProviderEvent::ToolUseStart {
                id: "a".into(),
                name: "r".into()
            }
        );
        assert_eq!(
            events[2],
            ProviderEvent::ToolUseDelta {
                partial_json: "{}".into()
            }
        );
        assert_eq!(events[3], ProviderEvent::ContentBlockStop);
        assert_eq!(
            events[4],
            ProviderEvent::ToolUseStart {
                id: "b".into(),
                name: "w".into()
            }
        );
        assert_eq!(
            events[5],
            ProviderEvent::ToolUseDelta {
                partial_json: "{}".into()
            }
        );
        assert_eq!(events[6], ProviderEvent::ContentBlockStop);
        assert!(matches!(events[7], ProviderEvent::MessageStop { .. }));
    }

    #[test]
    fn parse_done_marker_is_noop() {
        let mut state = ParseState::default();
        let events = parse_chunk("data: [DONE]", &mut state).unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn messages_to_openai_splits_tool_results_into_tool_role() {
        let req = StreamRequest {
            model: "gpt-4o".into(),
            system: Some("be helpful".into()),
            messages: vec![
                Message::user("hi"),
                Message {
                    role: Role::Assistant,
                    content: vec![ContentBlock::ToolUse {
                        id: "call_1".into(),
                        name: "read".into(),
                        input: json!({"path": "/a"}),
                    }],
                },
                Message {
                    role: Role::User,
                    content: vec![ContentBlock::ToolResult {
                        tool_use_id: "call_1".into(),
                        content: "hello file".into(),
                        is_error: false,
                    }],
                },
            ],
            tools: vec![],
            max_tokens: 100,
            thinking_budget: None,
        };
        let msgs = OpenAIProvider::messages_to_openai(&req);
        // system, user(hi), assistant(tool_calls), tool(result)
        assert_eq!(msgs.len(), 4);
        assert_eq!(msgs[0]["role"], "system");
        assert_eq!(msgs[0]["content"], "be helpful");
        assert_eq!(msgs[1]["role"], "user");
        assert_eq!(msgs[1]["content"], "hi");
        assert_eq!(msgs[2]["role"], "assistant");
        assert_eq!(msgs[2]["content"], Value::Null);
        assert_eq!(msgs[2]["tool_calls"][0]["id"], "call_1");
        assert_eq!(msgs[2]["tool_calls"][0]["function"]["name"], "read");
        assert_eq!(
            msgs[2]["tool_calls"][0]["function"]["arguments"],
            "{\"path\":\"/a\"}"
        );
        assert_eq!(msgs[3]["role"], "tool");
        assert_eq!(msgs[3]["tool_call_id"], "call_1");
        assert_eq!(msgs[3]["content"], "hello file");
    }

    #[test]
    fn build_body_maps_tools_to_openai_function_shape() {
        use crate::types::ToolDef;
        let req = StreamRequest {
            model: "gpt-4o".into(),
            system: None,
            messages: vec![Message::user("x")],
            tools: vec![ToolDef {
                name: "read_file".into(),
                description: "read a file".into(),
                input_schema: json!({"type":"object","properties":{"path":{"type":"string"}}}),
            }],
            max_tokens: 100,
            thinking_budget: None,
        };
        let body = OpenAIProvider::build_body(&req);
        assert_eq!(body["stream"], true);
        assert_eq!(body["tools"][0]["type"], "function");
        assert_eq!(body["tools"][0]["function"]["name"], "read_file");
        assert_eq!(body["tools"][0]["function"]["description"], "read a file");
        assert_eq!(
            body["tools"][0]["function"]["parameters"]["properties"]["path"]["type"],
            "string"
        );
    }

    #[tokio::test]
    async fn list_models_parses_data_array() {
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let body = r#"{"data":[
            {"id":"gpt-4o","object":"model","owned_by":"openai"},
            {"id":"gpt-4o-mini","object":"model","owned_by":"openai"}
        ]}"#;
        Mock::given(method("GET"))
            .and(path("/v1/models"))
            .and(header("authorization", "Bearer test-key"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(&server)
            .await;

        let provider = OpenAIProvider::new("test-key")
            .with_base_url(format!("{}/v1/chat/completions", server.uri()));
        let models = provider.list_models().await.expect("list");
        // Sorted
        let ids: Vec<_> = models.iter().map(|m| m.id.as_str()).collect();
        assert_eq!(ids, vec!["gpt-4o", "gpt-4o-mini"]);
    }

    #[tokio::test]
    async fn stream_end_to_end_text_via_wiremock() {
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;

        let sse_body = concat!(
            "data: {\"id\":\"c\",\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"\"}}]}\n\n",
            "data: {\"id\":\"c\",\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hi\"}}]}\n\n",
            "data: {\"id\":\"c\",\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\" there\"}}]}\n\n",
            "data: {\"id\":\"c\",\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n",
            "data: [DONE]\n\n",
        );

        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .and(header("authorization", "Bearer test-key"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/event-stream")
                    .set_body_raw(sse_body.as_bytes().to_vec(), "text/event-stream"),
            )
            .mount(&server)
            .await;

        let provider = OpenAIProvider::new("test-key")
            .with_base_url(format!("{}/v1/chat/completions", server.uri()));
        let req = StreamRequest {
            model: "gpt-4o".into(),
            system: None,
            messages: vec![Message::user("hey")],
            tools: vec![],
            max_tokens: 100,
            thinking_budget: None,
        };
        let raw = provider.stream(req).await.expect("stream");
        let result = collect_turn(assemble(raw)).await.expect("collect");
        assert_eq!(result.text, "Hi there");
        assert_eq!(result.tool_uses.len(), 0);
        assert_eq!(result.stop_reason.as_deref(), Some("stop"));
    }

    #[tokio::test]
    async fn stream_end_to_end_tool_use_via_wiremock() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;

        let sse_body = concat!(
            "data: {\"id\":\"c\",\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\"}}]}\n\n",
            "data: {\"id\":\"c\",\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_abc\",\"type\":\"function\",\"function\":{\"name\":\"read_file\",\"arguments\":\"\"}}]}}]}\n\n",
            "data: {\"id\":\"c\",\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"{\\\"pa\"}}]}}]}\n\n",
            "data: {\"id\":\"c\",\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"th\\\":\\\"/tmp/x\\\"}\"}}]}}]}\n\n",
            "data: {\"id\":\"c\",\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n",
            "data: [DONE]\n\n",
        );

        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/event-stream")
                    .set_body_raw(sse_body.as_bytes().to_vec(), "text/event-stream"),
            )
            .mount(&server)
            .await;

        let provider = OpenAIProvider::new("test-key")
            .with_base_url(format!("{}/v1/chat/completions", server.uri()));
        let req = StreamRequest {
            model: "gpt-4o".into(),
            system: None,
            messages: vec![Message::user("read /tmp/x")],
            tools: vec![],
            max_tokens: 100,
            thinking_budget: None,
        };
        let raw = provider.stream(req).await.expect("stream");
        let result = collect_turn(assemble(raw)).await.expect("collect");

        assert_eq!(result.text, "");
        assert_eq!(result.tool_uses.len(), 1);
        if let ContentBlock::ToolUse { id, name, input } = &result.tool_uses[0] {
            assert_eq!(id, "call_abc");
            assert_eq!(name, "read_file");
            assert_eq!(input, &json!({"path": "/tmp/x"}));
        } else {
            panic!("expected ToolUse");
        }
        assert_eq!(result.stop_reason.as_deref(), Some("tool_calls"));
    }
}
