//! Model Context Protocol (MCP) client over stdio JSON-RPC.
//!
//! Scope (Phase 15a):
//! - Spawn a subprocess configured via [`McpServerConfig`] or attach to any
//!   `AsyncRead` + `AsyncWrite` pair via [`McpClient::from_streams`] (used by
//!   tests with `tokio::io::duplex`).
//! - JSON-RPC 2.0 request/response with numeric ids, notifications for
//!   fire-and-forget messages.
//! - MCP handshake (`initialize` + `notifications/initialized`).
//! - Tool discovery (`tools/list`) and invocation (`tools/call`).
//! - [`McpTool`] adapter that implements the existing [`crate::tools::Tool`]
//!   trait, so discovered MCP tools register into the existing
//!   [`crate::tools::ToolRegistry`] and are indistinguishable from built-ins
//!   from the agent loop's perspective.
//!
//! Deferred:
//! - Resources, prompts, and bidirectional notifications (not needed for the
//!   tool-routing use case).
//! - HTTP/SSE transport — stdio is primary; HTTP is Phase 15b+ if needed.
//! - Cancellation / `$/cancelRequest`.

use crate::error::{Error, Result};
use crate::tools::Tool;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::{oneshot, Mutex as AsyncMutex};
use tokio::time::{timeout, Duration};

pub const PROTOCOL_VERSION: &str = "2024-11-05";
pub const REQUEST_TIMEOUT_SECS: u64 = 30;
pub const CLIENT_NAME: &str = "thclaws-core";
pub const CLIENT_VERSION: &str = "0.1.0";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct McpServerConfig {
    pub name: String,
    /// "stdio" (default) or "http".
    #[serde(default = "default_transport")]
    pub transport: String,
    /// For stdio: the command to spawn.
    #[serde(default)]
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: HashMap<String, String>,
    /// For HTTP transport: the server URL.
    #[serde(default)]
    pub url: String,
    /// Optional HTTP headers (e.g. Authorization). Each entry is sent
    /// verbatim on every POST. Use for Bearer tokens or API keys when
    /// the server requires auth but you don't have a full OAuth flow.
    #[serde(default)]
    pub headers: HashMap<String, String>,
}

fn default_transport() -> String {
    "stdio".into()
}

// ── MCP stdio spawn allowlist ────────────────────────────────────────

/// Path to the persistent per-user allowlist of MCP stdio commands.
fn mcp_allowlist_path() -> Option<std::path::PathBuf> {
    let base = if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        std::path::PathBuf::from(xdg)
    } else {
        let home = std::env::var("HOME").ok()?;
        std::path::PathBuf::from(home).join(".config")
    };
    Some(base.join("thclaws").join("mcp_allowlist.json"))
}

#[derive(Default, Serialize, Deserialize)]
struct McpAllowlist {
    /// Approved stdio commands. We key by the `command` string as it
    /// appears in the MCP config. Users who change PATH or substitute
    /// the binary will re-trigger approval if the command string differs.
    #[serde(default)]
    commands: Vec<String>,
}

impl McpAllowlist {
    fn load() -> Self {
        let Some(path) = mcp_allowlist_path() else {
            return Self::default();
        };
        match std::fs::read_to_string(&path) {
            Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    fn save(&self) {
        let Some(path) = mcp_allowlist_path() else {
            return;
        };
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let json = serde_json::to_string_pretty(self).unwrap_or_default();
        let _ = std::fs::write(&path, json);
    }

    fn contains(&self, cmd: &str) -> bool {
        self.commands.iter().any(|c| c == cmd)
    }

    fn insert(&mut self, cmd: &str) {
        if !self.contains(cmd) {
            self.commands.push(cmd.to_string());
        }
    }
}

/// Gate an MCP stdio spawn through an allowlist. The first time we see
/// a given command string, prompt the user on the controlling TTY to
/// approve it. If no TTY is attached (daemon / GUI path), refuse —
/// the caller should route approval through a UI dialog.
fn check_stdio_command_allowed(config: &McpServerConfig) -> Result<()> {
    // An explicit environment override lets CI and the GUI bypass the
    // TTY prompt once they have surfaced approval through their own UI.
    if std::env::var("THCLAWS_MCP_ALLOW_ALL").ok().as_deref() == Some("1") {
        return Ok(());
    }

    let mut allowlist = McpAllowlist::load();
    if allowlist.contains(&config.command) {
        return Ok(());
    }

    // Require a TTY to prompt; otherwise fail closed.
    use std::io::IsTerminal;
    if !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
        return Err(Error::Provider(format!(
            "mcp spawn refused: command `{}` for server `{}` is not in the \
             user allowlist. Approve it by running thclaws interactively \
             once, editing {}, or setting THCLAWS_MCP_ALLOW_ALL=1 in a \
             trusted context.",
            config.command,
            config.name,
            mcp_allowlist_path()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "<no config dir>".into())
        )));
    }

    eprintln!();
    eprintln!("\x1b[33m[mcp] New MCP stdio server wants to spawn:\x1b[0m");
    eprintln!("      name:    {}", config.name);
    eprintln!("      command: {}", config.command);
    if !config.args.is_empty() {
        eprintln!("      args:    {}", config.args.join(" "));
    }
    eprintln!();
    eprintln!("This will run the binary with your user privileges. Only");
    eprintln!("approve if you trust the MCP config that requested it.");
    eprint!("Approve and remember? [y/N] ");
    use std::io::{BufRead, Write};
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    let stdin = std::io::stdin();
    let _ = stdin.lock().read_line(&mut line);
    let answer = line.trim().to_ascii_lowercase();
    if answer == "y" || answer == "yes" {
        allowlist.insert(&config.command);
        allowlist.save();
        eprintln!(
            "\x1b[32m[mcp] `{}` added to allowlist.\x1b[0m",
            config.command
        );
        Ok(())
    } else {
        Err(Error::Provider(format!(
            "mcp spawn refused by user: {}",
            config.command
        )))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct McpToolInfo {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
}

type Pending = Arc<Mutex<HashMap<u64, oneshot::Sender<Result<Value>>>>>;

type BoxedWriter = Box<dyn AsyncWrite + Send + Unpin>;

pub struct McpClient {
    name: String,
    writer: AsyncMutex<BoxedWriter>,
    pending: Pending,
    next_id: AtomicU64,
    reader_task: tokio::task::JoinHandle<()>,
    _child: Mutex<Option<Child>>,
}

impl Drop for McpClient {
    fn drop(&mut self) {
        // Abort the reader task before fields drop so it releases its
        // read-half of whatever stream it owns; otherwise on stdio split
        // pairs the other side may not see EOF until the runtime cleans
        // up the task lazily. Abort is a no-op if the task already finished.
        self.reader_task.abort();
    }
}

impl McpClient {
    /// Build a client on top of any async stream pair. Starts a background
    /// reader task that parses incoming JSON-RPC messages and resolves pending
    /// requests by id. The task exits when the reader hits EOF; any still-
    /// pending requests at that point get an `"mcp transport closed"` error.
    pub fn from_streams<R, W>(name: impl Into<String>, reader: R, writer: W) -> Arc<Self>
    where
        R: AsyncRead + Send + Unpin + 'static,
        W: AsyncWrite + Send + Unpin + 'static,
    {
        let pending: Pending = Arc::new(Mutex::new(HashMap::new()));
        let pending_for_reader = pending.clone();

        let reader_task = tokio::spawn(async move {
            let mut buf_reader = BufReader::new(reader);
            let mut line = String::new();
            loop {
                line.clear();
                match buf_reader.read_line(&mut line).await {
                    Ok(0) => break,
                    Ok(_) => {
                        let trimmed = line.trim();
                        if trimmed.is_empty() {
                            continue;
                        }
                        if let Ok(msg) = serde_json::from_str::<Value>(trimmed) {
                            handle_incoming(msg, &pending_for_reader);
                        }
                    }
                    Err(_) => break,
                }
            }
            let pending: Vec<_> = pending_for_reader
                .lock()
                .unwrap()
                .drain()
                .map(|(_, tx)| tx)
                .collect();
            for tx in pending {
                let _ = tx.send(Err(Error::Provider("mcp transport closed".into())));
            }
        });

        Arc::new(Self {
            name: name.into(),
            writer: AsyncMutex::new(Box::new(writer) as BoxedWriter),
            pending,
            next_id: AtomicU64::new(1),
            reader_task,
            _child: Mutex::new(None),
        })
    }

    /// Create a client from config. Dispatches on `config.transport`:
    /// - `"stdio"` (default): spawn a subprocess, attach stdin/stdout.
    /// - `"http"`: POST JSON-RPC to `config.url` per request.
    pub async fn spawn(config: McpServerConfig) -> Result<Arc<Self>> {
        if config.transport == "http" {
            return Self::connect_http(config).await;
        }

        // Allowlist gate: MCP stdio configs come from project-scoped
        // JSON files that a user may have cloned from the internet. A
        // malicious `.thclaws/mcp.json` could point `command` at an
        // arbitrary binary. Require explicit per-command approval the
        // first time we see it and persist the decision.
        check_stdio_command_allowed(&config)?;

        let mut cmd = Command::new(&config.command);
        cmd.args(&config.args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true);
        for (k, v) in &config.env {
            cmd.env(k, v);
        }

        let mut child = cmd
            .spawn()
            .map_err(|e| Error::Provider(format!("mcp spawn `{}`: {}", config.command, e)))?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| Error::Provider("mcp: child had no stdin".into()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| Error::Provider("mcp: child had no stdout".into()))?;

        let client = Self::from_streams(config.name.clone(), stdout, stdin);
        *client._child.lock().unwrap() = Some(child);
        client.initialize().await?;
        Ok(client)
    }

    /// Connect to an HTTP MCP server. Each JSON-RPC call is an independent
    /// HTTP POST → JSON response. We simulate the stream pair by piping
    /// through an in-memory duplex so the rest of the client (reader task,
    /// pending map) works unchanged.
    async fn connect_http(config: McpServerConfig) -> Result<Arc<Self>> {
        if config.url.is_empty() {
            return Err(Error::Provider(format!(
                "mcp http server '{}': missing 'url' field",
                config.name
            )));
        }
        // Create an in-memory duplex. We'll use our write-half to send
        // requests and a background task that reads them, POSTs to the
        // HTTP server, and writes responses into the other half.
        let (client_read, server_write) = tokio::io::duplex(64 * 1024);
        let (server_read, client_write) = tokio::io::duplex(64 * 1024);

        let url = config.url.clone();
        let name_for_task = config.name.clone();
        let extra_headers = config.headers.clone();
        // Disable auto-redirects: reqwest strips the Authorization header on
        // ALL redirects (even same-origin 307). Our `write_response_lines`
        // handles 307/308 manually, preserving auth + fixing http→https.
        let http_client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        // Resolve OAuth token BEFORE creating the bridge so the initialize
        // handshake doesn't time out while the user is consenting in the
        // browser. Flow:
        //   1. Check cached token → use if valid.
        //   2. Try refresh if expired.
        //   3. Probe the server → if 401, run full OAuth browser flow.
        //   4. Only then set up the bridge with the token already loaded.
        let http_probe = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        let resolved_token =
            resolve_token_upfront(&http_probe, &url, &config.name, &config.headers).await;

        let token: std::sync::Arc<tokio::sync::Mutex<Option<String>>> =
            std::sync::Arc::new(tokio::sync::Mutex::new(resolved_token));

        let token_for_task = token.clone();
        let url_for_oauth = url.clone();
        // MCP Streamable HTTP session id — returned by the server in
        // `Mcp-Session-Id` header, must be echoed on every subsequent POST.
        let mcp_session: std::sync::Arc<tokio::sync::Mutex<Option<String>>> =
            std::sync::Arc::new(tokio::sync::Mutex::new(None));
        let mcp_session_for_task = mcp_session.clone();

        // Bridge task: read JSON-RPC lines from client_write side, POST
        // each to the HTTP URL, write the response body back to server_write.
        // On 401, attempt OAuth discovery + browser flow, then retry.
        tokio::spawn(async move {
            use tokio::io::{AsyncBufReadExt, BufReader};
            let mut reader = BufReader::new(server_read);
            let mut writer = server_write;
            let mut line = String::new();
            let token = token_for_task;
            let session = mcp_session_for_task;
            loop {
                line.clear();
                match reader.read_line(&mut line).await {
                    Ok(0) => break,
                    Ok(_) => {}
                    Err(_) => break,
                }
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }

                let build_post = |bearer: Option<&str>, sid: Option<&str>, body: &str| {
                    let mut req = http_client
                        .post(&url_for_oauth)
                        .header("content-type", "application/json")
                        .header("accept", "application/json, text/event-stream");
                    for (k, v) in &extra_headers {
                        req = req.header(k.as_str(), v.as_str());
                    }
                    if let Some(t) = bearer {
                        req = req.header("authorization", format!("Bearer {t}"));
                    }
                    if let Some(s) = sid {
                        req = req.header("mcp-session-id", s);
                    }
                    req.body(body.to_string())
                };

                let current_token = token.lock().await.clone();
                let current_session = session.lock().await.clone();
                eprintln!(
                    "\x1b[2m[mcp-http] bridge POST: token={}, session={}, body_len={}\x1b[0m",
                    current_token
                        .as_ref()
                        .map(|t| format!("{}…", &t[..t.len().min(12)]))
                        .unwrap_or("None".into()),
                    current_session.as_deref().unwrap_or("None"),
                    trimmed.len(),
                );
                let resp = build_post(
                    current_token.as_deref(),
                    current_session.as_deref(),
                    trimmed,
                )
                .send()
                .await;

                match resp {
                    Ok(r) if r.status().as_u16() == 401 => {
                        let hdrs = format!("{:?}", r.headers());
                        let body_preview = r.text().await.unwrap_or_default();
                        eprintln!(
                            "\x1b[36m[mcp-http] {} → 401\x1b[0m\n\x1b[2m  headers: {}\n  body: {}\x1b[0m",
                            name_for_task,
                            hdrs.chars().take(300).collect::<String>(),
                            body_preview.chars().take(300).collect::<String>(),
                        );
                        // Invalidate so resolve_oauth_token doesn't just
                        // return the same rejected token from the store.
                        {
                            let mut store = crate::oauth::TokenStore::load();
                            store.remove(&url_for_oauth);
                        }
                        *token.lock().await = None;
                        let new_token =
                            resolve_oauth_token(&http_client, &url_for_oauth, &name_for_task).await;
                        match new_token {
                            Some(t) => {
                                *token.lock().await = Some(t.clone());
                                let sid = session.lock().await.clone();
                                match build_post(Some(&t), sid.as_deref(), trimmed).send().await {
                                    Ok(r2) => {
                                        let sid = session.lock().await.clone();
                                        write_response_lines(
                                            &mut writer,
                                            r2,
                                            &session,
                                            &http_client,
                                            Some(&t),
                                            trimmed,
                                            &url_for_oauth,
                                            &extra_headers,
                                            sid.as_deref(),
                                        )
                                        .await;
                                    }
                                    Err(e) => {
                                        eprintln!(
                                            "\x1b[33m[mcp-http] {} retry error: {e}\x1b[0m",
                                            name_for_task
                                        );
                                    }
                                }
                            }
                            None => {
                                eprintln!(
                                    "\x1b[31m[mcp-http] {} OAuth failed — skipping request\x1b[0m",
                                    name_for_task
                                );
                            }
                        }
                    }
                    Ok(r) => {
                        let curr_tok = current_token.as_deref();
                        let curr_sid = current_session.as_deref();
                        let resp_status = r.status();

                        // "Session not found" detection: peek the body on
                        // error responses. If confirmed, clear the session
                        // and retry. For success responses, pass straight
                        // through to write_response_lines.
                        if resp_status.as_u16() == 400
                            || resp_status == reqwest::StatusCode::NOT_FOUND
                        {
                            let body = r.text().await.unwrap_or_default();
                            if body.contains("Session not found") {
                                eprintln!(
                                    "\x1b[33m[mcp-http] session expired, retrying without session ID\x1b[0m"
                                );
                                *session.lock().await = None;
                                match build_post(current_token.as_deref(), None, trimmed)
                                    .send()
                                    .await
                                {
                                    Ok(r2) => {
                                        write_response_lines(
                                            &mut writer,
                                            r2,
                                            &session,
                                            &http_client,
                                            current_token.as_deref(),
                                            trimmed,
                                            &url_for_oauth,
                                            &extra_headers,
                                            None,
                                        )
                                        .await;
                                    }
                                    Err(e) => {
                                        eprintln!(
                                            "\x1b[33m[mcp-http] {} retry error: {e}\x1b[0m",
                                            name_for_task
                                        );
                                    }
                                }
                            } else {
                                // Some other error — write it through.
                                write_body_to_pipe(&mut writer, &body, "application/json").await;
                            }
                        } else {
                            write_response_lines(
                                &mut writer,
                                r,
                                &session,
                                &http_client,
                                curr_tok,
                                trimmed,
                                &url_for_oauth,
                                &extra_headers,
                                curr_sid,
                            )
                            .await;
                        }
                    }
                    Err(e) => {
                        eprintln!(
                            "\x1b[33m[mcp-http] {} POST error: {e}\x1b[0m",
                            name_for_task
                        );
                    }
                }
            }
        });

        let client = Self::from_streams(config.name.clone(), client_read, client_write);
        client.initialize().await?;
        Ok(client)
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// Send a JSON-RPC request and wait for the matching response.
    pub async fn request(&self, method: &str, params: Value) -> Result<Value> {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = oneshot::channel();
        self.pending.lock().unwrap().insert(id, tx);

        let msg = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        });
        self.write_line(&msg).await?;

        match timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS), rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(Error::Provider("mcp response channel dropped".into())),
            Err(_) => {
                self.pending.lock().unwrap().remove(&id);
                Err(Error::Provider(format!("mcp request timed out: {method}")))
            }
        }
    }

    /// Send a JSON-RPC notification (no id, no response expected).
    pub async fn notify(&self, method: &str, params: Value) -> Result<()> {
        let msg = json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
        });
        self.write_line(&msg).await
    }

    async fn write_line(&self, msg: &Value) -> Result<()> {
        let line = format!("{}\n", serde_json::to_string(msg)?);
        let mut w = self.writer.lock().await;
        w.write_all(line.as_bytes())
            .await
            .map_err(|e| Error::Provider(format!("mcp write: {e}")))?;
        w.flush()
            .await
            .map_err(|e| Error::Provider(format!("mcp flush: {e}")))
    }

    pub async fn initialize(&self) -> Result<()> {
        self.request(
            "initialize",
            json!({
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": CLIENT_NAME, "version": CLIENT_VERSION}
            }),
        )
        .await?;
        self.notify("notifications/initialized", json!({})).await?;
        Ok(())
    }

    pub async fn list_tools(&self) -> Result<Vec<McpToolInfo>> {
        let result = self.request("tools/list", json!({})).await?;
        let arr = result
            .get("tools")
            .and_then(Value::as_array)
            .ok_or_else(|| Error::Provider("mcp tools/list: missing `tools` field".into()))?;
        let mut out = Vec::with_capacity(arr.len());
        for t in arr {
            let name = t
                .get("name")
                .and_then(Value::as_str)
                .ok_or_else(|| Error::Provider("mcp tool missing `name`".into()))?
                .to_string();
            let description = t
                .get("description")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let input_schema = t
                .get("inputSchema")
                .cloned()
                .unwrap_or_else(|| json!({"type": "object", "properties": {}}));
            out.push(McpToolInfo {
                name,
                description,
                input_schema,
            });
        }
        Ok(out)
    }

    pub async fn call_tool(&self, name: &str, arguments: Value) -> Result<String> {
        let result = self
            .request(
                "tools/call",
                json!({ "name": name, "arguments": arguments }),
            )
            .await?;

        let is_error = result
            .get("isError")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let text = extract_text(&result);
        if is_error {
            Err(Error::Tool(format!("mcp tool {name} error: {text}")))
        } else {
            Ok(text)
        }
    }
}

fn handle_incoming(msg: Value, pending: &Pending) {
    // We only handle responses (messages with an `id`). Notifications from
    // the server are ignored for MVP.
    let Some(id) = msg.get("id").and_then(Value::as_u64) else {
        return;
    };
    let tx_opt = pending.lock().unwrap().remove(&id);
    let Some(tx) = tx_opt else {
        return;
    };
    let result = if let Some(error) = msg.get("error") {
        let code = error.get("code").and_then(Value::as_i64).unwrap_or(0);
        let message = error
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        Err(Error::Provider(format!("mcp error {code}: {message}")))
    } else if let Some(result) = msg.get("result") {
        Ok(result.clone())
    } else {
        Err(Error::Provider(
            "mcp response missing both `result` and `error`".into(),
        ))
    };
    let _ = tx.send(result);
}

/// Pull text out of a `tools/call` result. MCP tool results are an array of
/// content blocks; we concatenate all `{type: "text"}` parts.
fn extract_text(result: &Value) -> String {
    let Some(content) = result.get("content").and_then(Value::as_array) else {
        return String::new();
    };
    content
        .iter()
        .filter_map(|c| c.get("text").and_then(Value::as_str).map(String::from))
        .collect::<Vec<_>>()
        .join("\n")
}

// ---------------------------------------------------------------------------
// McpTool — adapter that implements the existing Tool trait.
// ---------------------------------------------------------------------------

/// An MCP tool discovered via `tools/list`, wrapped so the agent's tool
/// registry treats it the same as a built-in tool.
///
/// `name` and `description` are leaked to `&'static str` at construction time
/// because the existing `Tool` trait returns `&'static str`. MCP tools are
/// registered once at REPL startup; the leak is a few hundred bytes per tool
/// and bounded by the configured server set. Document this in the phase log.
pub struct McpTool {
    client: Arc<McpClient>,
    name: &'static str,
    description: &'static str,
    schema: Value,
}

/// Separator used between server name and tool name in the qualified identifier.
/// `__` is used (not `.`) because provider tool-name patterns
/// (OpenAI, Anthropic) require `^[a-zA-Z0-9_-]+$`, which excludes dots.
pub const MCP_NAME_SEPARATOR: &str = "__";

impl McpTool {
    pub fn new(client: Arc<McpClient>, info: McpToolInfo) -> Self {
        let qualified_name = format!("{}{}{}", client.name(), MCP_NAME_SEPARATOR, info.name);
        Self {
            client,
            name: Box::leak(qualified_name.into_boxed_str()),
            description: Box::leak(info.description.into_boxed_str()),
            schema: info.input_schema,
        }
    }

    /// Original MCP tool name (without the server prefix). Splits on the first
    /// occurrence of [`MCP_NAME_SEPARATOR`].
    pub fn bare_name(&self) -> &str {
        self.name
            .split_once(MCP_NAME_SEPARATOR)
            .map(|(_, t)| t)
            .unwrap_or(self.name)
    }
}

#[async_trait]
impl Tool for McpTool {
    fn name(&self) -> &'static str {
        self.name
    }

    fn description(&self) -> &'static str {
        self.description
    }

    fn input_schema(&self) -> Value {
        self.schema.clone()
    }

    async fn call(&self, input: Value) -> Result<String> {
        self.client.call_tool(self.bare_name(), input).await
    }

    fn requires_approval(&self, _input: &Value) -> bool {
        // MCP tools can be arbitrary — default to requiring approval until
        // a per-tool allow-list / annotation mechanism lands.
        true
    }
}

// ---------------------------------------------------------------------------
// HTTP transport helpers
// ---------------------------------------------------------------------------

/// Write response data into the duplex pipe. Handles both plain JSON and
/// SSE (`text/event-stream`) responses — MCP Streamable HTTP servers can
/// return either depending on the request.
async fn write_body_to_pipe(writer: &mut tokio::io::DuplexStream, body: &str, content_type: &str) {
    use tokio::io::AsyncWriteExt;
    if content_type.contains("text/event-stream") {
        for line in body.lines() {
            if let Some(data) = line.trim().strip_prefix("data:").map(str::trim) {
                if data.is_empty() {
                    continue;
                }
                let _ = writer.write_all(data.as_bytes()).await;
                let _ = writer.write_all(b"\n").await;
                let _ = writer.flush().await;
            }
        }
    } else {
        for line in body.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let _ = writer.write_all(line.as_bytes()).await;
            let _ = writer.write_all(b"\n").await;
            let _ = writer.flush().await;
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn write_response_lines(
    writer: &mut tokio::io::DuplexStream,
    resp: reqwest::Response,
    session_id: &std::sync::Arc<tokio::sync::Mutex<Option<String>>>,
    client: &reqwest::Client,
    bearer: Option<&str>,
    body_sent: &str,
    original_url: &str,
    extra_headers: &HashMap<String, String>,
    mcp_sid: Option<&str>,
) {
    let status = resp.status();

    // Handle 307/308 redirects manually: the server may redirect /mcp →
    // /mcp/ with an http:// Location (broken scheme behind a TLS proxy).
    // We fix the scheme to https:// and re-POST with all headers intact
    // (reqwest's auto-redirect strips Authorization).
    if status == reqwest::StatusCode::TEMPORARY_REDIRECT
        || status == reqwest::StatusCode::PERMANENT_REDIRECT
    {
        if let Some(loc) = resp.headers().get("location").and_then(|v| v.to_str().ok()) {
            // Fix http → https if the original URL was https.
            let fixed = if loc.starts_with("http://") && original_url.starts_with("https://") {
                loc.replacen("http://", "https://", 1)
            } else {
                loc.to_string()
            };
            eprintln!("\x1b[2m[mcp-http] following redirect → {fixed}\x1b[0m");
            let mut req = client
                .post(&fixed)
                .header("content-type", "application/json")
                .header("accept", "application/json, text/event-stream");
            if let Some(t) = bearer {
                req = req.header("authorization", format!("Bearer {t}"));
            }
            if let Some(s) = mcp_sid {
                req = req.header("mcp-session-id", s);
            }
            for (k, v) in extra_headers {
                req = req.header(k.as_str(), v.as_str());
            }
            match req.body(body_sent.to_string()).send().await {
                Ok(redirected) => {
                    let rstatus = redirected.status();
                    if let Some(sid) = redirected
                        .headers()
                        .get("mcp-session-id")
                        .and_then(|v| v.to_str().ok())
                    {
                        *session_id.lock().await = Some(sid.to_string());
                    }
                    let ct = redirected
                        .headers()
                        .get("content-type")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_string();
                    eprintln!(
                        "\x1b[2m[mcp-http] redirected response: status={rstatus}, content-type={ct}\x1b[0m"
                    );
                    match redirected.text().await {
                        Ok(rbody) => {
                            if !rbody.is_empty() {
                                eprintln!(
                                    "\x1b[2m[mcp-http] redirected body ({}B): {}\x1b[0m",
                                    rbody.len(),
                                    rbody.chars().take(300).collect::<String>()
                                );
                            }
                            write_body_to_pipe(writer, &rbody, &ct).await;
                        }
                        Err(e) => {
                            eprintln!(
                                "\x1b[31m[mcp-http] failed to read redirected body: {e}\x1b[0m"
                            );
                        }
                    }
                }
                Err(e) => {
                    eprintln!("\x1b[31m[mcp-http] redirect POST failed: {e}\x1b[0m");
                }
            }
            return;
        }
    }

    // Capture Mcp-Session-Id header from the response.
    if let Some(sid) = resp
        .headers()
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
    {
        *session_id.lock().await = Some(sid.to_string());
    }

    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    if let Ok(body) = resp.text().await {
        if !body.is_empty() {
            eprintln!(
                "\x1b[2m[mcp-http] body ({}B): {}\x1b[0m",
                body.len(),
                body.chars().take(300).collect::<String>()
            );
        }
        write_body_to_pipe(writer, &body, &content_type).await;
    }
}

/// Pre-resolve an OAuth token before the bridge task starts. Runs the
/// full discovery + browser flow if needed so the bridge never blocks on
/// OAuth during the time-sensitive MCP initialize handshake.
async fn resolve_token_upfront(
    client: &reqwest::Client,
    mcp_url: &str,
    server_name: &str,
    extra_headers: &HashMap<String, String>,
) -> Option<String> {
    let mut store = crate::oauth::TokenStore::load();

    // Try cached token (or refreshed) — but ALWAYS verify against the
    // server with a probe POST. A token can be "valid" by expiry but
    // revoked server-side.
    let mut candidate: Option<String> = None;

    if let Some(entry) = store.get(mcp_url) {
        if crate::oauth::is_valid(entry) {
            candidate = Some(entry.access_token.clone());
        } else if entry.refresh_token.is_some() {
            eprintln!("\x1b[36m[mcp-http] {server_name}: refreshing expired token…\x1b[0m");
            match crate::oauth::refresh(client, entry).await {
                Ok(new_entry) => {
                    candidate = Some(new_entry.access_token.clone());
                    store.set(mcp_url, new_entry);
                }
                Err(e) => {
                    eprintln!("\x1b[33m[mcp-http] {server_name}: refresh failed ({e})\x1b[0m");
                    store.remove(mcp_url);
                }
            }
        }
    }

    // Auth probe: send a `ping` (valid JSON-RPC but no side effects, no
    // session creation). This ensures the server actually validates auth
    // on the request.
    let mut req = client
        .post(mcp_url)
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .body(r#"{"jsonrpc":"2.0","id":0,"method":"ping"}"#);
    for (k, v) in extra_headers {
        req = req.header(k.as_str(), v.as_str());
    }
    if let Some(ref t) = candidate {
        req = req.header("authorization", format!("Bearer {t}"));
    }

    eprintln!(
        "\x1b[2m[mcp-http] {server_name}: probing with ping (token: {})\x1b[0m",
        if candidate.is_some() { "yes" } else { "none" }
    );
    let probe = req.send().await;
    match probe {
        Ok(r) if r.status().as_u16() == 401 => {
            if candidate.is_some() {
                eprintln!("\x1b[33m[mcp-http] {server_name}: token rejected (401)\x1b[0m");
                store.remove(mcp_url);
            }
            eprintln!("\x1b[36m[mcp-http] {server_name}: server requires OAuth — starting browser flow…\x1b[0m");
        }
        Ok(r) => {
            let status = r.status();
            eprintln!("\x1b[2m[mcp-http] {server_name}: probe → {status} (auth OK)\x1b[0m");
            return candidate;
        }
        Err(e) => {
            eprintln!("\x1b[33m[mcp-http] {server_name}: probe failed ({e})\x1b[0m");
            return candidate;
        }
    }

    // Full OAuth discovery + browser flow.
    resolve_oauth_token(client, mcp_url, server_name).await
}

/// Try to get a valid OAuth token for an MCP URL:
///   1. Check the token store for a cached token → refresh if expired.
///   2. If no cached token or refresh fails, run the full browser flow.
///   3. Save the token to the store and return it.
async fn resolve_oauth_token(
    client: &reqwest::Client,
    mcp_url: &str,
    server_name: &str,
) -> Option<String> {
    let mut store = crate::oauth::TokenStore::load();

    // Full OAuth discovery up front — we need the authorization-server
    // origin to verify that any cached entry was issued by the SAME AS
    // currently advertised for this MCP URL. This blocks token-cache
    // confusion if an attacker swaps the advertised AS under a
    // previously-trusted MCP URL.
    let meta = match crate::oauth::discover(client, mcp_url).await {
        Ok(m) => m,
        Err(e) => {
            eprintln!("\x1b[31m[mcp-http] {server_name}: OAuth discovery failed: {e}\x1b[0m");
            return None;
        }
    };
    let expected_as = meta.authorization_server_origin.clone();

    if let Some(entry) = store.get_validated(mcp_url, &expected_as) {
        if crate::oauth::is_valid(entry) {
            return Some(entry.access_token.clone());
        }
        if entry.refresh_token.is_some() {
            eprintln!("\x1b[36m[mcp-http] {server_name}: refreshing expired token…\x1b[0m");
            match crate::oauth::refresh(client, entry).await {
                Ok(new_entry) => {
                    store.set(mcp_url, new_entry.clone());
                    return Some(new_entry.access_token);
                }
                Err(e) => {
                    eprintln!("\x1b[33m[mcp-http] {server_name}: refresh failed ({e}), re-authorizing…\x1b[0m");
                    store.remove(mcp_url);
                }
            }
        }
    } else if store.get(mcp_url).is_some() {
        // Entry exists but is either legacy (no AS binding) or bound to
        // a different AS. Treat as untrusted and re-authorize.
        eprintln!(
            "\x1b[33m[mcp-http] {server_name}: cached token not bound to current authorization server — re-authorizing\x1b[0m"
        );
        store.remove(mcp_url);
    }

    match crate::oauth::authorize(client, &meta, mcp_url).await {
        Ok(entry) => {
            let at = entry.access_token.clone();
            store.set(mcp_url, entry);
            Some(at)
        }
        Err(e) => {
            eprintln!("\x1b[31m[mcp-http] {server_name}: OAuth authorization failed: {e}\x1b[0m");
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    /// Build a client + a paired server IO that cleanly signals EOF when
    /// either side drops. Uses TWO duplex pairs — one for each direction —
    /// so the client's writer and the server's reader aren't coupled via
    /// `tokio::io::split`, which keeps the underlying stream alive until
    /// both halves drop.
    fn paired_streams() -> (
        Arc<McpClient>,
        (
            impl AsyncRead + Send + Unpin + 'static,
            impl AsyncWrite + Send + Unpin + 'static,
        ),
    ) {
        let (c_write, s_read) = duplex(4096); // client→server
        let (s_write, c_read) = duplex(4096); // server→client
        let client = McpClient::from_streams("mock", c_read, c_write);
        (client, (s_read, s_write))
    }

    /// Run a closure-driven mock MCP server against the server-side streams.
    async fn run_mock_server<R, W, F>(reader: R, mut writer: W, mut responder: F)
    where
        R: AsyncRead + Send + Unpin + 'static,
        W: AsyncWrite + Send + Unpin + 'static,
        F: FnMut(Value) -> Option<Value> + Send + 'static,
    {
        let mut buf = BufReader::new(reader);
        let mut line = String::new();
        loop {
            line.clear();
            match buf.read_line(&mut line).await {
                Ok(0) => break,
                Ok(_) => {
                    let trimmed = line.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    let msg: Value = match serde_json::from_str(trimmed) {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
                    if let Some(response) = responder(msg) {
                        let out = format!("{}\n", serde_json::to_string(&response).unwrap());
                        if writer.write_all(out.as_bytes()).await.is_err() {
                            break;
                        }
                        let _ = writer.flush().await;
                    }
                }
                Err(_) => break,
            }
        }
    }

    fn jsonrpc_response(id: u64, result: Value) -> Value {
        json!({"jsonrpc": "2.0", "id": id, "result": result})
    }

    fn jsonrpc_error(id: u64, code: i64, message: &str) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {"code": code, "message": message}
        })
    }

    #[tokio::test]
    async fn initialize_handshake_sends_initialize_and_initialized() {
        let (client, (s_read, s_write)) = paired_streams();

        let saw_initialize = Arc::new(Mutex::new(false));
        let saw_initialized = Arc::new(Mutex::new(false));
        let saw_initialize_cb = saw_initialize.clone();
        let saw_initialized_cb = saw_initialized.clone();

        let server_task = tokio::spawn(async move {
            run_mock_server(s_read, s_write, move |msg| {
                let method = msg.get("method").and_then(Value::as_str).unwrap_or("");
                match method {
                    "initialize" => {
                        *saw_initialize_cb.lock().unwrap() = true;
                        let id = msg.get("id").and_then(Value::as_u64).unwrap();
                        Some(jsonrpc_response(
                            id,
                            json!({
                                "protocolVersion": PROTOCOL_VERSION,
                                "capabilities": {},
                                "serverInfo": {"name": "mock", "version": "0.0.1"}
                            }),
                        ))
                    }
                    "notifications/initialized" => {
                        *saw_initialized_cb.lock().unwrap() = true;
                        None
                    }
                    _ => None,
                }
            })
            .await;
        });

        client.initialize().await.expect("initialize");
        tokio::time::sleep(Duration::from_millis(20)).await;
        drop(client);
        let _ = tokio::time::timeout(Duration::from_secs(2), server_task).await;

        assert!(*saw_initialize.lock().unwrap());
        assert!(*saw_initialized.lock().unwrap());
    }

    #[tokio::test]
    async fn list_tools_parses_inputSchema() {
        let (client, (s_read, s_write)) = paired_streams();

        let server_task = tokio::spawn(async move {
            run_mock_server(s_read, s_write, move |msg| {
                let method = msg.get("method").and_then(Value::as_str).unwrap_or("");
                let id = msg.get("id").and_then(Value::as_u64);
                match (method, id) {
                    ("tools/list", Some(id)) => Some(jsonrpc_response(
                        id,
                        json!({
                            "tools": [
                                {
                                    "name": "echo",
                                    "description": "echo back the input",
                                    "inputSchema": {
                                        "type": "object",
                                        "properties": {"text": {"type": "string"}}
                                    }
                                },
                                {"name": "noop"}
                            ]
                        }),
                    )),
                    _ => None,
                }
            })
            .await;
        });

        let tools = client.list_tools().await.expect("list_tools");
        drop(client);
        let _ = tokio::time::timeout(Duration::from_secs(2), server_task).await;

        assert_eq!(tools.len(), 2);
        assert_eq!(tools[0].name, "echo");
        assert_eq!(tools[0].description, "echo back the input");
        assert_eq!(
            tools[0].input_schema["properties"]["text"]["type"],
            "string"
        );
        assert_eq!(tools[1].name, "noop");
        assert_eq!(tools[1].description, "");
        assert_eq!(tools[1].input_schema["type"], "object");
    }

    #[tokio::test]
    async fn call_tool_returns_joined_text_content() {
        let (client, (s_read, s_write)) = paired_streams();

        let server_task = tokio::spawn(async move {
            run_mock_server(s_read, s_write, move |msg| {
                let method = msg.get("method").and_then(Value::as_str).unwrap_or("");
                let id = msg.get("id").and_then(Value::as_u64)?;
                match method {
                    "tools/call" => {
                        let args = msg
                            .pointer("/params/arguments")
                            .cloned()
                            .unwrap_or(json!({}));
                        let text = args
                            .get("text")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_string();
                        Some(jsonrpc_response(
                            id,
                            json!({
                                "content": [
                                    {"type": "text", "text": format!("you said: {text}")},
                                    {"type": "text", "text": "bye"}
                                ],
                                "isError": false
                            }),
                        ))
                    }
                    _ => None,
                }
            })
            .await;
        });

        let out = client
            .call_tool("echo", json!({"text": "hi"}))
            .await
            .expect("call_tool");
        drop(client);
        let _ = tokio::time::timeout(Duration::from_secs(2), server_task).await;

        assert_eq!(out, "you said: hi\nbye");
    }

    #[tokio::test]
    async fn call_tool_surfaces_is_error_as_tool_error() {
        let (client, (s_read, s_write)) = paired_streams();

        let server_task = tokio::spawn(async move {
            run_mock_server(s_read, s_write, move |msg| {
                let id = msg.get("id").and_then(Value::as_u64)?;
                Some(jsonrpc_response(
                    id,
                    json!({
                        "content": [{"type": "text", "text": "tool exploded"}],
                        "isError": true
                    }),
                ))
            })
            .await;
        });

        let err = client
            .call_tool("bad", json!({}))
            .await
            .expect_err("should error");
        drop(client);
        let _ = tokio::time::timeout(Duration::from_secs(2), server_task).await;

        let msg = format!("{err}");
        assert!(msg.contains("mcp tool bad error"));
        assert!(msg.contains("tool exploded"));
    }

    #[tokio::test]
    async fn jsonrpc_error_response_becomes_provider_error() {
        let (client, (s_read, s_write)) = paired_streams();

        let server_task = tokio::spawn(async move {
            run_mock_server(s_read, s_write, move |msg| {
                let id = msg.get("id").and_then(Value::as_u64)?;
                Some(jsonrpc_error(id, -32601, "method not found"))
            })
            .await;
        });

        let err = client
            .request("bogus/method", json!({}))
            .await
            .expect_err("should error");
        drop(client);
        let _ = tokio::time::timeout(Duration::from_secs(2), server_task).await;

        let msg = format!("{err}");
        assert!(msg.contains("mcp error"));
        assert!(msg.contains("method not found"));
    }

    #[tokio::test]
    async fn mcp_tool_impls_tool_trait_and_calls_through() {
        let (client, (s_read, s_write)) = paired_streams();

        let server_task = tokio::spawn(async move {
            run_mock_server(s_read, s_write, move |msg| {
                let id = msg.get("id").and_then(Value::as_u64)?;
                Some(jsonrpc_response(
                    id,
                    json!({
                        "content": [{"type": "text", "text": "pong"}],
                        "isError": false
                    }),
                ))
            })
            .await;
        });

        // Rename for clarity in the tool test (we need the server name to
        // be "weatherbot" so the qualified name comes out right).
        let info = McpToolInfo {
            name: "ping".into(),
            description: "say pong".into(),
            input_schema: json!({"type": "object", "properties": {}}),
        };
        let tool = McpTool::new(client.clone(), info);

        // `client.name` is "mock" from paired_streams, so qualified is "mock__ping".
        assert_eq!(tool.name(), "mock__ping");
        assert_eq!(tool.bare_name(), "ping");
        assert_eq!(tool.description(), "say pong");
        assert!(tool.requires_approval(&json!({})));

        let out = tool.call(json!({})).await.expect("call");
        drop(tool);
        drop(client);
        let _ = tokio::time::timeout(Duration::from_secs(2), server_task).await;

        assert_eq!(out, "pong");
    }

    #[tokio::test]
    async fn transport_closed_fails_pending_requests_cleanly() {
        let (client, (s_read, s_write)) = paired_streams();

        // Server reads one line and then drops both halves.
        let server_task = tokio::spawn(async move {
            let mut buf = BufReader::new(s_read);
            let mut line = String::new();
            let _ = buf.read_line(&mut line).await;
            drop(s_write); // close server→client channel → client reader EOF
        });

        let err = client
            .request("tools/list", json!({}))
            .await
            .expect_err("should error after pipe closed");
        drop(client);
        let _ = tokio::time::timeout(Duration::from_secs(2), server_task).await;

        let msg = format!("{err}");
        assert!(
            msg.contains("transport closed") || msg.contains("channel dropped"),
            "got: {msg}"
        );
    }
}
