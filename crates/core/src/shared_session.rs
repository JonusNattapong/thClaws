//! Shared in-process agent session that backs both the GUI's Terminal
//! and Chat tabs. One Agent, one Session, one history. Both tabs send
//! input through `ShellInput` and subscribe to `ViewEvent` broadcasts —
//! so typing in either tab contributes to the same conversation, and
//! /load replays the same transcript into both views.
//!
//! Only compiled with the `gui` feature because the previous
//! Terminal-tab REPL ran as a separate `--cli` PTY child; the
//! standalone CLI (`thclaws --cli`) is unchanged.

#![cfg(feature = "gui")]

use crate::agent::{Agent, AgentEvent};
use crate::config::AppConfig;
use crate::context::ProjectContext;
use crate::memory::MemoryStore;
use crate::repl::build_provider;
use crate::session::{Session, SessionStore};
use crate::tools::ToolRegistry;
use crate::types::{ContentBlock, Message, Role};
use futures::StreamExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use tokio::sync::broadcast;

/// Inputs to the shared session — produced by either tab.
#[derive(Debug, Clone)]
pub enum ShellInput {
    /// Raw line submitted by the user. Slash-prefix → dispatched as
    /// command, anything else → fed to the agent as a prompt.
    Line(String),
    /// Save the current session to disk, clear history, start fresh.
    NewSession,
    /// Load a session by id and replace history.
    LoadSession(String),
    /// Save the current session (window-close path).
    SaveAndQuit,
}

/// What both tabs render. Each variant maps to a UI affordance:
/// Chat → bubbles + tool blocks, Terminal → ANSI-formatted bytes.
#[derive(Debug, Clone)]
pub enum ViewEvent {
    UserPrompt(String),
    AssistantTextDelta(String),
    ToolCallStart { name: String, label: String },
    ToolCallResult { name: String, output: String },
    SlashOutput(String),
    TurnDone,
    HistoryReplaced(Vec<DisplayMessage>),
    SessionListRefresh(String),
    ErrorText(String),
}

#[derive(Debug, Clone)]
pub struct DisplayMessage {
    pub role: String,
    pub content: String,
}

impl DisplayMessage {
    pub fn from_messages(messages: &[Message]) -> Vec<Self> {
        messages
            .iter()
            .filter_map(|m| {
                let role = match m.role {
                    Role::User => "user",
                    Role::Assistant => "assistant",
                    Role::System => return None,
                };
                let content: Vec<String> = m
                    .content
                    .iter()
                    .filter_map(|b| match b {
                        ContentBlock::Text { text } => Some(text.clone()),
                        ContentBlock::ToolUse { name, .. } => Some(format!("[tool: {name}]")),
                        ContentBlock::ToolResult { content, .. } => {
                            let snippet: String = content.chars().take(200).collect();
                            Some(format!("[result: {snippet}]"))
                        }
                    })
                    .collect();
                if content.is_empty() {
                    return None;
                }
                Some(DisplayMessage {
                    role: role.to_string(),
                    content: content.join("\n"),
                })
            })
            .collect()
    }
}

pub struct SharedSessionHandle {
    pub input_tx: mpsc::Sender<ShellInput>,
    pub events_tx: broadcast::Sender<ViewEvent>,
    pub cancel: Arc<AtomicBool>,
}

impl SharedSessionHandle {
    pub fn subscribe(&self) -> broadcast::Receiver<ViewEvent> {
        self.events_tx.subscribe()
    }

    pub fn request_cancel(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }
}

/// Bundle of owned state the worker loop passes by `&mut` down into
/// slash-command dispatch. Having one struct keeps the dispatch
/// signature readable as we port every REPL command — each of which
/// may mutate any subset of these fields (agent for /model, config
/// for /permissions, session for /load, etc.) or rebuild the agent
/// outright (/model, /provider, /permissions after applying, …).
pub struct WorkerState {
    pub agent: Agent,
    pub config: AppConfig,
    pub session: Session,
    pub session_store: Option<SessionStore>,
    pub tool_registry: ToolRegistry,
    pub system_prompt: String,
    pub cwd: PathBuf,
    /// Shared handle into the SkillTool's internal store. `/skill
    /// install` replaces the store contents through this handle so a
    /// fresh skill is callable in the same session without restart.
    pub skill_store: std::sync::Arc<std::sync::Mutex<crate::skills::SkillStore>>,
    /// Live MCP client subprocesses. Kept so `/mcp add` can append new
    /// clients whose tools are wired into `tool_registry`; dropping
    /// the Vec shuts them all down.
    pub mcp_clients: Vec<std::sync::Arc<crate::mcp::McpClient>>,
}

impl WorkerState {
    /// Rebuild `agent` with a freshly-built provider from `self.config`,
    /// reusing the current tool registry + system prompt. Preserves
    /// `permission_mode` and `thinking_budget`.
    ///
    /// `preserve_history = true` carries the current conversation into
    /// the new Agent (used by mutations that change the tool roster or
    /// system prompt mid-conversation — /mcp add, /kms use, etc.).
    /// `false` clears history (used by /model and /provider switches
    /// where the new provider's schema may differ).
    pub fn rebuild_agent(&mut self, preserve_history: bool) -> crate::error::Result<()> {
        let prev_history = if preserve_history {
            Some(self.agent.history_snapshot())
        } else {
            None
        };
        let provider = build_provider(&self.config)?;
        let prev_perm = self.agent.permission_mode;
        let prev_thinking = self.agent.thinking_budget;
        let new_agent = Agent::new(
            provider,
            self.tool_registry.clone(),
            &self.config.model,
            &self.system_prompt,
        );
        self.agent = new_agent;
        self.agent.permission_mode = prev_perm;
        self.agent.thinking_budget = prev_thinking;
        if let Some(h) = prev_history {
            self.agent.set_history(h);
        }
        Ok(())
    }

    /// Recompute the system prompt from the current `config` (picks up
    /// updated `kms_active`, `team_enabled`, memory, skills, etc.).
    /// Call after any dispatcher mutation that should land in the next
    /// turn's system prompt.
    pub fn rebuild_system_prompt(&mut self) {
        self.system_prompt = build_system_prompt(&self.config, &self.cwd, &self.skill_store);
    }
}

/// Assemble the system prompt from the project context, memory, KMS
/// attachments, team grounding, and skill catalogue. Extracted so both
/// initial spawn and runtime rebuilds (`/kms use`, `/mcp add`, etc.)
/// share the same shape.
pub fn build_system_prompt(
    config: &AppConfig,
    cwd: &std::path::Path,
    skill_store: &std::sync::Arc<std::sync::Mutex<crate::skills::SkillStore>>,
) -> String {
    let ctx = ProjectContext::discover(cwd).unwrap_or(ProjectContext {
        cwd: cwd.to_path_buf(),
        git: None,
        project_instructions: None,
    });
    let system_fallback = if config.system_prompt.is_empty() {
        crate::prompts::defaults::SYSTEM
    } else {
        config.system_prompt.as_str()
    };
    let base_prompt = crate::prompts::load("system", system_fallback);
    let mut system = ctx.build_system_prompt(&base_prompt);

    if let Some(store) = MemoryStore::default_path().map(MemoryStore::new) {
        if let Some(mem) = store.system_prompt_section() {
            system.push_str("\n\n# Memory\n");
            system.push_str(&mem);
        }
    }

    let kms_section = crate::kms::system_prompt_section(&config.kms_active);
    if !kms_section.is_empty() {
        system.push_str("\n\n");
        system.push_str(&kms_section);
    }

    let team_enabled = crate::config::ProjectConfig::load()
        .and_then(|c| c.team_enabled)
        .unwrap_or(false);
    let team_section = team_grounding_prompt(&config.model, team_enabled);
    if !team_section.is_empty() {
        system.push_str("\n\n");
        system.push_str(&team_section);
    }

    let guard = skill_store.lock().ok();
    if let Some(store) = guard.as_ref() {
        if !store.skills.is_empty() {
            system.push_str("\n\n# Available skills (MANDATORY usage)\n");
            system.push_str(
                "The `Skill` tool loads expert instructions for a bundled workflow. \
                 If a user request matches the trigger criteria of any skill below, \
                 you MUST:\n\
                 1. Call `Skill(name: \"<skill-name>\")` FIRST — before any Bash, \
                    Write, Edit, or other tool calls for that task.\n\
                 2. Follow the instructions returned by that skill for the rest of \
                    the task. They override your default approach.\n\
                 3. Announce the skill at the start of your reply, e.g. \
                    \"Using the `pdf` skill to …\".\n\
                 Do NOT implement the task yourself when a matching skill exists — \
                 the skill encodes conventions and scripts you don't have built in.\n\n",
            );
            let mut entries: Vec<&crate::skills::SkillDef> = store.skills.values().collect();
            entries.sort_by(|a, b| a.name.cmp(&b.name));
            for skill in entries {
                system.push_str(&format!("- **{}** — {}", skill.name, skill.description));
                if !skill.when_to_use.is_empty() {
                    system.push_str(&format!("\n  Trigger: {}", skill.when_to_use));
                }
                system.push('\n');
            }
        }
    }

    system
}

pub fn spawn() -> SharedSessionHandle {
    let (input_tx, input_rx) = mpsc::channel::<ShellInput>();
    let (events_tx, _) = broadcast::channel::<ViewEvent>(256);
    let cancel = Arc::new(AtomicBool::new(false));

    let events_tx_for_thread = events_tx.clone();
    let cancel_for_thread = cancel.clone();
    std::thread::spawn(move || {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
            rt.block_on(run_worker(
                input_rx,
                events_tx_for_thread.clone(),
                cancel_for_thread,
            ));
        }));
        if let Err(payload) = result {
            let msg = if let Some(s) = payload.downcast_ref::<&str>() {
                (*s).to_string()
            } else if let Some(s) = payload.downcast_ref::<String>() {
                s.clone()
            } else {
                "shared session panicked".to_string()
            };
            let _ = events_tx_for_thread.send(ViewEvent::ErrorText(format!(
                "internal error: {msg}"
            )));
        }
    });

    SharedSessionHandle {
        input_tx,
        events_tx,
        cancel,
    }
}

async fn run_worker(
    input_rx: mpsc::Receiver<ShellInput>,
    events_tx: broadcast::Sender<ViewEvent>,
    cancel: Arc<AtomicBool>,
) {
    let cwd = std::env::current_dir().unwrap_or_default();
    let config = AppConfig::load().unwrap_or_default();

    // Shared SkillTool store — we keep a handle in WorkerState so
    // `/skill install` can repopulate it without restarting.
    let skill_store = std::sync::Arc::new(std::sync::Mutex::new(
        crate::skills::SkillStore::discover(),
    ));

    let mut tools = ToolRegistry::with_builtins();
    if !config.kms_active.is_empty() {
        tools.register(std::sync::Arc::new(crate::tools::KmsReadTool));
        tools.register(std::sync::Arc::new(crate::tools::KmsSearchTool));
    }
    let team_enabled = crate::config::ProjectConfig::load()
        .and_then(|c| c.team_enabled)
        .unwrap_or(false);
    if team_enabled {
        let _ = crate::team::register_team_tools(&mut tools, "lead");
    }
    let skill_tool = crate::skills::SkillTool::new_from_handle(skill_store.clone());
    tools.register(std::sync::Arc::new(skill_tool));

    // Spawn MCP servers (project + user) and register their tools —
    // the REPL does this at startup too, but shared_session used to
    // skip it which meant configured MCP servers silently had no
    // tools available in the GUI.
    let mut mcp_clients: Vec<std::sync::Arc<crate::mcp::McpClient>> = Vec::new();
    for server_cfg in &config.mcp_servers {
        match crate::mcp::McpClient::spawn(server_cfg.clone()).await {
            Ok(client) => {
                if let Ok(tool_infos) = client.list_tools().await {
                    for info in tool_infos {
                        let tool = crate::mcp::McpTool::new(client.clone(), info);
                        tools.register(std::sync::Arc::new(tool));
                    }
                    mcp_clients.push(client);
                } else {
                    let _ = events_tx.send(ViewEvent::ErrorText(format!(
                        "[mcp] list_tools failed for '{}'",
                        server_cfg.name
                    )));
                }
            }
            Err(e) => {
                let _ = events_tx.send(ViewEvent::ErrorText(format!(
                    "[mcp] '{}' failed to start: {e}",
                    server_cfg.name
                )));
            }
        }
    }

    let system = build_system_prompt(&config, &cwd, &skill_store);

    let provider = match build_provider(&config) {
        Ok(p) => p,
        Err(e) => {
            let _ = events_tx.send(ViewEvent::ErrorText(format!("Provider error: {e}")));
            return;
        }
    };
    let agent = Agent::new(provider, tools.clone(), &config.model, &system);

    let session_store = SessionStore::default_path().map(SessionStore::new);
    let current_session = Session::new(&config.model, cwd.to_string_lossy());

    let mut state = WorkerState {
        agent,
        config,
        session: current_session,
        session_store,
        tool_registry: tools,
        system_prompt: system,
        cwd,
        skill_store,
        mcp_clients,
    };

    while let Ok(input) = input_rx.recv() {
        match input {
            ShellInput::Line(text) => {
                cancel.store(false, Ordering::Relaxed);
                handle_line(text, &mut state, &events_tx, &cancel).await;
            }
            ShellInput::NewSession => {
                save_history(&state.agent, &mut state.session, &state.session_store);
                state.agent.clear_history();
                state.session =
                    Session::new(&state.config.model, state.cwd.to_string_lossy());
                let _ = events_tx.send(ViewEvent::HistoryReplaced(Vec::new()));
                let _ = events_tx.send(ViewEvent::SessionListRefresh(build_session_list(
                    &state.session_store,
                )));
            }
            ShellInput::LoadSession(id) => {
                let Some(ref store) = state.session_store else { continue };
                let Ok(loaded) = store.load(&id) else {
                    let _ = events_tx.send(ViewEvent::ErrorText(format!(
                        "Failed to load session '{id}'"
                    )));
                    continue;
                };
                state.agent.set_history(loaded.messages.clone());
                state.session = loaded;
                let display = DisplayMessage::from_messages(&state.session.messages);
                let _ = events_tx.send(ViewEvent::HistoryReplaced(display));
            }
            ShellInput::SaveAndQuit => {
                save_history(&state.agent, &mut state.session, &state.session_store);
                break;
            }
        }
    }
}

pub(crate) fn save_history(
    agent: &Agent,
    session: &mut Session,
    store: &Option<SessionStore>,
) {
    let history = agent.history_snapshot();
    if history.is_empty() {
        return;
    }
    session.sync(history);
    if let Some(ref store) = store {
        let _ = store.save(session);
    }
}

pub(crate) fn build_session_list(store: &Option<SessionStore>) -> String {
    let sessions: Vec<serde_json::Value> = store
        .as_ref()
        .and_then(|s| s.list().ok())
        .unwrap_or_default()
        .into_iter()
        .take(20)
        .map(|s| {
            serde_json::json!({
                "id": s.id,
                "model": s.model,
                "messages": s.message_count,
                "title": s.title,
            })
        })
        .collect();
    serde_json::json!({"type": "sessions_list", "sessions": sessions}).to_string()
}

async fn handle_line(
    text: String,
    state: &mut WorkerState,
    events_tx: &broadcast::Sender<ViewEvent>,
    cancel: &Arc<AtomicBool>,
) {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return;
    }

    let _ = events_tx.send(ViewEvent::UserPrompt(trimmed.to_string()));

    if trimmed.starts_with('/') {
        crate::shell_dispatch::dispatch(trimmed, state, events_tx).await;
        let _ = events_tx.send(ViewEvent::TurnDone);
        return;
    }

    let mut stream = Box::pin(state.agent.run_turn(trimmed.to_string()));
    while let Some(ev) = stream.next().await {
        if cancel.load(Ordering::Relaxed) {
            let _ = events_tx.send(ViewEvent::ErrorText("(interrupted)".into()));
            save_history(&state.agent, &mut state.session, &state.session_store);
            let _ = events_tx
                .send(ViewEvent::SessionListRefresh(build_session_list(&state.session_store)));
            let _ = events_tx.send(ViewEvent::TurnDone);
            return;
        }
        match ev {
            Ok(AgentEvent::Text(s)) => {
                let _ = events_tx.send(ViewEvent::AssistantTextDelta(s));
            }
            Ok(AgentEvent::ToolCallStart { name, input, .. }) => {
                let label = format_tool_label(&name, &input);
                let _ = events_tx.send(ViewEvent::ToolCallStart { name, label });
            }
            Ok(AgentEvent::ToolCallResult { name, output, .. }) => {
                let out = output.unwrap_or_else(|e| e);
                let _ = events_tx.send(ViewEvent::ToolCallResult {
                    name,
                    output: out,
                });
            }
            Ok(AgentEvent::Done { .. }) => {
                save_history(&state.agent, &mut state.session, &state.session_store);
                let _ = events_tx
                    .send(ViewEvent::SessionListRefresh(build_session_list(&state.session_store)));
                let _ = events_tx.send(ViewEvent::TurnDone);
            }
            Err(e) => {
                let _ = events_tx.send(ViewEvent::ErrorText(format!("Error: {e}")));
                let _ = events_tx.send(ViewEvent::TurnDone);
            }
            _ => {}
        }
    }
}

/// System-prompt addendum that grounds the model in thClaws's team
/// feature and pushes back against Claude Code training-data bias.
fn team_grounding_prompt(model: &str, team_enabled: bool) -> String {
    let kind = crate::providers::ProviderKind::detect(model);
    let on_claude_sdk = matches!(kind, Some(crate::providers::ProviderKind::AgentSdk));

    if !team_enabled && !on_claude_sdk {
        return String::new();
    }

    // Special case: teamEnabled is on, but the user picked agent/* —
    // which shells to the local `claude` CLI subprocess. That
    // subprocess uses Claude Code's own built-in toolset and does NOT
    // see thClaws's tool registry. So our `TeamCreate` /
    // `SpawnTeammate` / etc. are registered in our registry but are
    // unreachable by the model. Telling the model to use them would
    // be telling it to call tools it cannot see.
    if team_enabled && on_claude_sdk {
        return String::from(
            "# Agent Teams — UNREACHABLE on this provider\n\n\
             The user has enabled thClaws's team feature \
             (`teamEnabled: true`), but they are also running on the \
             `agent/*` provider — which shells to the local `claude` \
             CLI as a subprocess. That subprocess uses Claude Code's \
             own built-in toolset (`Agent`, `Bash`, `Edit`, `Read`, \
             `ScheduleWakeup`, `Skill`, `ToolSearch`, `Write`) and \
             does NOT see thClaws's tool registry.\n\n\
             This means thClaws's `TeamCreate`, `SpawnTeammate`, \
             `SendMessage`, `CheckInbox`, `TeamStatus`, \
             `TeamTaskCreate`/`List`/`Claim`/`Complete`, and \
             `TeamMerge` tools are REGISTERED in thClaws but are \
             unreachable from your current toolset. You literally \
             cannot call them.\n\n\
             Claude Code's own `TeamCreate` / `Agent` / `TodoWrite` / \
             `AskUserQuestion` / `ToolSearch` / `SendMessage` \
             built-ins are available to you, but they write state \
             under `~/.claude/teams/` and `~/.claude/tasks/` which is \
             invisible to the thClaws Team tab. Calling them produces \
             a fabricated success — the user sees an empty Team tab.\n\n\
             If the user asks you to \"create a team\" / \"spawn agents\":\n\
             - Explain that thClaws's team tools are unreachable from \
             the `agent/*` provider (their tool registry doesn't \
             cross the CLI subprocess boundary).\n\
             - Tell them to switch to a non-`agent/*` provider — e.g. \
             `claude-sonnet-4-6`, `claude-opus-4-7`, `gpt-4o`, etc. — \
             via `/model` or `/provider`. Once switched, thClaws's \
             team tools are directly callable.\n\
             - Offer to proceed sequentially without a team if they \
             prefer to stay on the `agent/*` model.\n\n\
             Do NOT pretend a team has been created. Do NOT call \
             Claude Code's built-in `TeamCreate` etc. as a substitute. \
             The honest answer is the only useful one.\n",
        );
    }

    if !team_enabled {
        return String::from(
            "# Agent Teams — DISABLED in this workspace\n\n\
             The user has NOT enabled thClaws's team feature \
             (`teamEnabled: true` is missing from `.thclaws/settings.json`). \
             thClaws's team tools (`TeamCreate`, `SpawnTeammate`, `SendMessage`, \
             `CheckInbox`, `TeamStatus`, `TeamTaskCreate/List/Claim/Complete`, \
             `TeamMerge`) are NOT registered in this session and you cannot \
             call them.\n\n\
             You are running under the local `claude` CLI subprocess \
             (Anthropic Agent SDK), which DOES ship its own `TeamCreate`, \
             `Agent`, `TodoWrite`, `AskUserQuestion`, `ToolSearch`, \
             `SendMessage` built-ins backed by `~/.claude/teams/` and \
             `~/.claude/tasks/`. DO NOT CALL THEM. Their state is invisible \
             to thClaws — the Team tab polls `.thclaws/team/agents/` locally \
             and will never see an SDK-created team, so the user gets a \
             fabricated success story with nothing behind it.\n\n\
             If the user asks you to \"create a team\" / \"spawn agents\" / \
             \"set up a team of subagents\", respond in plain text:\n\
             - Explain that thClaws's team feature is off in this workspace.\n\
             - Tell them to set `teamEnabled: true` in `.thclaws/settings.json` \
             (or globally in `~/.config/thclaws/settings.json`) and restart \
             the app.\n\
             - Offer to proceed WITHOUT a team by handling the task yourself \
             sequentially.\n\n\
             Do NOT claim to have created a team, spawned teammates, written \
             config, or stored state. Do NOT reference `~/.claude/teams/` or \
             `~/.claude/tasks/` paths. The only honest response is \"teams are \
             disabled\" — anything else is a hallucination.\n",
        );
    }

    let mut out = String::from(
        "# Agent Teams (thClaws native)\n\n\
         This workspace has thClaws's team feature ENABLED. When the user asks for \
         parallel work via a team, use ONLY these thClaws tools — they are the \
         canonical implementation and their state is visible in the Team tab:\n\n\
         - `TeamCreate` — define a team (name + member agents with roles/prompts). \
         Writes `.thclaws/team/config.json` in the current project root.\n\
         - `SpawnTeammate` — start one named teammate. Spawns a thClaws subprocess \
         that polls its inbox in a tmux pane (or background).\n\
         - `SendMessage` — deliver a message to a teammate's inbox.\n\
         - `CheckInbox` — read your own inbox.\n\
         - `TeamStatus` — summarise the team.\n\
         - `TeamTaskCreate` / `TeamTaskList` / `TeamTaskClaim` / `TeamTaskComplete` — \
         a shared task queue teammates can claim from.\n\
         - `TeamMerge` — (lead only) merge each teammate's git worktree back into \
         the main branch.\n\n\
         Team state lives under `.thclaws/team/` **in the current project root** — \
         NOT under `~/.claude/teams/`, NOT under `~/.claude/tasks/`. Do not reference \
         those paths; they are from a different product.\n\n\
         You are the team **lead**. After `TeamCreate`:\n\
         1. Do NOT use `Bash`/`Write`/`Edit` to build code — delegate via `SendMessage`.\n\
         2. Use `TeamTaskCreate` to queue work; teammates claim via `TeamTaskClaim`.\n\
         3. Use `Read`/`Glob`/`Grep` only for review and verification.\n\
         4. Watch `CheckInbox` / `TeamStatus` between coordination rounds.\n\
         \n\
         # CRITICAL: do NOT call Claude Code's Agent SDK team tools\n\n\
         Your training data contains references to an Anthropic Managed Agents \
         SDK server-side toolset (`agent_toolset_20260401`) that ships its own \
         `TeamCreate`, `Agent`, `AskUserQuestion`, `TodoWrite`, `ToolSearch`, \
         `SendMessage` tools backed by `~/.claude/teams/` and `~/.claude/tasks/`. \
         Those are a DIFFERENT SYSTEM, invisible to thClaws — if you call them \
         (or claim to have called them in your text output), the user will see \
         an empty Team tab and think nothing happened.\n\n\
         Rules that apply regardless of which provider you are running on:\n\
         - When the user asks about \"teams\" / \"agents\" / \"task queue\", use \
         the thClaws tools listed above. `TeamCreate` and `SendMessage` in this \
         workspace mean the thClaws versions — never the SDK's.\n\
         - Never reference `~/.claude/teams/`, `~/.claude/tasks/`, or \
         `~/.config/thclaws/teams/` paths in your replies. Teams live in \
         `.thclaws/team/`.\n\
         - Do not call `AskUserQuestion`, `TodoWrite`, `ToolSearch`, or a bare \
         `Agent` tool. Those belong to Claude Code's interactive flow and do \
         not exist in thClaws. If you need a task list, use `TeamTaskCreate`. \
         If you need to ask the user, just ask them in plain text.\n\
         - Do not claim to have created a team, spawned agents, or stored \
         config unless you actually called the corresponding thClaws tool and \
         got a success response back.\n",
    );

    if on_claude_sdk {
        out.push_str(
            "\n# Additional note for the Claude Agent SDK provider\n\n\
             You ARE running under the local `claude` CLI subprocess right now, \
             which ships its own `TeamCreate`, `Agent`, `AskUserQuestion`, \
             `TodoWrite`, and `ToolSearch` built-ins. Calling them will appear \
             to succeed inside Claude Code's own world, but the thClaws Team \
             tab polls `.thclaws/team/agents/` and will never see a team \
             created that way. Treat any impulse to call those tools as a bug.\n",
        );
    }

    out
}

fn format_tool_label(name: &str, input: &serde_json::Value) -> String {
    let detail = match name {
        "Skill" => input.get("name").and_then(|v| v.as_str()).map(|n| format!("({n})")),
        "Task" => input
            .get("agent")
            .and_then(|v| v.as_str())
            .map(|a| format!("(agent={a})")),
        "Bash" => input.get("command").and_then(|v| v.as_str()).map(|c| {
            let first: String = c.chars().take(40).collect();
            format!("({first}{})", if c.chars().count() > 40 { "…" } else { "" })
        }),
        "Read" | "Write" | "Edit" => input
            .get("path")
            .and_then(|v| v.as_str())
            .map(|p| format!("({p})")),
        "Grep" | "Glob" => input
            .get("pattern")
            .and_then(|v| v.as_str())
            .map(|p| format!("({p})")),
        "WebFetch" => input.get("url").and_then(|v| v.as_str()).map(|u| {
            format!("({})", u.chars().take(60).collect::<String>())
        }),
        "WebSearch" => input
            .get("query")
            .and_then(|v| v.as_str())
            .map(|q| format!("({q})")),
        _ => None,
    }
    .unwrap_or_default();
    if detail.is_empty() {
        name.to_string()
    } else {
        format!("{name} {detail}")
    }
}
