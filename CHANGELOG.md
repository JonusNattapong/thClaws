# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.2] — 2026-04-22

### Added

- **Shared in-process session backing both GUI tabs.** Terminal and Chat tabs now share one Agent + Session + history; typing in either contributes to the same conversation, and `/load` replays the transcript into both.
- **Every REPL slash command works from the GUI.** `/model`, `/provider`, `/permissions`, `/thinking`, `/compact`, `/doctor`, `/mcp`, `/plugin`, `/skill`, `/kms`, `/team`, and the rest all execute identically in Terminal, Chat, and CLI.
- **Live activation for mutations** (no restart required): `/mcp add` spawns the subprocess and registers its tools; `/skill install` refreshes the store and updates the system prompt; `/plugin install` picks up plugin-contributed skills immediately; `/kms use` / `/kms off` register and deregister tools on the fly.
- **Agent Teams toggle in the Settings menu** — one-click on/off for `teamEnabled` without editing `settings.json`.
- **Light/dark/system theme** — click the gear icon → Appearance. Covers app chrome, xterm terminal palette, CodeMirror editor, and Markdown preview; persists to `~/.config/thclaws/theme.json`.
- **Files-tab viewer + editor** — syntax-highlighted preview (CodeMirror 6, ~40 languages), GFM markdown preview (comrak), TipTap markdown editor, CodeMirror code editor with dirty-state tracking and Cmd/Ctrl+S save.
- **Chat tab welcome logo.** Team tab is always visible with an empty-state pointer.

### Fixed

- **Windows startup hang at the secrets-backend dialog.** Every `std::env::var("HOME")` site now goes through a cross-platform `home_dir()` helper that understands `%USERPROFILE%` and `%HOMEDRIVE%%HOMEPATH%`. Previously the silent `Error::Config("HOME is not set")` left the user staring at a silently re-enabled button.
- **Multi-line paste in Terminal tab** submits as one prompt instead of firing one `shell_input` per line.
- **Terminal assistant output concatenates** during streaming — previously each chunk erased the previous one.
- **ANSI escape codes stripped from Chat bubbles** — slash-command output (`render_help`) no longer shows `[2m...[0m` junk.
- **Ctrl+C on empty line cancels the in-flight turn** (was a no-op after the shared-session refactor).
- **Team tab auto-shows** after `TeamCreate` — no longer gated on `teamEnabled`.
- **`/provider X` falls back to the first available model** if the hardcoded default isn't in the live catalogue. `/model X` stays strict so typos fail loud.
- **System-prompt grounding on `agent/*` provider** — the SDK subprocess doesn't receive thClaws's tool registry; when the user asks for teams from `agent/*`, the model is told honestly that team tools are unreachable and to switch provider.

### Removed

- **`managed/*` (Anthropic Managed Agents cloud) provider.** The Managed Agents API is designed for deploying long-running agents to Anthropic's cloud with server-side tool execution — a poor fit for a local interactive CLI where tool calls should hit the user's filesystem.

### Diagnostics

- `THCLAWS_DEVTOOLS=1` opens the WebView devtools so users can Inspect → Console on a blank screen.
- Startup modal shows a diagnostic card after 3 seconds of IPC dead-air, listing `window.ipc` availability, platform, and UserAgent — instead of an indefinite blank screen.

## [0.2.1] — 2026-04-21

First public open-source release — version and date will be set on tag.

### Agent core

- **Native Rust agent loop** — single-binary distribution for macOS, Windows, Linux
- **Streaming provider abstraction** — token-by-token output to the UI, tool-use assembly across chunks
- **History compaction** — automatic when context approaches the configured budget, preserves semantic coherence
- **Permission modes** — `auto`, `ask`, `accept-all` with per-tool approval flow
- **Hooks** — shell commands triggered on agent lifecycle events (before-tool, after-response, etc.)
- **Retry loop with exponential backoff** — skips retries on config errors to surface actionable messages immediately
- **Max-iteration cap** — prevents runaway tool-call loops
- **Compatible session format** (JSONL, append-only) with rename and load-by-name

### Providers

- **Anthropic Claude** — with extended thinking (budget-configurable), prompt caching, and Claude Code CLI bridge
- **OpenAI** — Chat Completions and Responses API
- **Google Gemini** — including multi-byte-safe streaming
- **DashScope / Qwen**
- **Ollama** (local, also exposed as Ollama-Anthropic for drop-in compatibility)
- **Agentic Press LLM gateway** — first-class provider with fixed URL
- **Multi-provider switching mid-session** via `/provider` and `/model`
- **Model validation** — `/model NAME` verifies availability against the active provider before committing
- **Auto-fallback at startup** — picks the first provider with credentials if the configured model has no key

### Tools

- File: `Read`, `Write`, `Edit`, `Glob`, `Ls`, `Grep`
- Shell: `Bash` (with timeout, sandboxed cwd)
- Web: `WebFetch`, `WebSearch` (Tavily / Brave / DuckDuckGo / auto)
- User interaction: `AskUserQuestion`, `TodoWrite`
- Planning: `EnterPlanMode`, `ExitPlanMode`
- Delegation: `Task` (subagent with recursion up to `max_depth`)
- Knowledge: `KmsRead`, `KmsSearch`
- Team coordination: `SpawnTeammate`, `SendMessage`, `CheckInbox`, `TeamStatus`, `TeamCreate`, `TeamTaskCreate`, `TeamTaskList`, `TeamTaskClaim`, `TeamTaskComplete`
- Tool filtering via `allowedTools` / `disallowedTools` in config

### Claude Code compatibility

- Reads `CLAUDE.md` and `AGENTS.md` (walked up from `cwd`)
- `.claude/skills/`, `.claude/agents/`, `.claude/rules/`, `.claude/commands/`
- `.thclaws/` counterparts: `.thclaws/skills/`, `.thclaws/agents/`, `.thclaws/rules/`, `.thclaws/AGENTS.md`, `.thclaws/CLAUDE.md`
- `.mcp.json` at project root (primary) and `.thclaws/mcp.json`
- `~/.claude/settings.json` fallback for users migrating from Claude Code
- Permission shapes: string (`"auto"` / `"ask"`) and Claude Code object (`{allow, deny}` with `Tool(*)` globs)

### Built-in KMS (Knowledge Management System)

- Karpathy-style personal / project wikis under `~/.config/thclaws/kms/` and `.thclaws/kms/`
- Multi-select active list in `.thclaws/settings.json` — multiple KMS feed a single chat
- `index.md` injected into the system prompt; pages pulled on demand via `KmsRead` / `KmsSearch`
- No embeddings in v1 (grep + read); hosted embeddings planned for future RAG upgrade
- Slash commands: `/kms`, `/kms new [--project] NAME`, `/kms use`, `/kms off`, `/kms show`
- Sidebar checkbox UI for attach / detach

### Agent Teams

- Multi-agent coordination via tmux session with a GUI layer
- Role separation: `lead` coordinator + `teammate` executors
- Mailbox-based message passing
- Team tasks (create / list / claim / complete)
- Opt-in via `teamEnabled: true` in settings
- Worktree isolation — teammates can run in separate git worktrees

### Plugin system

- Install from git URL or `.zip` archive
- Enable / disable / show
- Plugins contribute skills, commands, agents, and MCP servers under one manifest
- Project-scope and user-scope installations
- `/plugin` slash command family (install / remove / enable / disable / show)

### MCP (Model Context Protocol)

- stdio transport (spawned subprocess)
- HTTP Streamable transport
- OAuth 2.1 + PKCE for protected MCP servers
- `/mcp add [--user] NAME URL`, `/mcp remove [--user] NAME`
- Discovered tools namespaced by server name

### Skills

- Claude Code's skill format (`SKILL.md` with frontmatter)
- Project, user, and plugin scopes (all merged)
- Exposed as a `Skill` tool AND as slash-command shortcuts (`/skill-name`)
- `/skill install [--user] <git-url-or-.zip> [name]` for installing remote skills
- Skill catalog surfaced in the system prompt

### Desktop GUI

- Native `wry` webview + `tao` windowing (not Electron)
- React + Vite frontend built as a single HTML file
- Sidebar: provider status, active model, sessions, MCP servers, knowledge bases
- Chat panel with streaming text rendering
- xterm.js terminal tab with native clipboard bridge (`arboard`) — Cmd/Ctrl+C/X/V/A/Z
- Ctrl+C heuristic: clears current line when non-empty, otherwise passes SIGINT
- Files tab
- Team view tab (tmux pane preview)
- Settings menu (gear popup): Global instructions, Folder instructions, Provider API keys
- Tiptap-based Markdown editor for AGENTS.md (round-trip through `tiptap-markdown`)
- Startup folder modal — pick working directory on launch
- Provider-ready indicator (green / red dot + strike-through when no key)
- Auto-switch model to a working provider when a key is saved
- Session rename with inline pencil button; `/load by name`
- Turn duration display after each assistant response

### Memory

- Persistent memory store at `~/.config/thclaws/memory/`
- Four memory types: user, feedback, project, reference
- `MEMORY.md` index auto-maintained
- `/memory list`, `/memory read NAME`
- Frontmatter-based classification so future conversations recall relevance

### Secrets & security

- OS keychain integration (macOS Keychain / Windows Credential Manager / Linux Secret Service)
- **Secrets-backend chooser** — first launch asks OS keychain or `.env`
- Single-entry keychain bundle — all provider keys in one item, one ACL prompt per launch
- `.env` fallback when keychain is unavailable (e.g. headless Linux)
- Cross-process key visibility — GUI and PTY-child REPL read the same keychain entry
- Precedence: shell export > keychain > `.env` file
- Sandboxed file tool operations (path-traversal rejection)
- Permission system protects destructive operations
- Env toggles: `THCLAWS_DISABLE_KEYCHAIN` (test opt-out), `THCLAWS_KEYCHAIN_TRACE` (diagnostics)

### Observability

- Per-provider, per-model token usage tracking (`/usage`)
- Turn duration surfaced after each LLM response
- Optional raw-response dump to stderr (`THCLAWS_SHOW_RAW=1`)
- Keychain trace logs for cross-process debugging

### Developer experience

- Slash commands: `/help`, `/clear`, `/history`, `/model`, `/models`, `/provider`, `/providers`, `/config`, `/save`, `/load`, `/sessions`, `/rename`, `/memory`, `/mcp`, `/plugin`, `/plugins`, `/tasks`, `/context`, `/version`, `/cwd`, `/thinking`, `/compact`, `/doctor`, `/skills`, `/skill`, `/permissions`, `/team`, `/usage`, `/kms`
- Shell escape: `! <command>` runs a shell command inline
- `--print` / `-p` non-interactive mode for scripting
- `--resume SESSION_ID` (or `last`) to pick up where you left off
- `--team-agent NAME` for spawning teammates
- Graceful startup — REPL opens with a friendly placeholder if no API key is configured
- Dual CLI + GUI from the same binary
- Compile-time default prompts with `.thclaws/prompt/` overrides

---

*Development prior to 0.2.0 was internal. The public history starts with this release.*
