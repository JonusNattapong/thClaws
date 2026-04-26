# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.1] — 2026-04-27

Same-day patch release fixing a critical Windows-only bug surfaced
within hours of v0.4.0 shipping.

### Fixed

- **Bash tool unusable on Windows** ([#29](https://github.com/thClaws/thClaws/issues/29),
  Chawasit Tengtrairatana). `/bin/sh` was hardcoded at 4 sites
  (`tools/bash.rs`, `team.rs`, `repl.rs`, `hooks.rs`) — Windows
  doesn't have that path, so spawn returned `os error 3` (path
  not found) and the agent was effectively crippled on Win11.
  Centralized shell resolution into `util::shell_command_{sync,
  async}()`, branching on `cfg!(windows)`. On Windows this is
  `cmd.exe /C <cmd>`; on Unix `/bin/sh -c <cmd>`, unchanged.

### Added

- **`THCLAWS_SHELL` env override.** Power users with `bash` from
  WSL / Git Bash, or who prefer `pwsh`, can set
  `THCLAWS_SHELL="bash -c"` (or `"pwsh -Command"`, etc.). The
  helper splits on whitespace into `(executable, flag)`. Useful on
  Windows where `cmd.exe` doesn't parse bash-syntax commands the
  same as `bash` does.

### Caveats

Bash-syntax commands the agent emits (`find . -name '*.rs'`,
single-quoted args, complex pipelines) may not parse identically
under `cmd.exe`. Set `THCLAWS_SHELL="bash -c"` if you have Git Bash
or WSL `bash` on `PATH` for closer-to-Unix semantics on Windows.

## [0.4.0] — 2026-04-27

Minor release. Provider expansion + agent-loop UX polish + a class
of bugs around credential detection. Substantial accumulated work
from same-day batch PR processing across 7 community contributors.

### Added — Providers (4 new)

- **Z.ai (GLM Coding Plan).** OpenAI-compatible upstream at
  `https://api.z.ai/api/coding/paas/v4`. Routes via `zai/<id>`
  prefix, default `zai/glm-4.6`. API key in `ZAI_API_KEY`. Power
  users on the BigModel SKU can override via `ZAI_BASE_URL`.
  Closes [#14](https://github.com/thClaws/thClaws/issues/14).
- **LMStudio.** Local OpenAI-compatible runtime at `/v1`, default
  `http://localhost:1234/v1`. No auth. User-configurable base URL
  via Settings (mirrors the Ollama UX); env override
  `LMSTUDIO_BASE_URL`.
- **Azure AI Foundry** ([#21](https://github.com/thClaws/thClaws/pull/21),
  Parinya-chab / joparin). Anthropic-Claude-on-Azure via
  `{resource}/anthropic/v1/messages` with `x-api-key` auth. Reuses
  `AnthropicProvider` with a custom base URL — no duplicate stream
  code. Default model placeholder `azure/<deployment>` (Azure
  deployments are user-named); set via
  `/model azure/<your-deployment>` once `AZURE_AI_FOUNDRY_ENDPOINT`
  + `AZURE_AI_FOUNDRY_API_KEY` are configured. Forward-looking
  hooks added to `OpenAIProvider` (`with_api_key_header`,
  `with_list_models_url`) for a future Azure OpenAI provider.
- **Ollama Cloud** ([#28](https://github.com/thClaws/thClaws/pull/28),
  Av0cadoo). Hits `https://ollama.com/api/chat` with Bearer auth;
  reuses local Ollama's NDJSON parser. Round-trips the cloud-
  specific `thinking` field as a sibling on assistant messages
  (DeepSeek V4, Kimi K2.5, GLM-5, etc. emit reasoning content
  separately from the visible answer). 38 cloud-only models
  auto-discovered via the new catalogue-seed probe — including
  `deepseek-v4-flash`, `kimi-k2.5/2.6`, `glm-5/5.1`,
  `qwen3-coder-next`, `mistral-large-3:675b`, `gpt-oss:20b/120b`.
  Closes [#17](https://github.com/thClaws/thClaws/issues/17).

### Added — Agent-loop UX

- **AskUserQuestion GUI bridge** ([#16](https://github.com/thClaws/thClaws/pull/16),
  Kinzen-dev). The agent's `AskUser` tool used to fall through to
  invisible CLI stdin in the GUI — chat hung indefinitely. The
  question now appears as a chat-composer reply prompt; user
  reply routes back through a `oneshot` to the awaiting tool call.
  Falls back to CLI readline when no GUI is registered.
- **macOS Cmd+Q / Cmd+W shutdown shortcuts** ([#16](https://github.com/thClaws/thClaws/pull/16)).
  Two-layer coverage (frontend keydown listener + tao native
  KeyboardInput) so Cmd+Q reaches the SaveAndQuit save path even
  in fullscreen / focus-edge cases.
- **Post-key-entry model picker** ([#13](https://github.com/thClaws/thClaws/issues/13)).
  After successfully saving an API key in Settings, if the
  provider has a non-trivial catalogue (≥3 models, skipping
  runtime-loaded backends), a searchable modal opens so the user
  can pick a default model.
- **`/model` interactive picker on no-args** ([#25](https://github.com/thClaws/thClaws/issues/25),
  tkvision). Typing `/model` with no arguments now opens the
  same picker modal in addition to printing the current model.
  Reuses the post-key picker's UX. CLI-side TUI picker is a future
  follow-up.
- **Slash-command popup** ([#20](https://github.com/thClaws/thClaws/pull/20),
  siharat-th). Typing `/` in chat or terminal opens an
  autocomplete menu — built-in commands grouped by category
  (Session / Model / Context / Extensions / Team / System), plus
  user `.claude/commands/` and installed skills. Arrow keys
  navigate, Tab/Enter accept, Esc cancels. Smart Enter: only
  swallows Enter while composing the command name, falls through
  to submit once arguments are being typed.
- **Terminal caret-aware editing** ([#22](https://github.com/thClaws/thClaws/pull/22),
  siharat-th). Left/Right arrow keys, Home/End, Ctrl-A/Ctrl-E
  navigate the line buffer instead of echoing escape codes.
  Backspace and printable-char insertion are caret-aware: the
  fast `term.write(ch)` / `\b \b` path stays at end-of-line;
  mid-line edits redraw so the tail shifts correctly.

### Added — Catalogue

- **`agent/claude-opus-4-7-1m`** in the agent-sdk catalogue
  ([#26](https://github.com/thClaws/thClaws/issues/26), tkvision).
  Max-subscription users on the `agent/*` provider can now
  explicitly select the 1M-context Opus variant.
- **Ollama Cloud auto-discovery** in `catalogue-seed`. Probes
  `https://ollama.com/v1/models` when `OLLAMA_CLOUD_API_KEY` is
  set; refreshes 38 cloud rows every run.
- **`load_dotenv_walking_up()`** in `catalogue-seed` — walks up
  from cwd to find a workspace-root `.env`, so the operator tool
  picks up API keys regardless of which directory cargo is invoked
  from.

### Changed

- **Default Gemini model** `gemini-2.0-flash` → `gemini-2.5-flash`
  ([#27](https://github.com/thClaws/thClaws/pull/27), gokusenz).
  Google's deprecation page lists 2.0-flash as deprecated with
  shutdown 2026-06-01. Existing user configs that explicitly pin
  2.0-flash still work.
- **Read tool** now errors out clearly when bytes don't match any
  supported image format (PNG/JPEG/WebP/GIF) instead of guessing
  the MIME from the extension. Real images sniff fine; only the
  wrong-extension/corrupted unhappy path changes.

### Fixed

- **Empty `ANTHROPIC_API_KEY=""` (or any provider key) was treated
  as configured.** `std::env::var(...).is_ok()` returns true for
  an exported-but-empty value, so a stale shell rc / VS Code env
  injection blocked `auto_fallback_model` from switching when the
  user added a Gemini/Z.ai/etc. key. Both `kind_has_credentials`
  and `api_key_from_env` now require non-empty values; empty env
  falls through to the keychain. Includes a regression test
  `empty_env_var_treated_as_unset`.
- **`/exit` / `/quit` / `/q` slash commands** route through
  the backend `app_close` save path
  ([#16](https://github.com/thClaws/thClaws/pull/16)) instead of
  frontend-only `window.close()` after a 200 ms timeout.
- **Tool-bubble finalizer** searches backwards for the most recent
  unfinished tool bubble — handles text events arriving between
  `tool_use` and `tool_done`
  ([#16](https://github.com/thClaws/thClaws/pull/16)).
- **Frontend security hardening** from a same-day audit pass:
  10 MB cap on pasted/dropped images with inline error banner
  (was: silent drop, multi-MB paste froze the UI during base64
  encoding); 1 MB cap on terminal clipboard paste; explanatory
  threat-model comment on the `ReactMarkdown` call site;
  `ansiToHtml` documented invariant block.
- **Backend security hardening:** IPC `chat_user_message`
  attachment array bounded at `MAX_ATTACHMENTS_PER_MESSAGE = 10`
  + 67 MB total b64.

### Infrastructure

- **Branch protection ruleset on `main`** — block force-push +
  deletion (non-admin), require PR before merging, require status
  checks (cargo fmt + clippy + test (ubuntu-latest) + audit) to
  pass. Admin bypass for sync-from-private-workspace flow and
  emergency corrections.
- **Private Vulnerability Reporting (PVR)** enabled. SECURITY.md
  refreshed: PVR primary, email alternate, supported versions
  bumped 0.2.x → 0.3.x → 0.4.x.
- **CodeQL default setup** for JavaScript/TypeScript + Actions.
- **`cargo-audit` workflow** runs on PRs touching `Cargo.lock` +
  weekly cron.
- **Node 24 actions runtime opt-in** via
  `FORCE_JAVASCRIPT_ACTIONS_TO_NODE24=true` ahead of GitHub's
  2026-06-02 forced switch.
- **`ci.yml` permissions block** — `contents: read, actions: read`
  at top level (was inheriting GITHUB_TOKEN's default write
  scope; closes 4 CodeQL alerts).

### Acknowledged but deferred

- Copy-button-on-chat-bubble surface scope decision (toast / scope
  restriction / pattern-redaction) — captured in the audit reports
  under `dev-log/103-security-audit-frontend.md`.
- IPC message types still stringly-typed; discriminated-union
  refactor queued.
- Transitive `glib` 0.18.5 / gtk-rs 0.18.x unmaintained warnings
  remain pending the upstream `wry`/`webkit2gtk` GTK4 migration.
- CLI TUI picker for `/model` no-args
  ([#25](https://github.com/thClaws/thClaws/issues/25)) — GUI
  side ships in this release; CLI is future work.
- GitHub Copilot provider
  ([#24](https://github.com/thClaws/thClaws/issues/24)) — needs
  GitHub OAuth web flow; queued for a future minor.
- `output.log` should record tool-call argument detail
  ([#23](https://github.com/thClaws/thClaws/issues/23)).

## [0.3.5] — 2026-04-26

Same-day feature/fix follow-up to v0.3.4: two new providers, the
post-key-entry model picker, plus a real bug fix for users whose
shell rc / VS Code env injects a blank `ANTHROPIC_API_KEY`.

### Added

- **Z.ai (GLM Coding Plan) provider.** OpenAI-compatible upstream
  at `https://api.z.ai/api/coding/paas/v4`. Models route via
  `zai/<id>` prefix (default `zai/glm-4.6`). API key in
  `ZAI_API_KEY`. Power users on the BigModel SKU can override the
  endpoint via `ZAI_BASE_URL`. Closes [#14](https://github.com/thClaws/thClaws/issues/14).
- **LMStudio provider.** Local-runtime, OpenAI-compatible at `/v1`.
  No auth. User-configurable base URL via Settings (default
  `http://localhost:1234/v1`); env override `LMSTUDIO_BASE_URL`.
  Mirrors the Ollama UX so changing port doesn't require a
  settings.json edit.
- **Post-key-entry model picker** ([#13](https://github.com/thClaws/thClaws/issues/13)).
  After successfully saving an API key in Settings, if the
  provider has a non-trivial catalogue (≥3 models, skipping
  runtime-loaded backends like Ollama/LMStudio), a searchable
  modal opens so the user can pick a default model directly —
  instead of landing on whatever `auto_fallback_model` chose.
  Skip / Esc / click-outside leaves the auto-pick in place.
- **AskUserQuestion GUI bridge** ([#16](https://github.com/thClaws/thClaws/pull/16),
  Kinzen-dev). The agent's `AskUser` tool used to fall through to
  invisible CLI stdin in the GUI — chat hung indefinitely. The
  question now appears as a chat-composer reply prompt; user
  reply routes back through a `oneshot` to the awaiting tool call.
  Falls back to CLI readline when no GUI is registered.
- **macOS Cmd+Q / Cmd+W shutdown shortcuts** ([#16](https://github.com/thClaws/thClaws/pull/16)).
  Two-layer coverage (frontend keydown listener + tao native
  KeyboardInput) so Cmd+Q reaches the SaveAndQuit save path even
  in fullscreen / focus-edge cases.

### Fixed

- **Empty `ANTHROPIC_API_KEY=""` (or any provider key) was treated
  as configured.** `std::env::var(...).is_ok()` returns true for an
  exported-but-empty value, so a stale shell rc / VS Code env
  injection blocked `auto_fallback_model` from switching when the
  user added a Gemini/Z.ai/etc. key. Both `kind_has_credentials`
  and `api_key_from_env` now require non-empty values; empty env
  falls through to the keychain. Includes a regression test
  (`empty_env_var_treated_as_unset`).
- **`catalogue-seed` reads workspace-root `.env`.** When invoked
  via `cargo run --bin catalogue-seed` from a nested crate dir,
  the binary now walks up from cwd to find the workspace's `.env`
  and load API keys from it. Added
  `dotenv::load_dotenv_walking_up()`.
- **Tool-bubble finalizer searches backwards for unfinished tools**
  ([#16](https://github.com/thClaws/thClaws/pull/16)). Old code
  assumed `messages[last]` was the matching tool bubble; failed
  when text or other events arrived between `tool_use` and
  `tool_done`.
- **`/exit` / `/quit` / `/q` slash commands** now route through
  the backend `app_close` save path ([#16](https://github.com/thClaws/thClaws/pull/16))
  instead of frontend-only `window.close()` after a 200 ms timeout.

### Internal

- New `model_set` IPC handler — frontend-driven model change path,
  used by the new picker; mirrors what `/model` does in the agent
  loop. Available for any future picker UI.
- Dotenv `load_dotenv_walking_up(start)` helper exposed for
  operator-tool scenarios.

## [0.3.4] — 2026-04-26

Same-day hardening patch following an internal security audit of v0.3.3.
No new features; all changes are defensive limits and clearer errors on
the image-attachment and terminal-paste paths.

### Added

- **Inline error feedback on image attachment.** Pasting or dropping an
  unsupported image type or an image larger than 10 MB now shows a
  short auto-clearing banner ("Image too large: 17.3 MB (max 10 MB)")
  instead of silently dropping. Same path covers
  `image/svg+xml`/etc. → "Unsupported image type".

### Changed

- **Read tool errors cleanly on wrong-extension image files.** Files
  like `screenshot.png` containing non-PNG bytes used to slip through
  with a guessed MIME and get rejected by the provider with an opaque
  400. They now fail at Read with a pointed error message
  ("bytes don't match any supported image format despite extension
  claiming image/png — file may be corrupted, encrypted, or saved
  with the wrong extension"). Real images with these extensions are
  unaffected.

### Fixed (security hardening)

- **ChatView image paste/drop:** 10 MB per-attachment cap. Above the
  cap, the image is rejected with a visible error rather than ballooning
  the IPC payload and freezing the UI during base64 encoding.
- **TerminalView clipboard paste:** 1 MB cap. Multi-MB pastes used to
  freeze the main thread during synchronous `atob()` + `TextDecoder`;
  oversized pastes are now dropped with a console warning.
- **Backend IPC `chat_user_message` attachment array:**
  `MAX_ATTACHMENTS_PER_MESSAGE = 10` and a 67 MB combined-base64 cap.
  Defense-in-depth against a malicious or buggy frontend bypassing
  the per-image cap; worst-case payload now bounded at ~50 MB raw
  per message rather than unbounded.
- **`TeamView.tsx` `ansiToHtml`:** documented the escape-first
  invariant in a JSDoc block. The function's output is consumed via
  `dangerouslySetInnerHTML`; preserving HTML-escape-before-tag-build
  ordering is what keeps it safe. Block lists three changes to NOT
  make.
- **Markdown rendering threat-model comment** added at the
  `ReactMarkdown` call site documenting that `msg.content` is
  untrusted model output and the configured plugin chain
  (`remark-gfm`, `rehype-highlight`) is intentionally the safe stack
  — no `allowDangerousHtml`, no `rehype-raw`.

### CI / Infrastructure

- **Workflow least-privilege.** `ci.yml` now declares an explicit
  top-level `permissions: contents: read, actions: read`, instead of
  inheriting the GITHUB_TOKEN's default write scope. Closes 4
  CodeQL alerts (`actions/missing-workflow-permissions`).
- **CodeQL Rust scan** actually runs now: added `libdbus-1-dev` +
  `pkg-config` install before `cargo build`. The keychain crate's
  transitive `libdbus-sys` was failing pkg_config detection, breaking
  every prior CodeQL Rust run before extraction even started.
- **Node 24 actions runtime opt-in** via
  `FORCE_JAVASCRIPT_ACTIONS_TO_NODE24=true` on both `release.yml`
  and `ci.yml`. Surfaces any action-runtime breakage on our schedule
  rather than at GitHub's 2026-06-02 forced cutover.

### Known issues — acknowledged but deferred

- Copy-button surface on chat bubbles (system/tool/assistant) doesn't
  warn or filter when copying messages that may contain previously-
  pasted secrets. Needs a design choice (toast confirmation vs.
  scope restriction vs. pattern-based redaction); deferred to v0.3.5.
- IPC message types are still stringly-typed; discriminated-union
  refactor queued for a future maintenance pass.
- Transitive `glib` 0.18.5 / gtk-rs 0.18.x unmaintained warnings
  (12 RustSec entries) remain pending the upstream `wry`/`webkit2gtk`
  GTK4 migration.

## [0.3.3] — 2026-04-26

Feature release rolling up image attachment across providers, chat UI
polish, and a community-PR sweep that ran `pnpm lint` to clean. Plus
a transitive postcss XSS patch and a docs-prerequisite correction.

### Added

- **Image attachment across providers.** The Read tool now returns
  inline images for vision-capable models (PNG/JPG/GIF/WebP). Wire
  shaping is per-provider:
  - **Anthropic** — native via serde, zero provider code.
  - **OpenAI** — synthetic user message with `image_url` blocks
    referencing the originating `tool_call_id` (their tool-role
    messages can't carry images).
  - **Gemini** — `inlineData` parts as siblings to `functionResponse`
    in the same content.
  - **Ollama / OpenAI Responses** — text-only flatten on wire (no
    pixels to model).
- **ChatView attachments.** Paste and drag-drop image files into the
  chat composer; thumbnails preview before send.

### Changed

- **Chat rendering.** Assistant turns render as markdown
  (headings/lists/code/tables) instead of raw text. Tool output
  collapses to compact one-line indicators by default, with errors
  always shown in full.
- **Tool result handling on history restore.** `tool_result` blocks
  are dropped on session reload; `tool_use` rendering is unified
  across the streaming and reload paths.

### Fixed

- **postcss 8.5.9 → 8.5.10** ([GHSA-qx2v-qp2m-jg93](https://github.com/advisories/GHSA-qx2v-qp2m-jg93)).
  Transitive frontend dep; thClaws ships pre-compiled Tailwind so
  runtime exposure was minimal but Dependabot was flagging.
- **Documented Rust prerequisite: 1.78 → 1.85** in user-manual.
  The `home` crate v0.5.12 (transitive) needs edition 2024, so the
  effective MSRV moved to 1.85. README + CONTRIBUTING were already
  updated in [#3](https://github.com/thClaws/thClaws/pull/3); this
  catches the user-manual files that PR missed.
- **Read tool: image format sniffing from magic bytes** instead of
  trusting file extensions (which lie often enough — `.jpg` files
  that are actually PNGs, etc.).
- **OpenAI batched tool messages.** Emit batched tool messages
  back-to-back with a single combined image follow-up, instead of
  interleaving.
- **Sidebar.tsx unreachable branch.** Duplicate `sessions_list`
  `else if` removed (#4).
- **Frontend lint sweep** by [@parintorns](https://github.com/parintorns)
  in #4, #6, #7, #8, #9, #10 — `react-hooks/exhaustive-deps`,
  `react-refresh/only-export-components`, `no-empty`, type safety
  in IPC bridge and TeamView. `pnpm lint` is now clean.
- **`.gitignore`: `.thclaws/sessions/` → `.thclaws/`.** Was leaking
  `team/`, `settings.json`, and similar runtime files into
  `git status` (#6).

### Infrastructure

- **Workspace `Cargo.toml` at repo root** by
  [@bombman](https://github.com/bombman) (#2). `cargo build` now
  works from the repo root as the README documents; build output
  is at `target/release/` instead of `crates/core/target/release/`.

## [0.3.2] — 2026-04-25

Patch release fixing two GUI startup-recovery bugs surfaced in the
hours after v0.3.1 shipped. Both reach the user before they've typed
their first prompt, so this release is recommended for everyone on
v0.3.1 — particularly Linux users, who can't launch v0.3.1 at all.

### Fixed

- **Linux GUI startup panic.** v0.3.1 panicked at startup on every
  Linux build with `webview build: UnsupportedWindowHandle`
  (reported on Ubuntu 22.04). `wry` can't construct a WebKit2GTK
  webview from a raw window handle the way it does on macOS / Windows
  — WebKit2GTK is a GTK widget that has to be packed into a GTK
  container. Fixed by switching to `wry`'s Linux-only
  `build_gtk(window.default_vbox().unwrap())` behind
  `#[cfg(target_os = "linux")]`. The cross-platform path is preserved
  for macOS / Windows. (commits 6171815 by @Phruetthiphong + 729538b)
- **First-time API key setup required an app restart.** Pasting a
  provider key in Settings on a fresh install would update the sidebar
  to show the new provider, but the running agent kept holding the
  stale (or no-op) provider it was constructed with at startup —
  resulting in "sidebar shows openai but error mentions anthropic"
  on the first send. Two fixes:
  - The shared-session worker no longer exits on missing-key startup;
    it installs a `NoopProvider` placeholder and stays alive so a
    later config reload can swap in a real provider.
  - Added `ShellInput::ReloadConfig`. The `api_key_set` and
    `api_key_clear` IPC handlers now send it after their save, so the
    worker reloads `AppConfig`, rebuilds the agent's provider in
    place, and broadcasts the sidebar update — all without an app
    restart. (commit 27d163d)

## [0.3.1] — 2026-04-25

Re-release of v0.3.0 — the v0.3.0 tag's release workflow failed
(missing `banner.txt` broke the frontend build). Tag re-cut against
the fix.

### Fixed (v0.3.1 vs v0.3.0)

- **`banner.txt` now ships in the repo** so `vite build` resolves
  `import bannerText from "../../../banner.txt?raw"` in
  `TerminalView.tsx`. v0.3.0 release job failed at this step on every
  platform.
- **`cargo fmt` drift** in `crates/core` cleaned up so the CI fmt
  check passes.
- **`actions/checkout`, `actions/setup-node`, `actions/upload-artifact`,
  `actions/download-artifact` bumped to v5** for Node 24 support
  (v4 is now deprecated on GitHub-hosted runners).

### Providers (since v0.2.2)

- Reasoning-model support end-to-end: DeepSeek v4-flash/pro, DeepSeek r1,
  OpenAI o-series via OpenRouter. `reasoning_content` is captured into a
  Thinking content block and echoed back on subsequent turns (these
  providers 400 without it). Conservative allowlist — non-thinking models
  pay zero extra tokens.
- Provider-aware alias resolution: agent-def `model: sonnet` stays in
  the project's current provider namespace instead of surprise-switching
  to native Anthropic.
- Model catalogue v3 (provider-keyed maps, real ids, per-row provenance).
  `/models` reads from catalogue; `/model` auto-scans Ollama context
  window.

### Agent Teams (since v0.2.2)

- Sandbox boundary anchors to `$THCLAWS_PROJECT_ROOT` (not cwd); worktree
  teammates can write shared artifacts at workspace root; `Write` into
  deep new trees walks up to the longest existing ancestor.
- "Project settings win" on cwd change: GUI reloads `ProjectConfig` and
  rebuilds the agent; worktree teammates pick up the workspace's
  `settings.json` (was silently falling back to user config).
- Role guards on `Bash` / `Write` / `Edit`:
  - Lead can't run `rm -rf`, `git reset --hard`, `git worktree remove`,
    `git push --force`, `git checkout -- …`, or `Write` / `Edit` source
    files. One narrow exception: when a merge is in progress and the
    target file has `<<<<<<<` markers, lead may write the resolved
    content (so package.json-style conflicts can be handled without
    delegating).
  - Teammates can't `git reset --hard <other-branch>`. Same-branch
    recovery (`HEAD~N`, sha, tags) stays allowed.
- `EDITOR` / `GIT_EDITOR` / `VISUAL` / `GIT_SEQUENCE_EDITOR` stubbed to
  `true` for teammates so `vi` / `git commit -e` don't hang waiting for
  input via `/dev/tty`.
- "Plan Approval" convention documented in default `lead.md` /
  `agent_team.md` prompts (lead↔teammate handshake, NOT a user gate).
- `TeamTaskCreate` gains an `owner` field; `claim_next` is role-aware.

### GUI (since v0.2.2)

- Terminal tab: Up/Down arrow prompt history.
- Files tab: WYSIWYG round-trip for `.md` preview + editor; HTML preview
  base-URL fix; off-screen edit-button positioning fix.
- Approval modal; MCP spawn through approval sink; `ReadyGate` for
  deferred startup so the worker accepts prompts before MCP-spawn
  approval returns.
- Context warning banner + per-file size breakdown of the system prompt.
- Settings menu polish: accent-tinted hover + focus highlight; modal
  backdrop dismiss on mousedown-origin (fewer accidental closes).
- Windows GUI fixes backported from upstream: `rfd` file picker,
  `native_dialog` confirm, `ospath()` path-separator helper.

### KMS

- `/kms ingest` slash command; sidebar refreshes live on KMS changes.

### Catalogue tooling

- New `make catalogue` target wraps `catalogue-seed` with a diff-stat
  preview and a per-provider transparency report (new IDs added +
  unchanged + skipped-no-context counts).

### User manual — NEW in this release

- 17-chapter reference manual in English (`user-manual/`) and Thai
  (`user-manual-th/`) with shared images at `user-manual-img/`. Covers
  installation through agent teams. Case-study chapters (18–24) for
  building/deploying real projects remain in workspace draft and will
  graduate to the published manual as each is reviewed.

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
