# What AgentLens can and cannot see

AgentLens reads **configuration files** and shows what they declare. It never observes enforcement, never runs an agent or an MCP server, and never reads conversation history. This page is the complete list of inputs per platform — what is read, what is only *stated* as a note, and what is out of reach — so "no findings" can be interpreted correctly (SR4). Vendor references were verified on the dates given; when a vendor changes semantics, this page and `docs/collectors.md` are updated together.

## Claude Code (verified 2026-10-11)

**Read**

| File | Tier | What is taken from it |
|---|---|---|
| `/etc/claude-code/managed-settings.json`, `/Library/Application Support/ClaudeCode/managed-settings.json` | managed | same keys as below |
| `~/.claude/settings.json` | user | `permissions.allow/ask/deny` (rules, provenance, deny → ask → allow rank), `permissions.defaultMode`, `permissions.additionalDirectories`, `sandbox.*` (enabled, allowUnsandboxedCommands, autoAllowBashIfSandboxed, excludedCommands, network allowlist; filesystem/network extras counted), `hooks` (event, matcher, redacted command preview), the controls listed below, `enabledMcpjsonServers` / `disabledMcpjsonServers` / `enableAllProjectMcpServers` / `deniedMcpServers` / `allowedMcpServers` (approvals), `autoMode` (key names only), `env` (variable names only) |
| `<git root>/.claude/settings.json`, `<git root>/.claude/settings.local.json` | project, local | same keys; project-tier MCP approvals count only once the folder is trusted (vendor) |
| `<git root>/.mcp.json` | project | MCP servers: transport, command/URL, args, env **key names** |
| `~/.claude.json` | — | user-level `mcpServers`; per-project entries: `mcpServers`, `enabledMcpjsonServers`, `disabledMcpjsonServers`, `hasTrustDialogAccepted`, legacy `allowedTools`; the `projects` keys as default scan roots |

Controls shown as a table: `skipDangerousModePermissionPrompt`, `permissions.disableBypassPermissionsMode`, `permissions.disableAutoMode`, `permissions.blockReadsOutsideWorkingDirectories`, `enableAllProjectMcpServers`, `disableAllHooks`, `allowManagedPermissionRulesOnly`, `allowManagedHooksOnly`, `useAutoModeDuringPlan`, `skipAutoPermissionPrompt`, `autoMode.classifyAllShell`, `sandbox.failIfUnavailable`.

**Stated as notes, not interpreted:** the vendor's description of the effective mode (including that `auto` is the built-in default since v2.1.283 and that `auto` set in project files does not take effect); `autoMode` rule contents; `env` values; `allowedMcpServers` (not applied to enablement); `deniedMcpServers` URL/command patterns beyond exact matches; legacy per-project `allowedTools` (not merged into declarations); folder-trust state.

**Session transcripts (`~/.claude/projects/**`): not read, unless you run `agentlens trace import <file>` on a transcript you name.** Even then AgentLens keeps only the tool-call structure — tool names, file paths, redacted and truncated command strings, hosts, MCP server and tool names, skill names — never prompts, responses, file contents or tool outputs. A hook-based trace exists only for sessions you start with the AgentLens hook settings ([session-trace.md](session-trace.md)).

**Not read:** `history.jsonl`, todos, credentials, plugin and skill contents (skill **directory names** and `enabledPlugins` keys are read), hook script files (only the command string from settings), `~/.claude.json` usage/cost keys, any file outside the list above.

**Invisible by nature:** command-line flags (`--permission-mode`, `--dangerously-skip-permissions`, `--add-dir`, `--settings`), environment variables set in the shell, server-side availability of auto mode, the classifier's decisions, "don't ask again" grants held only in memory, and what the platform's evaluator actually does at run time — the only ground truth.

## Gemini CLI (verified 2026-10-09)

**Read:** `/etc/gemini-cli/settings.json` or the macOS equivalent (managed), `~/.gemini/settings.json` (user), `<dir>/.gemini/settings.json` (project): `tools.allowed` → allow, `tools.exclude` → deny, `general.defaultApprovalMode`, `tools.sandbox` / `tools.sandboxNetworkAccess`, `mcpServers` (`url` = SSE, `httpUrl` = HTTP; env key names), `mcp.allowed` / `mcp.excluded` → enablement, `hooks`, `security.folderTrust.enabled`; `~/.gemini/trustedFolders.json` (the rule for the folder, or the nearest ancestor rule, verbatim).

**Stated as notes:** `tools.core` (an availability allowlist, not an approval grant), per-server `trust: true`, legacy flat keys, `hooksConfig.enabled: false`, that no cross-tier allow/deny evaluation order is documented.

**Not read:** the system-defaults file, TOML policy files (`~/.gemini/policies`, `/etc/gemini-cli/policies`), extensions. **Invisible:** the YOLO flag and other CLI/env overrides.

## Codex CLI (verified 2026-10-11)

**Read:** `$CODEX_HOME/config.toml` (default `~/.codex/config.toml`) and `<dir>/.codex/config.toml` — merged only when the user config records `[projects."<dir>"] trust_level = "trusted"`: `approval_policy`, `sandbox_mode`, `[sandbox_workspace_write]`, `[mcp_servers.*]` (command/args/env key names, `url`, `bearer_token_env_var` and `env_http_headers` *names*, `enabled`), `shell_environment_policy`, `web_search`, `[projects.*] trust_level`.

**Stated as notes:** that Codex has no per-tool allow/ask/deny list (so instances carry no rules), per-server `default_tools_approval_mode` and tool filters, profile file count, untrusted project config (declared but inactive).

**Not read:** profile files (apply only via `--profile`), `requirements.toml` / cloud-managed policies, execution-policy rules, `http_headers` values. **Invisible:** CLI flags, env.

## Generic `mcp.json` manifests

**Read:** any `mcp.json` under a scanned root (depth ≤ 4; e.g. `.cursor/mcp.json`, `.vscode/mcp.json`): servers with transport, command/URL, args, env key names. No permission rules exist in these manifests, so no scenario needs a shell atom from them.

## What is never done, anywhere

- No MCP server is executed to enumerate tools; `declaredTools` is null unless a file declares them.
- No secret value is persisted: env values are dropped; everything else passes the redactor before it is written; parse failures are fixed codes, never parser text.
- No write to any agent configuration; the only writes are AgentLens's own snapshots (and, in watch mode with `--keep`, deleting its own oldest snapshots).
- No network: no analytics, no update checks, no remote assets; the dashboard serves loopback `Host` values only.
- No claim of enforcement: every rule, mode and scenario is a configured declaration. Absence of a finding is absence of a *declared* risk in the files above — nothing more.

## Session traces (what a traced session reveals, and to whom)

A session you start with the AgentLens hook settings (`npm run qa -- claude <recipe>`, or `claude --settings "$(agentlens hook-settings)"`) sends one event per tool call to the loopback receiver, projected and redacted **inside the session process** by `bin/agentlens-hook.mjs`: file paths written (contents never), redacted command strings (output never), `scheme://host/path` of fetched URLs (query strings never), MCP server and tool names (arguments never), skill names, subagent types, session start/end with cwd and mode, configuration-change notices. File reads are included only with `--reads`, reduced to directories. On session end, if the working directory lies under a project AgentLens has already scanned, a size+mtime diff of that directory is recorded (paths only). Traces live in `data/observed/trace-*.ndjson` (gitignored, 7 days, 10 MiB/day) and are shown on `/sessions`; `agentlens trace print` exports one as text — that export carries paths and commands and is not meant to leave the machine. The hook prints nothing, exits 0, writes no files and takes only a port; it can never block or alter a session.

Related: [collectors.md](collectors.md) (exact mapping per key), [security-architecture.md](security-architecture.md) (SR1–SR5 and their tests), [threat-scenarios.md](threat-scenarios.md) (how declarations are composed).
