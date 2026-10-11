# AgentLens — Collector Specifications

Collectors are read-only filesystem readers. Shared contract, then one section per platform, then the risk heuristics. For the reader-facing inventory of what is read, stated or out of reach, see [what-agentlens-sees.md](what-agentlens-sees.md).

## 1. Shared collector contract

1. **SR1 — read-only.** Open with read-only intent; never create, write, or touch anything outside the snapshot output directory (`data/snapshots/`). No child processes that could mutate state; version detection via `--version` subprocess is the only allowed exec, and it must be the platform binary with that single flag. Never *execute* an MCP server to enumerate tools.
2. **SR2 — redact before persist.** Collected strings pass through the redactor (`lib/redact.ts`) before entering the snapshot object: rule matchers, MCP commands/args/URLs, hook command bodies, sandbox allowlists. Env **values** are dropped unconditionally (key names survive). *Both Step 2 gaps (parse-error messages echoing config content; scalar fields bypassing redaction) are closed and regression-tested in `tests/sr2-redaction.test.ts`.* Secret-shaped substrings anywhere else (commands, args, URLs, hook bodies) are replaced with `[REDACTED]`. Patterns include: `sk-…`, `ghp_`/`gho_`/`github_pat_`, `AKIA…`, `xoxb-`/`xoxp-`, `Bearer <token>`, `key=`/`token=`/`secret=`/`password=` value captures, JWT triplets, and ≥32-char high-entropy base64/hex runs. False positives are acceptable; false negatives are the failure mode.
3. **Allowlisted paths only.** Each collector declares the exact glob set below; nothing else is read. Project scanning is limited to roots passed explicitly (`npm run collect -- <root>...`) or, when none are passed, to **cwd plus the keys of the `projects` map in `~/.claude.json`** — the directories Claude Code has been launched from, which the Claude Code collector already reads. Discovery uses read-only existence checks, skips symlinked entries, and never treats `$HOME` or the filesystem root as a project (doing so would misfile user-tier settings as project-tier declarations). Explicit roots disable discovery — that is the opt-out. Walks are max depth 4, skipping `node_modules`, `.git`, and symlinks (path-traversal guard, threat T4).
4. **Malformed input is data.** Config files are untrusted content. Parse failures produce an `info` finding, never a crash; parsed strings are stored verbatim (post-redaction) and only ever rendered escaped.
5. **Absence is not knowledge.** If a platform's binary/config isn't found, the collector reports nothing and the snapshot's `collectors` list still names it as *ran* — the UI distinguishes "ran, found nothing" from "didn't run".

## 2. Claude Code collector (`claude-code`) — implemented in v1

### Files read (settings tiers)

| Level | Path | Notes |
|---|---|---|
| `managed` | `/etc/claude-code/managed-settings.json` (Linux), `/Library/Application Support/ClaudeCode/managed-settings.json` (macOS) | Admin-enforced; cannot be overridden |
| `local` | `<projectRoot>/.claude/settings.local.json` | Per-checkout, usually gitignored |
| `project` | `<projectRoot>/.claude/settings.json` | Checked in — team-visible |
| `user` | `~/.claude/settings.json` | |

`<projectRoot>` is the **git repository root**, resolved by walking up from each scanned directory to the nearest `.git` entry (directory, or file for worktrees; symlinked `.git` is not trusted — T4). Scanning a nested package directory therefore still applies the repo root's settings, matching vendor behavior. No `.git` found → the scanned directory itself. Multiple scanned roots resolving to the same repository dedupe to one project instance.

**Rule evaluation semantics (per first-party docs, verified 2026-08-13; engine reimplemented in hardening Step 5):** permission rule lists are *merged across all settings files* and evaluated globally as `deny → ask → allow` — "the first match in that order determines the outcome, and rule specificity doesn't change the order." A deny in any tier wins over an allow in any other tier. The stored `precedenceRank` encodes exactly this: effect-first (deny < ask < allow), with tier only breaking ties within an effect; the UI's evaluation-order view sorts by it. Tier precedence applies to **single-value settings** (`defaultMode`, sandbox fields): managed > command line > local project > shared project > user, merged **per-field** — each field is taken from the highest-precedence file that defines it, with the contributing file recorded (`defaultModeSourceFile`, `sandbox.fieldSources`). Conformance fixtures for both semantics live in `tests/vendor-conformance.test.ts`.

**Trust state and legacy grants (collected as instance notes since 2026-10-11):** each project instance states the folder-trust dialog outcome recorded in its `~/.claude.json` project entry (`hasTrustDialogAccepted` true / false / no decision) and, when present, the legacy per-project `allowedTools` list (count + redacted preview) — surfaced for review, **not** merged into declarations, because current versions do not honour it. The entries' usage/cost telemetry keys are never read.

**Known uncollected inputs (SR4 — declared, not silently missing):** session-scoped grants recorded outside settings files (if any) and command-line flag overrides (`flag` tier), which are invisible to a filesystem collector by nature.

### Extracted per file

- `permissions.deny` / `permissions.ask` / `permissions.allow` → `PermissionRule[]` (matcher verbatim; `tool` parsed from the `Tool(specifier)` shape).
- `permissions.defaultMode` (+ its contributing file) → `defaultMode`, with a **mode-semantics note** quoting the vendor's description of that mode (default/acceptEdits/plan/auto/dontAsk/bypassPermissions; verified 2026-10-11). Vendor caveat applied: `"auto"` set in `.claude/settings.json` or `.claude/settings.local.json` does not take effect — noted, and not counted by H8.
- `permissions.additionalDirectories` → `additionalDirectories[]` with per-entry provenance (file access outside the project without prompts; S5 treats an entry over home/config paths as a read atom).
- **Controls** (`controls[]`, highest-precedence file wins, shown as a table): `skipDangerousModePermissionPrompt`, `permissions.disableBypassPermissionsMode`, `permissions.disableAutoMode`, `permissions.blockReadsOutsideWorkingDirectories`, `enableAllProjectMcpServers`, `disableAllHooks`, `allowManagedPermissionRulesOnly`, `allowManagedHooksOnly`, `useAutoModeDuringPlan`, `skipAutoPermissionPrompt`, `autoMode.classifyAllShell`, `sandbox.failIfUnavailable`. Notes state `autoMode` key names (contents not collected), `env` variable **names**, `deniedMcpServers` / `allowedMcpServers` counts, `disableAllHooks` (hooks declared but off) and a bypass default made inert by `disableBypassPermissionsMode`.
- `sandbox.*` → `SandboxConfig` (`enabled`, `allowUnsandboxedCommands` (boolean; a string value is kept in the notes), `autoAllowBashIfSandboxed` (vendor default true: sandboxed commands run without prompts), `excludedCommands` (run outside the sandbox — H6 low), network allowlist; filesystem/network extra rules are counted in the notes — per-field tier merge with per-field provenance). Vendor facts recorded in the notes: the sandbox covers shell commands only (file tools, MCP servers and hooks run outside it); egress filtering is hostname-only.
- `hooks` → `Hook[]` (event, matcher, redacted+truncated command).
- MCP servers from: `<projectRoot>/.mcp.json`, `~/.claude.json` `mcpServers` (user instance) and per-project `projects[<path>].mcpServers` entries (project instance). **Approval (`enablement`) sources, per vendor docs verified 2026-10-11:** the prompt choice recorded in the `~/.claude.json` project entry (`enabledMcpjsonServers` / `disabledMcpjsonServers`), plus the same keys and `enableAllProjectMcpServers` in **any settings file** — except that approvals committed to the project's own `.claude/settings.json` / `settings.local.json` count only once the folder is trusted (`hasTrustDialogAccepted: true`); until then they are stated in a note and ignored, exactly as the vendor does. Rejections always count; `deniedMcpServers` entries matching a server's name, URL or command mark it `disabled` on every instance. Disabled wins on conflict; null = no recorded choice — **not** a claim the server is active (SR4).

### Instance construction

- One `user`-scope instance from user+managed files.
- One `project`-scope instance per resolved project root (git root of a scanned directory) containing `.claude/`, `.mcp.json`, or a matching `~/.claude.json` project entry, merging managed+user+project+local (a project instance shows the *full* effective set, not just project-file rules).

## 3. Codex CLI collector (`codex-cli`) — implemented 2026-10-11

Vendor docs verified 2026-10-11 (Codex configuration reference and sample `config.toml`). TOML is parsed with `smol-toml` 1.9.1 (exact pin; zero dependencies, no install scripts — T10 review in [security-architecture.md](security-architecture.md) §4); malformed files yield the fixed code `ERR_TOML_SYNTAX`, never parser text (SR2).

### Files read

| Level | Path | Notes |
|---|---|---|
| `user` | `$CODEX_HOME/config.toml` (default `~/.codex/config.toml`) | |
| `project` | `<scanned dir>/.codex/config.toml` | Loaded by the vendor **only** when the user config records `[projects."<dir>"] trust_level = "trusted"`; AgentLens merges it only in that case and otherwise lists it as declared-but-inactive |

Not read (declared as notes): profile files `$CODEX_HOME/<name>.config.toml` (apply only via `--profile`, flag tier — the count is stated), `requirements.toml` / cloud-managed policies (constrain from above), execution-policy rules.

### Mapping

| Codex setting | AgentLens field | Semantics |
|---|---|---|
| `approval_policy` (`on-request` \| `never` \| granular table; `on-failure` deprecated, `untrusted` unsupported) | `defaultMode` | `never` + `sandbox_mode = "danger-full-access"` → `defaultMode = "bypass (…)"` → **H1** (the vendor's `--dangerously-bypass-approvals-and-sandbox` combination). `never` alone → note "the sandbox is the only remaining gate" |
| `sandbox_mode` (`read-only` \| `workspace-write` \| `danger-full-access`), `[sandbox_workspace_write] network_access / writable_roots` | `SandboxConfig` (`enabled = mode !== danger-full-access`, per-field provenance) | `danger-full-access` → **H6**; network access and writable roots in `notes` |
| `[mcp_servers.<name>]` stdio (`command`, `args`, `env`) / HTTP (`url`, `bearer_token_env_var`, `http_headers`, `env_http_headers`) | `McpServer[]` | Env **key names** plus the bearer-token env var name and `env_http_headers` env var names (all names, never values — SR2); `http_headers` values are never read |
| `enabled = false/true` | `McpServer.enablement` | absent → `null` (no recorded choice) |
| `default_tools_approval_mode`, `enabled_tools` / `disabled_tools` | note | Per-server approval default and server-side tool filters, stated verbatim |
| `shell_environment_policy.inherit` / `set` | note | Env exposure to shell commands; `set` key names only |
| `web_search` | note | Stated when not `disabled` |
| `[projects."<dir>"] trust_level` | note on project instances + merge gating | `trusted` → project file merged; `untrusted` / no record → not merged, stated |

**No per-tool allow/ask/deny list exists in `config.toml`**, so `permissionRules` is empty for Codex instances and the first note on every instance says so (SR4). Conformance fixtures: `tests/codex-collector.test.ts` on the shared fixture machine (SR1/SR2 coverage extends to these files).

## 4. Gemini CLI collector (`gemini-cli`) — implemented 2026-10-09

Vendor docs verified 2026-10-09 (`docs/reference/configuration.md`, `docs/cli/settings.md`, `docs/cli/trusted-folders.md`, `docs/cli/sandbox.md`, `docs/reference/policy-engine.md` in the `google-gemini/gemini-cli` repo).

### Files read (settings tiers, highest precedence first)

| Level | Path | Notes |
|---|---|---|
| `managed` | `/etc/gemini-cli/settings.json` (Linux), `/Library/Application Support/GeminiCli/settings.json` (macOS) | Vendor "system settings" — overrides project and user |
| `project` | `<scanned dir>/.gemini/settings.json` | Gemini's workspace is the launch directory; no git-root walk-up is documented, so none is done |
| `user` | `~/.gemini/settings.json` | |

Also read: `~/.gemini/trustedFolders.json` — the recorded rule for a project folder (or the nearest ancestor rule, flagged as such because inheritance semantics are not re-implemented) is surfaced verbatim as a note on the project instance (2026-10-11). Not read: the system-defaults file (`/etc/gemini-cli/system-defaults.json`, lowest precedence, admin-provided) and TOML policy files (`~/.gemini/policies/*.toml`, `/etc/gemini-cli/policies`; the TOML parser now exists, the policy-engine semantics are the remaining work). Each is declared on the instance as a mapping note (SR4), not silently missing.

### Mapping (nested v2 keys; legacy flat keys read as fallback when the nested key is absent)

| Gemini setting | AgentLens field | Semantics |
|---|---|---|
| `tools.allowed` (legacy `allowedTools`) | `allow` rule | Vendor: "tool names that bypass the confirmation dialog". A bare `run_shell_command` is unbounded shell (H2); `run_shell_command(git)` is a prefix-scoped allow |
| `tools.exclude` (legacy `excludeTools`) | `deny` rule | Tool removed from discovery |
| `tools.core` (legacy `coreTools`) | note only | Availability allowlist — **not** an approval grant; listed tools still prompt unless also in `tools.allowed` |
| `general.defaultApprovalMode` | `defaultMode` | `default` \| `auto_edit` \| `plan`. **YOLO exists only as a CLI flag/env** (`flag` tier) and is invisible to a filesystem collector — stated in the notes |
| `tools.sandbox` (legacy `sandbox`), `tools.sandboxNetworkAccess` | `SandboxConfig.enabled` + notes, per-field provenance | Boolean, profile string or command; H6 fires only on an explicit `false` |
| `mcpServers` (top level; `url` = SSE, `httpUrl` = streamable HTTP) | `McpServer[]` | Env **key names only** (SR2); `headers` values never read |
| `mcp.allowed` / `mcp.excluded` (legacy `allowMCPServers` / `excludeMCPServers`) | `McpServer.enablement` | excluded → `disabled`; when an allow-list exists, listed → `enabled`, unlisted → `disabled`; otherwise `null` (no recorded choice) |
| per-server `trust: true` | note | Vendor: confirmations bypassed for that server's tools |
| `hooks` | `Hook[]` | Same `{ <Event>: [ { matcher, hooks: [ { command } ] } ] }` shape as Claude Code; `hooksConfig.enabled: false` noted |
| `security.folderTrust.enabled` (default true) | note on project instances | When enabled, project settings and MCP servers load only if the folder is trusted — project-tier rows are **conditional** and the UI says so |

**Precedence (SR4):** Gemini documents tier precedence for single values (system > project > user) but no cross-tier allow/deny evaluation order over these lists. `precedenceRank` is therefore effect-first (deny before allow) for *display grouping* only, and the instance page says so instead of claiming vendor semantics. Conformance fixtures: `tests/gemini-collector.test.ts` on the shared fixture machine (which also extends SR1/SR2 coverage to these files).

## 5. Generic MCP collector (`generic-mcp`) — implemented in v1

- Files: any file named exactly `mcp.json` in scanned roots (covers `.vscode/mcp.json`, `.cursor/mcp.json`). `.mcp.json` is claimed by the claude-code collector; broader `*.mcp.json` patterns are spec'd but not yet implemented.
- Produces a `generic-mcp` instance per file with `McpServer` rows only.

## 6. Risk heuristics (v1)

| Id | Severity | Trigger | Rationale |
|---|---|---|---|
| H1 | critical | Bypass modes: `defaultMode: "bypassPermissions"`, Codex `danger-full-access`, Gemini YOLO/auto-accept | All gating off |
| H2 | high | Wildcard allow: matcher `*`, bare tool with `:*`/`(*)` on Bash/Write/Edit-class tools | Unbounded tool surface |
| H3 | high (unpinned) / medium (pinned) | stdio MCP server launched via `npx -y` / `uvx` / `pipx run`. Unpinned specs execute latest upstream on every start; a version-pinned spec is a lower-severity "remote launcher" variant (still fetched from the registry at startup) | Supply-chain exposure; landscape notes stdio is outside the MCP auth spec entirely |
| H4 | high | MCP `env` contains secret-suggestive key names (`*_TOKEN`, `*_KEY`, `*_SECRET`, `*_PASSWORD`) | Long-lived creds in agent-readable config (values already redacted by SR2; finding cites key names) |
| ~~H5~~ | — | **Retired 2026-08-13.** Flagged "deny shadowed by broader allow" — the opposite of documented behavior (deny wins globally). Kept in the schema enum for old snapshots only | See `local/mvp-review-accuracy-analysis.md` F1 |
| H6 | medium | Sandbox disabled or `allowUnsandboxedCommands: true` where the platform offers sandboxing | Filesystem/network confinement off |
| H7 | low | Hook command pipes remote content to a shell (`curl … \| sh` shape) | Hook = arbitrary code in the agent loop. *(Spec trimmed in Step 5: the earlier outside-path clause is dropped rather than promised-but-unimplemented; a hook-command path heuristic can return as a new rule if warranted)* |
| H8 | low | Reduced-oversight mode: Claude Code `auto` (a classifier reviews actions instead of you — the vendor's built-in default for interactive sessions since v2.1.283) or `acceptEdits`; Gemini `auto_edit`; Codex `approval_policy = "never"` without `danger-full-access`. Reported once, on the instance whose own tier set it; Claude Code's `auto` in project files is inert (vendor) and not reported | Prompts are the user's last manual gate; a mode that removes them deserves a line, with the vendor's own wording as evidence — low because it is the documented default |
| H9 | low | `skipDangerousModePermissionPrompt: true` | Removes the confirmation shown before entering `bypassPermissions` |
| H6 (variant) | low | Sandbox on but `sandbox.excludedCommands` lists patterns that run outside it | Declared holes in a boundary the user believes is closed |

Each heuristic yields a `RiskFinding` with post-redaction evidence. Heuristics are pure functions over the normalized snapshot — they never re-read disk — so they are testable against fixtures.
