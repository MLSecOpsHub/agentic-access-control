# AgentLens — Collector Specifications

Collectors are read-only filesystem readers. Shared contract, then one section per platform, then the risk heuristics.

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

**Known uncollected inputs (SR4 — declared, not silently missing):** folder/workspace trust state (`hasTrustDialogAccepted` in `~/.claude.json` project entries) and session-scoped "always allow" grants are not collected yet (roadmap Phase 1.5); `~/.claude.json` is read for MCP data and project-root discovery only — its legacy per-project `allowedTools` lists are not read; command-line flag overrides (`flag` tier) are invisible to a filesystem collector by nature.

### Extracted per file

- `permissions.deny` / `permissions.ask` / `permissions.allow` → `PermissionRule[]` (matcher verbatim; `tool` parsed from the `Tool(specifier)` shape).
- `permissions.defaultMode` (+ its contributing file), `permissions.additionalDirectories`.
- `sandbox.*` → `SandboxConfig` (`enabled`, `allowUnsandboxedCommands`, network allowlist — per-field tier merge with per-field provenance; note recorded that egress filtering is hostname-only per vendor docs).
- `hooks` → `Hook[]` (event, matcher, redacted+truncated command).
- MCP servers from: `<projectRoot>/.mcp.json`, `~/.claude.json` `mcpServers` (user instance) and per-project `projects[<path>].mcpServers` entries (project instance). The project entry's `enabledMcpjsonServers`/`disabledMcpjsonServers` lists set each `.mcp.json` server's `enablement` (`enabled`/`disabled`; disabled wins on conflict; null = no recorded choice — **not** a claim the server is active, SR4).

### Instance construction

- One `user`-scope instance from user+managed files.
- One `project`-scope instance per resolved project root (git root of a scanned directory) containing `.claude/`, `.mcp.json`, or a matching `~/.claude.json` project entry, merging managed+user+project+local (a project instance shows the *full* effective set, not just project-file rules).

## 3. Codex CLI collector (`codex-cli`) — spec'd, stubbed (not yet read)

- Files: `~/.codex/config.toml`; project `requirements.toml` where present.
- Extract: approval policy (map `untrusted`→`ask`-dominant, `on-failure`/`never` noted on the instance), sandbox mode (`read-only`, `workspace-write`, `danger-full-access` → SandboxConfig + H1 when `danger-full-access`), network access flag and domain allowlist, MCP servers from `mcp_servers` tables.
- Mapping loss: Codex has no per-rule allow/deny list; we synthesize at most coarse rules from sandbox mode and record the native construct in `notes`.

## 4. Gemini CLI collector (`gemini-cli`) — implemented 2026-10-09

Vendor docs verified 2026-10-09 (`docs/reference/configuration.md`, `docs/cli/settings.md`, `docs/cli/trusted-folders.md`, `docs/cli/sandbox.md`, `docs/reference/policy-engine.md` in the `google-gemini/gemini-cli` repo).

### Files read (settings tiers, highest precedence first)

| Level | Path | Notes |
|---|---|---|
| `managed` | `/etc/gemini-cli/settings.json` (Linux), `/Library/Application Support/GeminiCli/settings.json` (macOS) | Vendor "system settings" — overrides project and user |
| `project` | `<scanned dir>/.gemini/settings.json` | Gemini's workspace is the launch directory; no git-root walk-up is documented, so none is done |
| `user` | `~/.gemini/settings.json` | |

Not read: the system-defaults file (`/etc/gemini-cli/system-defaults.json`, lowest precedence, admin-provided); `~/.gemini/trustedFolders.json`; TOML policy files (`~/.gemini/policies/*.toml`, `/etc/gemini-cli/policies`) — a TOML parser is a new dependency and goes through T10 first. Each is declared on the instance as a mapping note (SR4), not silently missing.

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

Each heuristic yields a `RiskFinding` with post-redaction evidence. Heuristics are pure functions over the normalized snapshot — they never re-read disk — so they are testable against fixtures.
