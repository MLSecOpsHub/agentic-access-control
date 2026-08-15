# AgentLens — Collector Specifications

Collectors are read-only filesystem readers. Shared contract, then one section per platform, then the risk heuristics.

## 1. Shared collector contract

1. **SR1 — read-only.** Open with read-only intent; never create, write, or touch anything outside the snapshot output directory (`data/snapshots/`). No child processes that could mutate state; version detection via `--version` subprocess is the only allowed exec, and it must be the platform binary with that single flag. Never *execute* an MCP server to enumerate tools.
2. **SR2 — redact before persist.** Collected strings pass through the redactor (`lib/redact.ts`) before entering the snapshot object: rule matchers, MCP commands/args/URLs, hook command bodies, sandbox allowlists. Env **values** are dropped unconditionally (key names survive). *Both Step 2 gaps (parse-error messages echoing config content; scalar fields bypassing redaction) are closed and regression-tested in `tests/sr2-redaction.test.ts`.* Secret-shaped substrings anywhere else (commands, args, URLs, hook bodies) are replaced with `[REDACTED]`. Patterns include: `sk-…`, `ghp_`/`gho_`/`github_pat_`, `AKIA…`, `xoxb-`/`xoxp-`, `Bearer <token>`, `key=`/`token=`/`secret=`/`password=` value captures, JWT triplets, and ≥32-char high-entropy base64/hex runs. False positives are acceptable; false negatives are the failure mode.
3. **Allowlisted paths only.** Each collector declares the exact glob set below; nothing else is read. Project scanning is limited to roots passed explicitly (`npm run collect -- <root>...`, default: cwd), max depth 4, skipping `node_modules`, `.git`, and symlinks (path-traversal guard, threat T4).
4. **Malformed input is data.** Config files are untrusted content. Parse failures produce an `info` finding, never a crash; parsed strings are stored verbatim (post-redaction) and only ever rendered escaped.
5. **Absence is not knowledge.** If a platform's binary/config isn't found, the collector reports nothing and the snapshot's `collectors` list still names it as *ran* — the UI distinguishes "ran, found nothing" from "didn't run".

## 2. Claude Code collector (`claude-code`) — implemented in v1

### Files read (settings tiers)

| Level | Path | Notes |
|---|---|---|
| `managed` | `/etc/claude-code/managed-settings.json` (Linux), `/Library/Application Support/ClaudeCode/managed-settings.json` (macOS) | Admin-enforced; cannot be overridden |
| `local` | `<project>/.claude/settings.local.json` | Per-checkout, usually gitignored. ⚠️ Vendor docs load this from the **git repository root**; the collector currently reads it from each scanned root (gap, roadmap Step 5) |
| `project` | `<project>/.claude/settings.json` | Checked in — team-visible |
| `user` | `~/.claude/settings.json` | |

**Rule evaluation semantics (per first-party docs, verified 2026-08-13):** permission rule lists are *merged across all settings files* and evaluated globally as `deny → ask → allow` — "the first match in that order determines the outcome, and rule specificity doesn't change the order." A deny in any tier wins over an allow in any other tier. Tier precedence applies to **single-value settings** (`defaultMode`, `disableBypassPermissionsMode`, sandbox config), not to rule evaluation.

⚠️ The collector's stored `precedenceRank` still encodes a level-first ordering that predates this verification and is **not** the vendor semantics; the UI therefore displays rules grouped by effect with provenance and makes no evaluation-order claim. A correct precedence engine is roadmap Step 5.

### Extracted per file

- `permissions.deny` / `permissions.ask` / `permissions.allow` → `PermissionRule[]` (matcher verbatim; `tool` parsed from the `Tool(specifier)` shape).
- `permissions.defaultMode`, `permissions.additionalDirectories`.
- `sandbox.*` → `SandboxConfig` (`enabled`, `allowUnsandboxedCommands`, network allowlist; note recorded that egress filtering is hostname-only per vendor docs).
- `hooks` → `Hook[]` (event, matcher, redacted+truncated command).
- MCP servers from: `<project>/.mcp.json`, `~/.claude.json` (`mcpServers` top-level and per-project entries), `enabledMcpjsonServers`/`disabledMcpjsonServers` lists.

### Instance construction

- One `user`-scope instance from user+managed files.
- One `project`-scope instance per scanned root containing `.claude/` or `.mcp.json`, merging managed+user+project+local (a project instance shows the *full* effective set, not just project-file rules).

## 3. Codex CLI collector (`codex-cli`) — spec'd, stubbed in v1

- Files: `~/.codex/config.toml`; project `requirements.toml` where present.
- Extract: approval policy (map `untrusted`→`ask`-dominant, `on-failure`/`never` noted on the instance), sandbox mode (`read-only`, `workspace-write`, `danger-full-access` → SandboxConfig + H1 when `danger-full-access`), network access flag and domain allowlist, MCP servers from `mcp_servers` tables.
- Mapping loss: Codex has no per-rule allow/deny list; we synthesize at most coarse rules from sandbox mode and record the native construct in `notes`.

## 4. Gemini CLI collector (`gemini-cli`) — spec'd, stubbed in v1

- Files: `~/.gemini/settings.json`, `<project>/.gemini/settings.json`.
- Extract: `coreTools`/`excludeTools` (map to `allow`/`deny` rules), tool auto-accept / YOLO-mode flags (H1), `mcpServers` blocks (same shape as Claude's), trust/`folderTrust` settings.

## 5. Generic MCP collector (`generic-mcp`) — implemented in v1

- Files: any file named exactly `mcp.json` in scanned roots (covers `.vscode/mcp.json`, `.cursor/mcp.json`). `.mcp.json` is claimed by the claude-code collector; broader `*.mcp.json` patterns are spec'd but not yet implemented.
- Produces a `generic-mcp` instance per file with `McpServer` rows only.

## 6. Risk heuristics (v1)

| Id | Severity | Trigger | Rationale |
|---|---|---|---|
| H1 | critical | Bypass modes: `defaultMode: "bypassPermissions"`, Codex `danger-full-access`, Gemini YOLO/auto-accept | All gating off |
| H2 | high | Wildcard allow: matcher `*`, bare tool with `:*`/`(*)` on Bash/Write/Edit-class tools | Unbounded tool surface |
| H3 | high | stdio MCP server launched via unpinned `npx -y` / `uvx` / `pipx run` | Executes latest upstream on every start — supply-chain exposure; landscape notes stdio is outside the MCP auth spec entirely |
| H4 | high | MCP `env` contains secret-suggestive key names (`*_TOKEN`, `*_KEY`, `*_SECRET`, `*_PASSWORD`) | Long-lived creds in agent-readable config (values already redacted by SR2; finding cites key names) |
| ~~H5~~ | — | **Retired 2026-08-13.** Flagged "deny shadowed by broader allow" — the opposite of documented behavior (deny wins globally). Kept in the schema enum for old snapshots only | See `local/mvp-review-accuracy-analysis.md` F1 |
| H6 | medium | Sandbox disabled or `allowUnsandboxedCommands: true` where the platform offers sandboxing | Filesystem/network confinement off |
| H7 | low | Hook command pipes remote content to a shell (`curl … \| sh` shape). *(The outside-path clause of the original spec is not yet implemented — roadmap Step 5)* | Hook = arbitrary code in the agent loop |

Each heuristic yields a `RiskFinding` with post-redaction evidence. Heuristics are pure functions over the normalized snapshot — they never re-read disk — so they are testable against fixtures.
