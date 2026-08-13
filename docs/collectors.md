# AgentLens — Collector Specifications

Collectors are read-only filesystem readers. Shared contract, then one section per platform, then the risk heuristics.

## 1. Shared collector contract

1. **SR1 — read-only.** Open with read-only intent; never create, write, or touch anything outside the snapshot output directory (`data/snapshots/`). No child processes that could mutate state; version detection via `--version` subprocess is the only allowed exec, and it must be the platform binary with that single flag. Never *execute* an MCP server to enumerate tools.
2. **SR2 — redact before persist.** All collected strings pass through the redactor (`lib/redact.ts`) before entering the snapshot object. Env **values** are dropped unconditionally (key names survive). Secret-shaped substrings anywhere else (commands, args, URLs, hook bodies) are replaced with `[REDACTED]`. Patterns include: `sk-…`, `ghp_`/`gho_`/`github_pat_`, `AKIA…`, `xoxb-`/`xoxp-`, `Bearer <token>`, `key=`/`token=`/`secret=`/`password=` value captures, JWT triplets, and ≥32-char high-entropy base64/hex runs. False positives are acceptable; false negatives are the failure mode.
3. **Allowlisted paths only.** Each collector declares the exact glob set below; nothing else is read. Project scanning is limited to roots passed explicitly (`npm run collect -- <root>...`, default: cwd), max depth 4, skipping `node_modules`, `.git`, and symlinks (path-traversal guard, threat T4).
4. **Malformed input is data.** Config files are untrusted content. Parse failures produce an `info` finding, never a crash; parsed strings are stored verbatim (post-redaction) and only ever rendered escaped.
5. **Absence is not knowledge.** If a platform's binary/config isn't found, the collector reports nothing and the snapshot's `collectors` list still names it as *ran* — the UI distinguishes "ran, found nothing" from "didn't run".

## 2. Claude Code collector (`claude-code`) — implemented in v1

### Files read, in precedence order (our interpretation — SR4)

| Rank | Level | Path | Notes |
|---|---|---|---|
| 1 | `managed` | `/etc/claude-code/managed-settings.json` (Linux), `/Library/Application Support/ClaudeCode/managed-settings.json` (macOS) | Admin-enforced; wins over everything |
| 2 | `local` | `<project>/.claude/settings.local.json` | Per-checkout, usually gitignored |
| 3 | `project` | `<project>/.claude/settings.json` | Checked in — team-visible |
| 4 | `user` | `~/.claude/settings.json` | |

Within a level, `deny` beats `ask` beats `allow`. `precedenceRank` encodes (level, effect) lexicographically so the UI can sort a merged table.

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

- Files: any `mcp.json` / `.mcp.json` / `*.mcp.json` in scanned roots not already claimed by a platform collector (e.g. editor-agnostic configs, `.vscode/mcp.json`, `.cursor/mcp.json`).
- Produces a `generic-mcp` instance per file with `McpServer` rows only.

## 6. Risk heuristics (v1)

| Id | Severity | Trigger | Rationale |
|---|---|---|---|
| H1 | critical | Bypass modes: `defaultMode: "bypassPermissions"`, Codex `danger-full-access`, Gemini YOLO/auto-accept | All gating off |
| H2 | high | Wildcard allow: matcher `*`, bare tool with `:*`/`(*)` on Bash/Write/Edit-class tools | Unbounded tool surface |
| H3 | high | stdio MCP server launched via unpinned `npx -y` / `uvx` / `pipx run` | Executes latest upstream on every start — supply-chain exposure; landscape notes stdio is outside the MCP auth spec entirely |
| H4 | high | MCP `env` contains secret-suggestive key names (`*_TOKEN`, `*_KEY`, `*_SECRET`, `*_PASSWORD`) | Long-lived creds in agent-readable config (values already redacted by SR2; finding cites key names) |
| H5 | medium | Deny rule co-exists with a broader allow on the same tool (e.g. `deny Bash(rm:*)` + `allow Bash`) | Interpretation-dependent shadowing; per-platform precedence should protect, but it's the classic footgun |
| H6 | medium | Sandbox disabled or `allowUnsandboxedCommands: true` where the platform offers sandboxing | Filesystem/network confinement off |
| H7 | low | Hook command pipes remote content to a shell (`curl … \| sh` shape) or references files outside the project and home config dirs | Hook = arbitrary code in the agent loop |

Each heuristic yields a `RiskFinding` with post-redaction evidence. Heuristics are pure functions over the normalized snapshot — they never re-read disk — so they are testable against fixtures.
