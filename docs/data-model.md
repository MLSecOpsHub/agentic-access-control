# AgentLens — Canonical Data Model

The single source of truth in code is `lib/schema.ts` (zod). This document explains the semantics; if the two diverge, treat `lib/schema.ts` as authoritative and fix this file.

Everything below is contained in one **Snapshot** — an immutable, content-hashed JSON document produced by one collector run. The dashboard only ever reads snapshots; it has no other data source.

## Snapshot

| Field | Type | Semantics |
|---|---|---|
| `schemaVersion` | string | Semver of this schema; collectors and UI must agree on major |
| `generatedAt` | ISO 8601 string | Collection wall-clock time; UI always displays age (stale-data risk, threat model T7) |
| `machineId` | string | Stable non-PII identifier (hash of hostname); for Phase 3 multi-machine merge |
| `hash` | string | SHA-256 of the canonicalized snapshot body *excluding this field* (SR5) |
| `collectors` | string[] | Collector ids that ran, e.g. `["claude-code"]` — absence of a platform ≠ absence of the tool |
| `instances` | AgentInstance[] | |
| `mcpServers` | McpServer[] | Flattened across instances; each row carries `instanceId` |
| `findings` | RiskFinding[] | Output of heuristics H1–H7 |

## AgentInstance

One (platform × scope × project) combination. A user-level Claude Code config and a project-level one are **two instances**, because their configured permission sets differ.

| Field | Type | Semantics |
|---|---|---|
| `id` | string | Stable: `platform:scope[:projectPathHash]` |
| `platform` | `"claude-code" \| "codex-cli" \| "gemini-cli" \| "generic-mcp"` | |
| `version` | string \| null | Best-effort detected tool version |
| `scope` | `"user" \| "project"` | |
| `projectPath` | string \| null | Absolute path when scope = project |
| `configFiles` | string[] | Every file read to build this instance — the provenance universe |
| `defaultMode` | string \| null | Platform permission mode if configured (e.g. `plan`, `acceptEdits`, `bypassPermissions`) |
| `permissionRules` | PermissionRule[] | Merged, precedence-ranked |
| `sandbox` | SandboxConfig \| null | |
| `hooks` | Hook[] | |

## PermissionRule

| Field | Type | Semantics |
|---|---|---|
| `effect` | `"allow" \| "ask" \| "deny"` | Normalized across platforms |
| `matcher` | string | Platform-native matcher verbatim, e.g. `Bash(git push:*)`, `WebFetch(domain:example.com)` |
| `tool` | string \| null | Parsed tool name when extractable from the matcher |
| `sourceFile` | string | Exact file that contributed the rule |
| `sourceLevel` | `"managed" \| "user" \| "project" \| "local" \| "flag"` | Settings tier |
| `precedenceRank` | number | ⚠️ Legacy display-ordering value using a level-first encoding that does **not** match vendor rule-evaluation semantics (global deny → ask → allow). The UI no longer shows it as evaluation order; scheduled for reimplementation in roadmap Step 5 |

**Effect normalization note:** Claude Code's `deny → ask → allow` maps directly. Codex CLI approval policies and Gemini CLI trust settings map with loss; the collector spec ([collectors.md](collectors.md)) defines each mapping and the UI shows the native construct on hover/detail.

## McpServer

| Field | Type | Semantics |
|---|---|---|
| `name` | string | Key from the declaring config |
| `transport` | `"stdio" \| "http" \| "sse" \| "unknown"` | |
| `commandOrUrl` | string | stdio command or remote URL (post-redaction) |
| `args` | string[] | Post-redaction |
| `envKeys` | string[] | **Names only.** Values are dropped at collection time, never persisted (SR2) |
| `declaredTools` | string[] \| null | Only if statically declared; never obtained by *running* the server (SR1) |
| `sourceFile` | string | |
| `instanceId` | string | Owning AgentInstance |

## SandboxConfig

| Field | Type |
|---|---|
| `enabled` | boolean \| null |
| `allowUnsandboxedCommands` | boolean \| null |
| `networkAllowlist` | string[] |
| `notes` | string \| null (platform-specific caveats, e.g. "hostname-only egress filtering") |

## Hook

| Field | Type | Semantics |
|---|---|---|
| `event` | string | e.g. `PreToolUse`, `PostToolUse` |
| `matcher` | string \| null | |
| `commandPreview` | string | Redacted + truncated to 200 chars — hooks are arbitrary shell and may embed secrets |
| `sourceFile` | string | |

## RiskFinding

| Field | Type | Semantics |
|---|---|---|
| `id` | string | Stable within a snapshot: `heuristicId:instanceId:n` |
| `heuristicId` | `"H1"…"H7" \| "PARSE"` | Defined in [collectors.md](collectors.md) §6; `PARSE` marks an unreadable config (severity `info`); `H5` is retired (kept in the enum only so old snapshots parse) |
| `severity` | `"critical" \| "high" \| "medium" \| "low" \| "info"` | |
| `title` | string | One line, human-readable |
| `evidence` | string | The config fragment (post-redaction) that triggered the finding |
| `instanceId` | string \| null | |
| `sourceFile` | string \| null | |

## Drift (derived, not stored)

Drift is computed by the dashboard from the two newest snapshots — never persisted, so it can't be tampered with independently of the hashed snapshots, and only when **both** snapshots pass raw-hash verification (SR5); otherwise the UI reports "drift unavailable" with the reason. Diff key for rules: `(instanceId, effect, matcher, sourceLevel)`; for MCP servers: `(instanceId, name)`. Output classes: `added`, `removed`, and — for a same-named MCP server whose security-relevant fields (transport, commandOrUrl, args, envKeys, declaredTools, sourceFile) differ — a field-level `changed` entry. Hash mismatch with identical content ⇒ integrity warning.
