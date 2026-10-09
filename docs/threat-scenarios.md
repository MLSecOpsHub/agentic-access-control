# AgentLens — Threat Scenario Engine (spec)

Status: **v1-static implemented 2026-10-09** — schema (`ThreatScenarioSchema` in `lib/schema.ts`, confidence fields present per §6), engine (`lib/threat-scenarios.ts`), catalog with **S1–S4** (`lib/scenario-catalog.ts`; S3/S4 added 2026-10-09), precedence-aware reachability predicate (`lib/precedence.ts`), `/threat-model` page, per-instance section and the counts-only share card (§8.4), tests on emitted objects **and rendered pages** (`tests/scenario-catalog.test.ts`, `tests/sr3-crawl.test.ts`). S5, `declared+observed` confidence (Step 6 remodel) and the plugin (§8.3) are **not** implemented. This document is the design contract; when implementation diverges, fix one or the other before shipping.

## 1. Purpose and positioning

[threat-model.md](threat-model.md) points STRIDE *inward* at AgentLens. This feature points the same discipline *outward* at the observed machine: it composes the collected posture — permission declarations in vendor evaluation order, MCP inventory with approval state, sandbox posture with per-field provenance, hooks, and (when present) observed activity — into **threat scenarios**: named attack paths whose preconditions are all present in the snapshot.

The existing heuristics (H1–H7) are single-signal: one config fact → one finding. A scenario is a conjunction: *unpinned stdio MCP server* (supply chain entry) **+** *`allow Bash` reachable before any deny* **+** *sandbox disabled* **+** *credential-shaped env keys* ⇒ the configured declarations permit a code-execution → credential-exfiltration chain, with every precondition citing the exact file and rule that contributes it.

Layer taxonomy check (README): this is still **L2 — governance & posture**. The engine derives and displays; it never blocks, never edits, never sits in the request path.

## 2. Non-goals (binding, same force as the roadmap's permanent non-goals)

1. **No enforcement, no gating.** No hook that warns or blocks pre-tool-use — that is an L1 product. The in-session surface (§8.3) is display-only.
2. **No "attack detected" claims.** A scenario asserts that *configured declarations permit a path* (SR4). It never asserts that an attack is possible, likely, or occurring. Wording contract in §7.
3. **No config mutation.** A scenario may name the single precondition whose removal severs the path ("severance hint") and link to the file; the user edits.
4. **No new data collection.** The engine is a pure function over verified snapshots (+ the observed-event store, already local). It reads nothing else and produces no egress (SR3 unchanged).

## 3. Data model

Zod mirror to be added to `lib/schema.ts`; this table is the semantic contract.

### ThreatScenario

| Field | Type | Semantics |
|---|---|---|
| `id` | string | `<scenarioId>:<instanceId>:<n>` — stable within a snapshot |
| `scenarioId` | string | Catalog key, e.g. `S1-supply-chain-to-exfil` (§5) |
| `title` | string | Names the *path*, not an attack: "Configured path: unpinned MCP server → unsandboxed shell → credential env" |
| `severity` | Severity (existing enum) | Computed per §5 rules, never higher than the weakest-confidence precondition allows |
| `confidence` | `"declared" \| "declared+observed"` | §6. v1-static emits only `declared` |
| `preconditions` | Precondition[] | Every link in the chain, each independently cited |
| `categories` | { owaspAsi: string[], stride: string[] } | Mapped to the vocabularies already used in [threat-model.md](threat-model.md) §4. (MITRE ATLAS mapping is a candidate later addition; technique IDs must be verified against the published matrix at that time, not from memory.) |
| `severanceHints` | SeveranceHint[] | Minimal cut set(s): which single precondition removal breaks the path |
| `instanceId` | string | Owning AgentInstance |
| `caveat` | string | Always present, rendered verbatim; the SR4 sentence (§7) |

### Precondition

| Field | Type | Semantics |
|---|---|---|
| `kind` | enum | `permission-rule` \| `mcp-server` \| `sandbox-field` \| `hook` \| `mode` \| `observed-event` |
| `claim` | string | One factual sentence, e.g. "`allow Bash(*)` at local tier is reachable before any deny for the Bash tool" |
| `evidence` | string | Post-redaction, same rules as RiskFinding evidence |
| `sourceFile` | string \| null | Exact contributing file (Step 5 provenance: `sourceFile`, `defaultModeSourceFile`, `sandbox.fieldSources`) |
| `refId` | string \| null | Cross-reference: heuristic finding id when a heuristic already covers this atom (H1–H7 findings become citable atoms, not duplicated logic) |
| `confidence` | `"declared" \| "observed" \| "approval-recorded"` | Per-atom; scenario confidence derives from the weakest atom |

### SeveranceHint

| Field | Type | Semantics |
|---|---|---|
| `preconditionIndex` | number | Which link, if removed, severs the path |
| `text` | string | "Removing rule `allow Bash(*)` from `<file>` severs this path" — link to file/line, never an offer to edit |

## 4. Engine contract

- `lib/threat-scenarios.ts`: `runScenarios(ctx: { instances, mcpServers, findings, observed? }): ThreatScenario[]` — pure, no disk, no network, testable on fixtures (identical contract to `runHeuristics`).
- **Scenario rules are data**, not code: a catalog module (`lib/scenario-catalog.ts` in v1; user-extensible packs are the roadmap's "heuristic packs as data" item and come later) where each entry declares its precondition predicates, category mapping, severity function, and wording templates. Predicates operate only on schema fields — a scenario can require e.g. `effectivelyAllowed("Bash")`, which must reuse the Step 5 effect-first precedence logic, not reimplement it.
- **Reachability, not existence:** a permission-rule precondition holds only if the allow is not preceded by a matching deny under the documented evaluation order (`precedenceRank`). The conformance fixtures in `tests/vendor-conformance.test.ts` are the ground truth the predicate must agree with.
- **Enablement gates:** an MCP-server precondition on a server with `enablement: "disabled"` does not hold; `enablement: null` holds with the atom's claim explicitly noting "no recorded approval choice" — unknown is not enabled, but the path is still reported at reduced severity because unknown is not disabled either.
- Scenarios where a precondition is *absent* are not emitted as "safe" — absence of a scenario is not an all-clear (same principle as the findings empty state).

## 5. Initial catalog (v1)

Severity rule: base severity per scenario, **capped one level below the base when any precondition is `enablement: null`** (unknown approval) and **raised one level when confidence is `declared+observed`** (§6). Never exceeds `critical`. *Exception (2026-10-09): S4's missing approval choice is the scenario's own atom, not an uncertainty about another atom, so the cap does not apply to S4 — it reports at its base severity.*

| Id | Path (all preconditions must hold) | Base severity | Categories |
|---|---|---|---|
| S1 supply-chain → exfil | stdio MCP server via unpinned runner (H3-high atom) + credential env keys on any server for the instance (H4 atom) + effective `allow Bash` or sandbox disabled/escapable (H2/H6 atoms) | critical | ASI02, ASI03, ASI10 analog; STRIDE E/I |
| S2 gating collapse | `defaultMode` bypass (H1) + any MCP server or hook present | critical | ASI03, ASI05; E |
| S3 hook injection chain *(implemented)* | Hook piping remote content to shell (H7) + effective `allow` on the platform's shell or write tool (`Bash`/`Write`, `run_shell_command`/`write_file`) + sandbox disabled (H6) | high | ASI02, ASI05; T/E |
| S4 unreviewed project takeover *(implemented)* | Project-tier or local-tier `allow` on a shell/write-class tool, not outranked by an unbounded deny, + an MCP server declared in a file under the project root (`.mcp.json`, `.gemini/settings.json`) with `enablement: null` (team-writable config, no recorded approval) | high (no null cap, see above) | ASI03, ASI05; S/E |
| S5 credential concentration | ≥2 servers with credential env keys (H4) + any effective allow on a file-read tool covering home/config paths | medium | ASI03; I |

Catalog entries must each ship with: a fixture machine that triggers it, a fixture one-precondition-short that must **not** trigger it, and a wording test (§9).

## 6. Confidence model (why this is Step 6-gated)

- `declared`: every atom comes from configuration. This is v1-static and must say so.
- `declared+observed`: at least the *entry* atom was exercised in the observed-event window (e.g., the unpinned server actually connected — the `/live` correlation from `c763cb0`; the allow rule's tool was actually invoked). Uses `data/observed/` only; inherits every SR4 caveat of the live-tracking feature, including "invocation matching, never rule-attribution claims" — an observed atom says "this tool/server was used", never "this rule fired".
- The Step 6 schema fields (`status`, `confidence`, `source`, `trust`) are prerequisites for per-atom confidence to be first-class rather than bolted on. **Decision:** a v1-static engine (all atoms `declared`) may ship before the remodel only if the ThreatScenario schema lands with the confidence fields already present, so Step 6 extends values without a schema break.

## 7. Wording contract (the honesty core — lint-style enforced in tests)

Required, on every scenario, verbatim caveat: *"These are configured declarations composed by AgentLens, not observed enforcement or an observed attack. The platform's own evaluator is ground truth (SR4)."*

Banned phrases in any title/claim/hint (tested by string assertion against the rendered page and the emitted objects): "attack is possible", "vulnerable to", "exploitable", "attacker can", "will execute". Required framing: "configured declarations permit", "path exists in configuration", "no recorded approval choice".

Rationale: a composed claim is epistemically *weaker* than each atom (T5 parse-divergence risk multiplies across the conjunction), while reading as *stronger* to the user. The wording contract is the counterweight, and it is what keeps this feature from repeating the pre-Step-1 false-claim class at higher stakes.

## 8. Surfaces

### 8.1 Dashboard page `/threat-model`
Scenario list, severity-sorted; each expands to the precondition chain with per-atom file links, categories, severance hints, confidence badge. Standing SR4 banner as on every other page. Empty state: "No scenario from the current catalog matches the collected data" — never "no attack paths exist".

### 8.2 Per-instance section
On `/agents/<id>`: scenarios owned by the instance, below findings.

### 8.4 Share card `/share` (implemented 2026-10-09)
The one artifact designed to leave the machine, so it is counts-only by contract: instances per platform, declaration totals by effect, MCP totals by transport, findings by severity, scenario ids with counts and top severity, collectors run. **Never** file paths, rule matchers, server names, hostnames or machine ids. `lib/share-card.ts` builds it as a pure function; `tests/share-card.test.ts` asserts every identifying string in the fixture is absent; the SR3 crawl applies the §7 banned-phrase check to the rendered page. Copying is a user-triggered local clipboard action — no network.

### 8.3 Claude Code plugin (display-only, separate deliverable)
The roadmap parking-lot item, promoted: a plugin whose skill + SessionStart hook reads the **newest verified snapshot** (hash check before trust — SR5) and prints a one-line summary in-session ("AgentLens: 2 threat scenarios for this project — open /threat-model"). Constraints: read-only (SR1), loopback dashboard link only (SR3), never a PreToolUse gate, degrades silently to nothing when no snapshot exists. It runs *inside* an agent session, i.e. inside M2's blast radius — see T13.

## 9. Testing (Step 4 style — executable or it doesn't ship)

- Per-catalog-entry: trigger fixture, near-miss fixture, wording assertions (§7 banned/required strings) on both the emitted objects and the rendered page (extend the SR3 crawl test to `/threat-model`).
- Reachability predicate agreement with `tests/vendor-conformance.test.ts` semantics (deny-first) — a deny anywhere must sever S1/S3/S4 paths that route through the matched tool.
- Enablement gating: `disabled` server never appears as an atom; `null` caps severity.
- Determinism: same snapshot ⇒ byte-identical scenario list (drift for scenarios becomes possible later; not in v1).

## 10. Threat-model & SR deltas (to land in [threat-model.md](threat-model.md) / [security-architecture.md](security-architecture.md) with the implementation)

- **T13 (new)** — Scenario overclaim: composed wording induces a wrong mental model in the user (A3-adjacent, but *semantic* rather than tamper). Mitigation: §7 contract, enforced by tests; residual **medium and permanent** — same class as T5, and inherits T5 (a parse-divergence error propagates into every scenario built on the misparsed atom).
- **T14 (new)** — Plugin surface: the in-session plugin executes inside agent sessions; a prompt-injected agent (M2) could read its output (A1 fragment) or attempt to have the hook script modified. Mitigation: plugin reads snapshot + prints only; no arguments taken from session content; installation is explicit user action; hook file integrity is the user's `.claude/` trust domain, stated plainly in the plugin README.
- SR4 wording requirement extends to scenario output (§7). SR1/SR3/SR5 unchanged and re-asserted by the same CI tests.

## 11. Sequencing & acceptance

1. ~~Land ThreatScenario schema (with confidence fields) + engine + S1/S2 + `/threat-model` page + tests.~~ **Done 2026-10-09** (preceded the Step 6 remodel per §6 decision; per-instance surface landed with it).
2. ~~S3–S4~~ **Done 2026-10-09**, with the rendered-page wording test and the share card (8.4). S5 remains.
3. Step 6 remodel lands → `declared+observed` confidence via the observed store.
4. Plugin (8.3) last — it is a consumer, and it triggers the T14 threat-model update as a landing condition.

**Acceptance:** all §9 tests green in CI; threat-model.md carries T13/T14; roadmap parking-lot entries ("heuristic packs as data" — partially, "Claude Code plugin") updated to reference this spec; no banned phrase reachable in any rendered surface.
