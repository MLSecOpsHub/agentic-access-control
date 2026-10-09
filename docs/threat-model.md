# AgentLens — Threat Model

Scope: the AgentLens pipeline (collectors → normalizer → snapshot store → dashboard) on a single machine, per the component/boundary diagram in [security-architecture.md](security-architecture.md). Method: STRIDE per boundary, then a mapping to the OWASP Top 10 for Agentic Applications (Dec 2025), which the landscape research identifies as "the most concrete artifact to sell/build against today."

## 1. Assets

| Asset | Why it matters |
|---|---|
| A1 — The aggregated permission map (snapshots + rendered views) | Recon gold: one file describing every gap in the machine's agent confinement |
| A2 — Secrets embedded in agent configs | MCP env tokens, hook credentials — flow *through* collectors even though they must not flow *into* snapshots |
| A3 — Integrity of findings & drift | Users make security decisions from these; a falsified "all clear" is worse than no tool |
| A4 — The user's trust in "read-only" | One accidental config write destroys the product's core promise |
| A5 — Observed-event history (`data/observed/`) | Behavioral record of tool usage per session — at least as sensitive as A1; gitignored, bounded retention |

## 2. Attackers considered

- **M1 — Malicious project repo**: user clones a repo whose `.claude/`, `.mcp.json`, or directory structure is crafted to attack the collector or the viewer (adversarial strings, symlinks, parser bombs). *Most realistic attacker — cloning untrusted repos is the norm.*
- **M2 — Compromised/prompt-injected agent on the same machine**: can write its own configs and possibly snapshots.
- **M3 — Same-host other-user or malware**: local access, wants A1/A2.
- **M4 — Supply chain**: compromised npm dependency of AgentLens itself.
- Out of scope v1: network attackers (no listener beyond loopback, no egress), cloud-side attackers (no cloud connectors yet).

## 3. STRIDE findings

| Id | STRIDE | Threat | Boundary | Mitigation | Residual risk |
|---|---|---|---|---|---|
| T1 | Tampering / Elevation | Crafted config strings execute in the viewer (stored XSS) → with localhost server, pivot to reading arbitrary snapshots | B1→B3 | React escaping only; `dangerouslySetInnerHTML` banned; config content never rendered as HTML/markdown | Low |
| T2 | Information disclosure | Secrets in configs persisted into snapshots, then shared (bug report, git commit) | B2 | SR2 collection-time redaction; env values dropped; snapshots gitignored | Medium — pattern-based redaction misses novel formats (non-guarantee #4) |
| T3 | Information disclosure | A1 exfiltrated by AgentLens itself phoning home | B4+ | SR3: zero egress by construction; no analytics/CDN; CI egress test | Low |
| T4 | Elevation / Info disclosure | Symlink or path trick in a scanned project makes the collector read `~/.ssh`, `/etc/shadow` into a snapshot | B1 | Allowlisted globs, symlinks not followed, depth cap, resolved-path prefix check | Low |
| T5 | Repudiation-adjacent (wrong attestation) | **Parse divergence**: our precedence interpretation disagrees with the platform's real evaluator → user believes something is denied that isn't | Normalizer | SR4 banner + per-rule provenance; per-platform mapping documented with vendor links; known mapping losses recorded on the instance; conformance fixtures per platform release | **Medium and permanent** — platforms change semantics without notice; this is the product's biggest honest weakness |
| T6 | Spoofing / Info disclosure | Dashboard accidentally exposed beyond loopback (LAN, port-forward, reverse proxy) with no auth layer | B4 | Explicit `-H 127.0.0.1`; docs warn against proxying; no auth in v1 is a *documented* limitation | Medium if user proxies it — roadmap: opt-in auth before any remote mode |
| T7 | Tampering (staleness) | Decisions made on an old snapshot ("that deny exists" — removed yesterday) | B3 | `generatedAt` age always rendered, warning styling past threshold | Low |
| T8 | Tampering | M2/M3 edits a snapshot to hide a finding (A3) | B3 | SR5 content hash, integrity warning on mismatch | Medium — local attacker can re-hash; signing is roadmap |
| T9 | Denial of service | Parser bomb: multi-GB JSON, deeply nested structures in a cloned repo | B1 | File-size cap before parse, parse in try/catch → `info` finding | Low |
| T10 | Elevation | npm dependency compromise (M4) | build | 4 direct runtime/dev deps, committed lockfile, review on bump. Transitive deps (esbuild, sharp, fsevents) carry install scripts | Medium — industry-standard, not solved |
| T11 | Tampering (A4) | A code path writes to an agent config (bug, not attack) | B1 | SR1 design (no write APIs imported in collector modules), mtime-invariance test in CI | Low |
| T13 | Repudiation-adjacent (wrong attestation) | **Scenario overclaim**: a composed threat scenario ([threat-scenarios.md](threat-scenarios.md)) reads as *stronger* than its atoms while being epistemically *weaker* — a T5 parse-divergence error in one atom propagates into every scenario built on it, and the user forms a wrong mental model ("an attack is possible") from what is only a conjunction of configured declarations | Normalizer → B3 | Wording contract (threat-scenarios §7) enforced by string assertions in `tests/scenario-catalog.test.ts`; verbatim SR4 caveat on every scenario; reachability predicate reuses the conformance-tested precedence logic rather than reimplementing it; empty state never reads as an all-clear | **Medium and permanent** — same class as T5 and inherits it |
| T14 | Elevation / Information disclosure | **In-session plugin surface** (threat-scenarios §8.3, *not yet built*): a display-only hook running inside an agent session is inside M2's blast radius — a prompt-injected agent could read its output (A1 fragment) or attempt to alter the hook script | B4 | Plugin reads the newest hash-verified snapshot and prints only; takes no arguments from session content; installation is an explicit user act; hook integrity is the user's `.claude/` trust domain, stated in the plugin README | Medium — recorded now so the landing condition is explicit; re-assess when the plugin is built |
| T12 | Spoofing / Tampering / DoS | The loopback OTLP receiver (`/api/otel/v1/logs`) is AgentLens's first ingestion listener: any local process running as the user can POST forged events (fake "reject" decisions, flooding), or oversized/malformed payloads | B4 (revised) | POST+JSON only; body cap before parse; event-name and attribute allowlists; identity attributes never read; fixed error codes (no payload echo); dedup; bounded, gitignored storage with retention; UI states that localhost origin is not cryptographic authenticity | Medium — local forgery is inherent to unauthenticated loopback ingestion; acceptable for an observe-only local tool, revisit before any multi-machine mode |

## 4. OWASP Agentic Top 10 mapping

AgentLens is not an agent — it has no model, no tool loop — so most ASI items apply in the "what AgentLens helps *users* see" sense, with three applying to AgentLens itself:

| OWASP ASI | Relation |
|---|---|
| **ASI03 Identity & Privilege Abuse** | The product's reason to exist: renders privilege sprawl (F2) and over-permissive posture (H1/H2). This is the anchor per the landscape doc. |
| ASI02 Tool Misuse | MCP inventory (F3) + unpinned-server and secret-env heuristics (H3/H4) give the pre-conditions view; threat scenarios S1/S2 compose them into cited paths (each scenario carries its own ASI/STRIDE tags) |
| ASI05 Insecure Config | The whole surface: bypass modes, disabled sandboxes (H1/H6) |
| *Applies to AgentLens itself:* | |
| ASI06 Memory/Context Poisoning analog | T1/T2 — our "context" is untrusted config; handled at B1 |
| ASI08 Insufficient Logging analog | Snapshots ARE the audit trail; SR5 protects them |
| ASI10 Unsafe Third-Party Ecosystem | T10 dependency posture |

## 5. Review cadence

- Re-run this model when: a new collector lands, any dependency is added, any network capability is proposed (that one is a full re-model — it breaks B4's core assumption), or a platform ships a permission-semantics change (T5 fixture refresh).
- Standing rule from A4: any PR touching collector code must state in its description how SR1 is preserved.
- Standing rule from T13: any new scenario-catalog entry ships with a trigger fixture, a near-miss fixture and wording assertions (threat-scenarios §9) — no exceptions for "obvious" scenarios.
