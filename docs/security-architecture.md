# AgentLens — Security Architecture

AgentLens is a security tool, so its own security posture is a product feature. This document defines the components, trust boundaries, and the five numbered security requirements (SR1–SR5) every change is reviewed against. The adversarial analysis lives in [threat-model.md](threat-model.md).

## 1. Components and data flow

```
 agent config files            AgentLens boundary
┌─────────────────────┐   ┌──────────────────────────────────────────────────┐
│ ~/.claude/*.json    │   │                                                  │
│ <proj>/.claude/*    │──▶│ Collectors ──▶ Normalizer ──▶ Snapshot store     │
│ .mcp.json, TOML …   │ R │ (read-only    (canonical     (hashed JSON,       │
│ [UNTRUSTED CONTENT] │ O │  fs readers,   schema,        data/snapshots/)   │
└─────────────────────┘   │  redactor)     heuristics)         │             │
                          │                                    ▼ read-only   │
                          │                       Dashboard (Next.js,        │
                          │                       binds 127.0.0.1, no egress)│
                          └──────────────────────────────┬───────────────────┘
                                                         ▼
                                              Browser on same machine
```

One-way pipeline: files → snapshot → UI. There is no arrow pointing back at the config files (SR1) and no arrow leaving the machine (SR3).

## 2. Trust boundaries

| # | Boundary | Trust stance |
|---|---|---|
| B1 | Config files → Collectors | **Untrusted input.** Configs are written by users, checked-in project files (i.e., *other people via git*), installers, and potentially by a compromised or prompt-injected agent. Treat every string as adversarial data: parse defensively, redact, escape on render. |
| B2 | Collectors/Normalizer → Snapshot store | Trusted code, untrusted-derived data. Snapshot dir is the only writable location. |
| B3 | Snapshot store → Dashboard | Snapshots may have been edited on disk between collect and render (they're user-owned files). Hash verification (SR5) detects, not prevents. Content still rendered escaped. |
| B4 | Dashboard server ↔ Browser / local processes | Same-machine only. Localhost bind is the control; there is no authn/authz layer in v1, so the LAN-exposure failure mode is prevented, not mitigated (see T6). **Revised 2026-08-13:** the server now also *ingests* — the loopback OTLP receiver (`/api/otel/v1/logs`) accepts user-directed Claude Code telemetry. Any local process running as the user can reach it; localhost origin is not authenticity (T12). |

## 3. Security requirements

### SR1 — Read-only guarantee
Collectors must not modify agent configuration or any file outside `data/snapshots/`.
- Files opened for read only; single allowed subprocess shape is `<platform-binary> --version`.
- MCP servers are **never executed** to enumerate tools; only statically declared tool lists are recorded.
- Path allowlist per collector ([collectors.md](collectors.md) §1.3); symlinks not followed during project scans.
- **Test:** record mtimes of every file in the allowlist before/after `npm run collect`; assert unchanged. Assert no files created outside `data/snapshots/`.

### SR2 — Secrets redaction at collection time
Secret material must never reach the snapshot file, therefore never the DOM.
- Redaction happens in the collector, before the snapshot object is assembled — not at render time. Until the Step 4 test suite proves this end-to-end, treat snapshots as sensitive files, not shareable artifacts.
- MCP `env` values dropped unconditionally (key names kept — they power heuristic H4). Pattern-based redaction over rule matchers, commands, args, URLs, and hook bodies (patterns in [collectors.md](collectors.md) §1.2, implemented in `lib/redact.ts`). **Known gaps** (verified 2026-08-13, fix scheduled as roadmap Step 2): persisted JSON parse-error messages can echo config content, and some scalar fields (`defaultMode`, hook event names) bypass redaction — see `local/mvp-review-accuracy-analysis.md` F3.
- Bias to over-redaction: a mangled command display is acceptable; a leaked token is not. (Pattern precedent: `l-mb/claude-code-redaction-hooks` from the landscape research.)
- **Test:** fixture configs seeded with fake secrets of every pattern class; assert none survive into the snapshot; CI grep of generated snapshots for `sk-`, `AKIA`, `ghp_`, `Bearer`.

### SR3a — Loopback event ingestion (added 2026-08-13)
The live-tracking feature adds one ingestion listener: `POST /api/otel/v1/logs` on the existing 127.0.0.1-bound server, receiving Claude Code OpenTelemetry events **only when the user explicitly launches Claude Code with an exporter pointed at it** (AgentLens never writes telemetry config — SR1). Controls: POST + `application/json` only; 2 MB body cap enforced before parsing; event-name and attribute allowlists (`lib/observed.ts`); identity attributes (user/org/installation ids, emails) never read; values redacted at ingest; fixed error codes with no payload echo (SR2); deterministic dedup; bounded gitignored storage (`data/observed/`, 7-day retention, per-segment size cap). Residual risk: local processes can forge events — T12. Design details: `local/live-tracking-final-plan.md`.

### SR3 — Local-only by default
The dashboard aggregates a complete map of the machine's agent attack surface — permission gaps, MCP inventory, sandbox state. That artifact is exactly what an attacker doing recon wants. Therefore:
- Dev/prod server binds `127.0.0.1` explicitly (`next dev -H 127.0.0.1`).
- Zero outbound requests: no analytics, no update checks, no CDN assets, no remote fonts. Everything ships in the repo.
- Snapshots are gitignored by default; committing one is an explicit user act.
- **Test:** crawl rendered pages for external URLs in `src`/`href` of loadable resources; run collector and server under network observation in CI and assert no egress.

### SR4 — Interpretation honesty
Rendered permission views show *configured declarations* with provenance — not a re-implementation of the platform's evaluator, whose semantics are the only ground truth and change without notice. An evaluation-order view returns only when backed by vendor-conformance tests (hardening roadmap Step 5).
- Persistent banner on every page: interpretation, not enforcement; link to per-platform precedence spec in [collectors.md](collectors.md) with vendor-doc references.
- Every rule row carries provenance (`sourceFile`, `sourceLevel`) so users can verify against the raw file in one step.
- Parse-divergence risk is a first-class threat (T5), and known mapping losses (Codex, Gemini) are recorded on the instance, not hidden.
- This requirement is the product's answer to the landscape doc's core L2 critique: never let observation cosplay as enforcement.

### SR5 — Tamper-evident snapshots
- Each snapshot embeds a SHA-256 over its canonicalized body (hash field excluded); the UI recomputes on load and shows an integrity warning on mismatch. **Known gap** (fix scheduled as roadmap Step 3): verification currently runs after schema validation, which strips unknown fields — so the implemented guarantee is known-schema object integrity, not whole-file integrity; drift is also not yet gated on hash verification.
- Drift is always computed from two hash-verified snapshots; it is derived at render time and never stored (no third artifact to tamper with).
- This is tamper-*evidence*, not tamper-*proofing*: an attacker with local write access can re-hash. Signing snapshots is a roadmap item; the honest v1 claim is "detects accidental edits and unsophisticated tampering."

## 4. Dashboard-as-target: key mitigations

| Attack | Mitigation |
|---|---|
| Stored XSS via adversarial config strings (a matcher named `<img onerror=…>`) | React default escaping only — no `dangerouslySetInnerHTML` anywhere in the codebase (convention today; lint enforcement lands with roadmap Step 4); no markdown rendering of config content |
| Path traversal via crafted project structure (symlink from a scanned repo → `/etc`, `~/.ssh`) | Allowlisted globs, symlink entries skipped during traversal, depth cap. A resolved-path prefix check is specified but not yet implemented (roadmap Step 4/5) |
| Snapshot poisoning (edit snapshot to hide a finding before a review) | SR5 hash check; findings recomputable from raw rules client-side in a later version |
| Exfiltration of the aggregated map | SR3: no egress, localhost bind, snapshots gitignored |
| Dependency supply chain | Minimal direct dependency set (next, react, zod, tsx); lockfile committed. Note: transitive dependencies (esbuild, sharp, fsevents) do carry install scripts — review on every bump |

## 5. Explicit non-guarantees

Stated so the product can't oversell itself:
1. AgentLens cannot see permissions granted *outside* config files (session-scoped "always allow" state stored elsewhere, cloud-side grants) unless a collector spec covers that store.
2. A snapshot is stale the moment it's written; the UI always shows age.
3. Localhost binding does not defend against other processes/users on the same machine.
4. Redaction is pattern-based and can miss novel secret formats.
