# AgentLens — read-only permission observatory for local AI agents

AgentLens answers one question: **what are the AI agents on this machine currently allowed to do?**

It discovers agent/LLM tooling installed locally (Claude Code and Gemini CLI today, plus generic `mcp.json` manifests; Codex CLI is spec'd but not yet read), reads their permission-relevant configuration **read-only**, normalizes it into one canonical schema, and renders it in a local dashboard: configured permission declarations with provenance, MCP server inventory, sandbox/hook posture, risk findings, composed threat scenarios, and drift between snapshots.

## What it is — and is not

Using the layer taxonomy from our [landscape research](docs/research/aiagentaccesscontrollandscape.md):

| Layer | Role | AgentLens? |
|---|---|---|
| L0 | Native platform controls (the configs agents actually obey) | **Read as input** |
| L1 | In-path gateways & sandboxes (the only layer that blocks) | ✗ Not this |
| L2 | Governance & posture (discover, map, score) | **✓ This — and honestly labeled as such** |

AgentLens **never enforces, never modifies a config, never sits in the request path, and never sends data anywhere**. The landscape doc's core critique of the L2 market is vendors marketing observation as enforcement; AgentLens's design principle is the opposite: observe-only, and say so on every screen.

It targets the whitespace the research identifies: individual/prosumer tooling ("nobody has built the Little Snitch for AI agents" — this is the read-only telescope half of that idea) and permission-level audit visibility.

## Quick start

```bash
npm install
npm run dev        # dashboard on http://127.0.0.1:3000 with bundled fixture data
npm run collect    # scan this machine read-only → data/snapshots/<timestamp>.json
npm test           # executable SR1–SR5 verification (see security posture below)
```

The dashboard renders the newest snapshot in `data/snapshots/`, falling back to `data/fixtures/sample-snapshot.json` so it works out of the box.

## Repository layout

| Path | Contents |
|---|---|
| `docs/poc-guide.md` | **Start here** — current featureset and step-by-step local test walkthrough |
| `docs/testing-live-tracking.md` | Testing guide for the `/live` observed-activity feature (synthetic + real-session paths) |
| `docs/product-spec.md` | Personas, jobs, MVP features, non-goals, competitive positioning |
| `docs/security-architecture.md` | Components, trust boundaries, security requirements SR1–SR5 |
| `docs/threat-model.md` | STRIDE pass mapped to OWASP Agentic Top 10 (ASI03) |
| `docs/threat-scenarios.md` | Threat scenario engine — composes collected posture into cited attack-path scenarios (v1: S1/S2 implemented, `/threat-model` page) |
| `docs/data-model.md` | Canonical schema (mirrored by `lib/schema.ts` zod schemas) |
| `docs/collectors.md` | Per-platform collector specs: file locations, precedence, risk heuristics |
| `docs/roadmap.md` | Phase 2 cloud connectors, Phase 3 fleet aggregation, permanent non-goals |
| `docs/research/` | The landscape map (markdown + interactive HTML) this project is grounded in |
| `app/`, `lib/`, `collectors/` | Next.js dashboard, schema, collector CLI |
| `data/` | Fixtures (committed) and snapshots (generated, gitignored) |

## Security posture in one paragraph

Collectors open files read-only from an allowlist of known config locations (SR1) and redact secret-shaped values before anything touches disk (SR2). The dashboard binds to 127.0.0.1 and makes zero outbound requests (SR3) — a map of your machine's agent attack surface is itself sensitive. Every permission view carries the caveat that it shows *configured declarations*, not proof of enforcement (SR4). Snapshots are content-hashed for tamper evidence, verified on the raw bytes before validation, and drift only renders between two verified snapshots (SR5). Each requirement is backed by an executable test in `tests/` (`npm test`, enforced in CI). Details: [docs/security-architecture.md](docs/security-architecture.md); hardening plan: `local/hardening-roadmap.md`.
