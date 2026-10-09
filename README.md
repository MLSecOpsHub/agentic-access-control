# AgentLens — what are the AI agents on this machine allowed to do?

AgentLens finds the AI coding agents installed on a machine — **Claude Code, Gemini CLI**, plus generic `mcp.json` manifests — reads their permission-relevant configuration **read-only**, and shows in a local dashboard what they are *configured* to be allowed to do: every allow/ask/deny declaration with the file it came from, every MCP server, sandbox and hook posture, risk findings, composed **threat scenarios**, and drift between snapshots.

It never enforces, never edits a config, never sits in the request path, and never sends data anywhere. Every screen says so.

## 60 seconds to your own posture

```bash
git clone https://github.com/MLSecOpsHub/agentic-access-control.git && cd agentic-access-control
npm install
npm run collect      # read-only scan: user configs + cwd + every project Claude Code has been opened in
npm run dev          # dashboard on http://127.0.0.1:3000 (loopback only)
```

Or, once the npm package is published: `npx @mlsecopshub/agentlens scan` does both (snapshots land in `~/.local/share/agentlens`; `--open` launches a browser).

What to look at first:

1. **Overview** — instances per platform, declaration counts, MCP servers, findings by severity, drift since the last snapshot.
2. **`/agents/<id>`** — one instance's merged declarations in the platform's documented evaluation order (Claude Code: deny → ask → allow across all tiers), each row traceable to its source file; sandbox fields and hooks with per-field provenance; per-platform *mapping notes* for what does not map onto rules.
3. **`/threat-model`** — findings composed into cited attack paths (S1 unpinned MCP server → shell → credential env; S2 bypassed gating; S3 remote-content hook chain; S4 unreviewed project takeover). Every precondition names its file; every scenario carries the same caveat: *configured declarations, not an observed attack*.
4. **`/share`** — a counts-only card you can paste anywhere. By tested contract it contains no paths, matchers, server names or hostnames:

```
AgentLens posture summary · 2026-08-13
What this is: configured declarations read from local agent config files — not enforcement, not observed activity.

Agent instances: 4 (claude-code ×2, gemini-cli ×1, generic-mcp ×1)
Permission declarations: 11 (5 deny · 1 ask · 5 allow)
MCP servers: 5 (4 stdio · 1 remote)
Risk findings: 9 (1 critical · 6 high · 1 medium · 1 low)
Threat scenarios: 4 (S1-supply-chain-to-exfil ×1 (critical), S2-gating-collapse ×1 (critical), S3-hook-injection-chain ×1 (high), S4-unreviewed-project-takeover ×1 (high))
```

With no snapshot yet, the dashboard renders a bundled demo fixture (a deliberately risky posture) and says so. `npm test` runs the executable security requirements SR1–SR5 (read-only, redaction, no egress, interpretation honesty, tamper evidence) — the same suite CI runs.

## What it is — and is not

Using the layer taxonomy from our [landscape research](docs/research/aiagentaccesscontrollandscape.md):

| Layer | Role | AgentLens? |
|---|---|---|
| L0 | Native platform controls (the configs agents actually obey) | **Read as input** |
| L1 | In-path gateways & sandboxes (the only layer that blocks) | ✗ Not this |
| L2 | Governance & posture (discover, map, score) | **✓ This — and honestly labeled as such** |

AgentLens **never enforces, never modifies a config, never sits in the request path, and never sends data anywhere**. The landscape doc's core critique of the L2 market is vendors marketing observation as enforcement; AgentLens's design principle is the opposite: observe-only, and say so on every screen.

It targets the whitespace the research identifies: individual/prosumer tooling ("nobody has built the Little Snitch for AI agents" — this is the read-only telescope half of that idea) and permission-level audit visibility.

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
