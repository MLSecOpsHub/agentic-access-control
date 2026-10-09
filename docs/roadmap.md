# AgentLens — Roadmap

## Phase 1 — Local-first MVP (this repo, now)

- Claude Code collector (full), Gemini CLI collector (settings tiers; shipped 2026-10-09) + generic MCP collector; Codex CLI collector spec'd and stubbed ([collectors.md](collectors.md) §3–4).
- Default project-root discovery from `~/.claude.json` `projects` (2026-10-09) — `npm run collect` with no arguments covers every directory Claude Code has been launched from.
- Threat scenarios S1–S4, `/share` counts-only card, `agentlens` CLI (`npx @mlsecopshub/agentlens scan`) — 2026-10-09.
- Dashboard: overview, per-instance configured permissions, MCP inventory, findings, drift.
- SR1–SR5 implemented and tested per [security-architecture.md](security-architecture.md).

**Exit criteria:** the four success criteria in [product-spec.md](product-spec.md) §8.

## Phase 1.5 — Hardening & platform completion

- Implement the Codex CLI collector (TOML parser via T10 review); Gemini CLI follow-ups: TOML policy files, `trustedFolders.json`; conformance fixtures per platform version (T5 mitigation).
- Session-state stores (per-session "always allow" grants) added to collector allowlists where locations are documented.
- Snapshot signing (age/minisign key) upgrading SR5 from tamper-evident to tamper-resistant against T8.
- Watch mode: fs-watch on allowlisted config paths → auto-collect on change (still read-only; turns drift into near-real-time).

## Phase 2 — Cloud connectors (read-only, per landscape §1)

Same observe-only contract, new collector class hitting admin APIs with **read-only credentials** — the SR set extends (SR6: least-privilege API scopes; SR7: cloud secrets never stored, OS keychain only):

| Connector | Source | Reads |
|---|---|---|
| Entra Agent ID | Microsoft Graph | Agent identities, Conditional Access coverage, sponsor chains |
| AWS AgentCore | AWS APIs | AgentCore Identity workloads, IAM policies, CloudTrail data-event config (flag the off-by-default gap) |
| Google Workspace | Admin SDK | AI control center toggle state per OU |
| OpenAI Enterprise | Compliance/admin API | Connector/app enablement, per-action scopes |
| Anthropic Enterprise | Compliance API | Admin/resource events (note: excludes inference content — display that caveat, don't paper over it) |

Prereq before any connector ships: full threat-model re-run — cloud creds and any remote data path break B4's "no listener, no egress" assumptions (threat model §5).

## Phase 3 — Fleet aggregation (small teams, P2)

- Merge snapshots from multiple machines (`machineId` already in schema).
- Transport candidates, in order of preference for the trust model: git repo of signed snapshots (no server at all) → self-hosted collector push. Never a hosted SaaS ingest by default.
- Dashboard auth becomes mandatory the moment a snapshot can originate off-machine (T6).
- Team policy diff: "this repo's checked-in `.claude/settings.json` differs from team baseline."

## Ideas parking lot (unscheduled)

- Heuristic packs as data (user-extensible rules, à la `agent-audit`'s 296 rules). *Partially promoted: the threat-scenario catalog ([threat-scenarios.md](threat-scenarios.md) §4) is the first data-driven rule set; user-extensible packs remain parked.*
- Export findings as SARIF for code-scanning UIs.
- ~~Claude Code plugin/hook that surfaces "AgentLens: 2 new findings" inside the agent session~~ **Promoted** into the threat-scenario spec ([threat-scenarios.md](threat-scenarios.md) §8.3) — display only, last in that spec's sequencing.
- **Threat scenario engine** — spec'd 2026-09-05 in [threat-scenarios.md](threat-scenarios.md); **v1-static (S1/S2) shipped 2026-10-09**. Remaining: S3–S5, `declared+observed` confidence after the Step 6 remodel, display-only plugin (§8.3).

## Permanent non-goals

Restated from [product-spec.md](product-spec.md) §6 because roadmaps attract scope creep:

1. **No enforcement.** If we ever want to block a tool call, that is an L1 product (gateway/sandbox/hook) with a different threat model — a sibling repo, not a feature flag here. The landscape doc's L1/L2 boundary stays load-bearing.
2. **No config mutation** — not even "fix this finding for me." AgentLens links to the file and line; the user edits.
3. **No off-device telemetry or phone-home behavior.** AgentLens may optionally ingest Claude Code OpenTelemetry events through a loopback-only endpoint selected by the user; normalized data remains local, and AgentLens never configures an exporter, writes telemetry settings, or installs hooks without explicit user action. The aggregated permission map and observed-event history (assets A1/A5) never leave the user's custody by default. *(Wording revised 2026-08-13 — the previous absolute "no telemetry" conflated off-device phone-home, still banned, with user-directed local ingestion of vendor events; see `local/live-tracking-final-plan.md`.)*
