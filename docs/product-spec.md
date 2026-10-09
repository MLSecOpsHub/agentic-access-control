# AgentLens — Product Specification (v1, local-first)

Status: draft for MVP build · Owner: mlsecopshub · Last updated: 2026-08-13

## 1. Problem

AI agents with tool access are configured by scattered, overlapping, mutually-shadowing files: user settings, project settings, local overrides, managed policies, MCP manifests, hooks, sandbox flags. No single view answers "what can my agents touch right now?" The [landscape research](research/aiagentaccesscontrollandscape.md) surveyed ~100 products and found the individual/user side of this market is "almost entirely hobby-grade" (§2e) and names prosumer tooling as whitespace #2. Enterprise L2 vendors solve this for clouds and SaaS; nobody renders the *local* permission surface.

## 2. Product statement

> A read-only, local-only dashboard that inventories every AI agent instance on a machine, shows each one's configured permissions with file-level provenance, inventories configured MCP servers, flags risky posture, and diffs snapshots over time.

Positioning per the landscape taxonomy: **deliberately L2 (observe-only)**. We adopt the doc's own evaluation question — *"does this product see the tool call before it executes, or does it read logs afterward?"* — and answer honestly: neither; we read **configuration**, ahead of time. That distinction appears in the UI (SR4 banner).

## 3. Personas

| Persona | Situation | Primary question |
|---|---|---|
| **P1 — Agent power user** | Runs Claude Code + 1–2 other CLIs daily, has accumulated permission rules and MCP servers over months | "What have I actually allowed, and where did each rule come from?" |
| **P2 — Small-team lead** | 3–10 devs using coding agents on shared repos; no IAM team, no budget for enterprise governance | "Which repos have `settings.local.json` overrides or unvetted MCP servers checked in?" |
| **P3 — Security-curious self-hoster** | Treats agents as untrusted-by-default; reads the OWASP Agentic Top 10 | "Show me drift: what changed since last week, and is anything running unsandboxed?" |

## 4. Jobs to be done

1. **Inventory** — "List every agent instance (platform × scope) on this machine and the config files that define it."
2. **Configured permissions** — "For an instance, show the merged allow/ask/deny declarations across all settings tiers, each rule traceable to its source file." (The evaluation-order view returned with hardening Step 5, backed by vendor-conformance tests.)
3. **MCP surface** — "List every configured MCP server: transport, command/URL, env key names, declaring file."
4. **Risk** — "Flag posture that a security reviewer would flag: bypass modes, wildcard allows, unpinned `npx -y` servers, secret-bearing env, disabled sandboxes."
5. **Drift** — "Diff the two most recent snapshots at rule level."

## 5. MVP feature list

| # | Feature | Notes |
|---|---|---|
| F1 | Agent instance inventory | Platforms: Claude Code (full), Gemini CLI (settings tiers, tools allow/exclude, approval mode, sandbox, MCP, hooks — [collectors.md](collectors.md) §4), generic `mcp.json`; Codex CLI spec'd, stubbed |
| F2 | Configured-permission view | Rules table per instance: effect, matcher, source file, settings level — ordered by documented evaluation semantics (deny → ask → allow across tiers), still declarations rather than proof of enforcement (SR4) |
| F3 | MCP server inventory | Env **key names only** — values redacted at collection (SR2) |
| F4 | Sandbox & hook posture | Sandbox enabled/escape flags; hook event + truncated command preview |
| F5 | Risk findings | Heuristics (see [collectors.md](collectors.md) §6; H5 retired) with severity + evidence |
| F6 | Snapshot drift | Rule-level added/removed/changed between two newest snapshots; content hashes shown |
| F7 | Interpretation banner | Persistent SR4 caveat on every page |
| F8 | Threat scenarios | Catalog S1–S4 composing findings into cited paths with severance hints ([threat-scenarios.md](threat-scenarios.md)) |
| F9 | Share card | Counts-only pasteable summary (`/share`), no identifying strings by tested contract |
| F10 | CLI | `npx @mlsecopshub/agentlens scan` — collect + serve, data outside the package |

## 6. Non-goals (v1) and permanent non-goals

- **Never (permanent):** enforcement, config mutation, sitting in the request path, telemetry/phone-home. If we ever want enforcement, that is a different product at L1 — see roadmap.
- **Not in v1:** cloud admin-API connectors (Entra Agent ID, AWS AgentCore, Workspace AI controls, OpenAI Enterprise — Phase 2), multi-machine aggregation (Phase 3), runtime log analysis, Windows support beyond WSL2, authentication on the dashboard (localhost-only instead).

## 7. Competitive positioning (nearest neighbors from the landscape §2e)

| Tool | Overlap | Difference |
|---|---|---|
| `Tonyhzk/cc-permission-manager` (30★) | GUI over Claude Code permission configs | It is read-**write** and Claude-only; AgentLens is read-only, covers Claude Code + Gemini CLI + generic MCP manifests, adds risk, threat scenarios + drift |
| `delexw/claude-code-trace` (321★) | Visibility into agent activity | Trace reads session *logs* (what happened); AgentLens reads *permissions* (what could happen) |
| `scadastrangelove/agent-audit` (15★) | Local forensic audit, rule-based | Point-in-time forensics CLI; AgentLens is a continuously refreshable posture dashboard |
| `karanb192/claude-code-hooks` (455★) | Safety tooling for individuals | Hooks act in-path (L1-ish); complementary — AgentLens would *display* installed hooks |
| Enterprise L2 (Obsidian, Silverfort, Token…) | Permission mapping | Cloud/SaaS surface, sales-motion, agentless via admin APIs; none read local dev-machine configs |

## 8. Success criteria (MVP)

- Fresh clone → `npm install && npm run dev` renders fixture data in < 2 min, zero config.
- `npm run collect` on a real machine with Claude Code produces a valid snapshot (zod-clean) with zero writes outside `data/snapshots/`.
- A secret planted in an MCP `env` block never appears in a snapshot or the DOM.
- A rule added to `~/.claude/settings.json` between two collects appears in the drift view.

## 9. Open questions

- Should project discovery scan a configured root list or walk `$HOME` (slow, privacy-heavier)? MVP: explicit roots via CLI args, default cwd.
- Version detection per platform (parse `--version` output?) — MVP: best-effort, nullable field.
- ~~Packaging: npm package vs. clone-and-run. MVP: clone-and-run.~~ Resolved 2026-10-09: `@mlsecopshub/agentlens` npm package with a `bin` (ships the production build; `next` pinned exactly so `next start` matches the shipped `.next`), clone-and-run still works.
