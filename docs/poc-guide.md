# AgentLens PoC — Features & Local Test Walkthrough

A concise tour of what the proof-of-concept does today and how to exercise every feature on your machine. Deep dives: [product-spec.md](product-spec.md) (requirements), [security-architecture.md](security-architecture.md) (SR1–SR5), [collectors.md](collectors.md) (file locations & heuristics).

## Current featureset

| Feature | What it does | Where |
|---|---|---|
| Agent instance inventory | Discovers agent installs as (platform × scope) instances — Claude Code and Gemini CLI, plus generic `mcp.json` manifests; Codex CLI is a spec'd stub | Overview |
| Configured permissions | Merged allow/ask/deny declarations per instance, ordered by the documented evaluation semantics (deny → ask → allow across all tiers), each with source file + settings level (managed/user/project/local) | `/agents/<id>` |
| MCP server inventory | Every configured server: transport, command/URL, env **key names** (values redacted at collection), declaring file | `/mcp` |
| Sandbox & hook posture | Sandbox flags (warning-styled when disabled/escapable) and redacted hook command previews | `/agents/<id>` |
| Risk findings | Heuristics: bypass modes, wildcard allows, `npx -y`/`uvx`-launched servers, credential env keys, disabled sandboxes, pipe-to-shell hooks | `/findings` |
| Threat scenarios | Composes collected posture into cited attack-path scenarios (v1: S1 supply-chain → exfil, S2 gating collapse); each precondition cites its source file, with OWASP ASI/STRIDE tags and severance hints | `/threat-model`, `/agents/<id>` |
| Snapshot drift | Rule/server-level diff between the two newest snapshots | Overview banner |
| Integrity & honesty rails | SHA-256 tamper-evidence per snapshot, snapshot-age display, permanent "interpretation, not enforcement" banner | every page |

Everything is read-only and local-only: no config writes, no network egress, dashboard bound to 127.0.0.1.

## Prerequisites

- Node.js ≥ 20 and npm (tested on Node 20 / Linux; macOS works, Windows via WSL2)
- No accounts, keys, or network services needed

## Step-by-step local test

### 1. Install and start

```bash
npm install
npm run dev
```

Open **http://127.0.0.1:3000**. With no snapshots collected yet, the dashboard renders the bundled **sample fixture** (a deliberately risky demo posture) and says so in a notice.

**Check:** four stat tiles (3 instances, 9 rules, 4 MCP servers, 8 findings); the orange "Read-only interpretation, not enforcement" banner; active page highlighted in the nav.

### 2. Tour the fixture

1. **Overview** — the `claude-code · project` instance shows a red `bypassPermissions` mode badge and 7 findings.
2. Click it → **instance detail**: 4 configured permission declarations in evaluation order (denies first) with per-rule source file, an amber (disabled) sandbox card, one hook whose command pipes `curl` to `sh`, and 2 MCP servers.
3. **MCP servers** — note `github` runs via `npx -y` and lists `GITHUB_PERSONAL_ACCESS_TOKEN` as an env *key* (its value never reached the snapshot).
4. **Findings** — 8 findings from `critical` (H1 bypass mode) down to `low` (H7 hook), each with post-redaction evidence and provenance.
5. **Threat scenarios** — the fixture's project instance triggers S1 and S2; expand one to see every precondition with its source file, the OWASP ASI / STRIDE tags, and the severance hint naming which single declaration breaks the path. Note the verbatim caveat: these are configured declarations composed by AgentLens, not an observed attack.

### 3. Snapshot your real machine

```bash
npm run collect              # scans user-level configs + current directory
# or: npm run collect -- ~/myproject ~/otherproject
```

Refresh the dashboard — it now shows your real posture (the fixture notice disappears). The snapshot lives in `data/snapshots/<timestamp>.json` (gitignored).

**Check (SR1, read-only):** your `~/.claude` files' mtimes are untouched — `stat -c '%y' ~/.claude/settings.json` before/after.

### 4. See drift

```bash
# add a harmless rule to ~/.claude/settings.json, e.g. in permissions.allow:
#   "WebFetch(domain:example.com)"
npm run collect
```

Refresh the Overview: a drift banner lists the added rule with its instance. Remove the rule and collect again to see it as removed. (Drift always compares the two newest snapshots.)

### 5. Verify the security rails

```bash
# SR2 — no secrets in snapshots (empty output = pass):
grep -E 'sk-[A-Za-z0-9]|AKIA|ghp_|Bearer [A-Za-z0-9]' data/snapshots/*.json

# SR5 — tamper evidence: edit any value inside the newest snapshot file by hand,
# refresh the dashboard → red "Integrity warning" appears on every page.
# Delete the edited file and re-run `npm run collect` to recover.

# SR3 — local only: the server listens on 127.0.0.1 only:
ss -tln | grep 3000
```

Type-safety check for contributors: `npm run typecheck`.

## Known PoC limits

- The Codex CLI collector is a stub (spec in [collectors.md](collectors.md) §3) — its TOML configs are not yet read.
- Gemini CLI: TOML policy files, `trustedFolders.json` and the system-defaults file are not read; the YOLO flag is invisible to any filesystem collector. Each is stated as a mapping note on the instance.
- Session-scoped permission grants stored outside settings files are not collected yet.
- Rendered precedence is an interpretation (SR4) — the platform's own evaluator remains ground truth.
- Redaction is pattern-based; novel secret formats can slip through (bias is to over-redact).

## File map

```
app/            dashboard pages (Overview, /agents/[id], /mcp, /findings, /threat-model, /live)
collectors/     read-only collectors + `npm run collect` orchestrator
lib/            zod schema, redaction, heuristics, scenario catalog + engine, hashing, snapshot loader
data/fixtures/  bundled sample snapshot (committed)
data/snapshots/ your machine's snapshots (gitignored)
docs/           specs, architecture, threat model, this guide
```
