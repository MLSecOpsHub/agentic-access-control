# Testing Guide — QA Lab & Watch Mode

How to exercise every AgentLens feature against **real local agent sessions** without touching your real snapshots or agent configuration. Companion to [poc-guide.md](poc-guide.md) (fixture tour) and [testing-live-tracking.md](testing-live-tracking.md) (`/live`).

## What the lab is

`npm run qa -- lab` generates `local/qa-lab/` (gitignored):

| Path | Contents | Who writes it |
|---|---|---|
| `projects/<recipe>/` | One disposable project per feature — `.claude/`, `.mcp.json`, `.gemini/`, `.codex/`, `.cursor/`, `.vscode/` fixtures, stub `tools/*.js` servers that exit immediately, a `.git` marker (so the Claude Code collector's git-root walk-up stops there), and a **`QA.md` card** | AgentLens's generator; then **your agent**, when you open a session there |
| `home/` | An isolated HOME for deterministic runs: finding-free user-tier configs for Claude Code, Gemini CLI and Codex CLI, `~/.claude.json` project entries (trust decisions, legacy `allowedTools`, `.mcp.json` approvals), `~/.gemini/trustedFolders.json`, `~/.codex/config.toml` with a trusted project | the generator only |
| `data/` | Lab snapshots and observed events — `AGENTLENS_DATA_DIR` for every `qa` command, separate from your real `data/` | AgentLens (`collect`/`watch`/receiver) |

Everything under `local/qa-lab/` is AgentLens-owned **test data**. SR1 is unchanged: AgentLens never writes agent configuration; the generator writes only the files listed in `lab.json`, so anything your agent adds there (credentials, `settings.local.json`) survives `qa lab`. `qa lab --reset` wipes `projects/` and `home/`.

## Two modes

- **Live (default).** Your real HOME + the lab projects. Open a real session in a recipe; Claude Code records trust and `.mcp.json` approvals in your real `~/.claude.json` under the lab path, and the collector shows exactly that. This is the mode for "does my change behave with a real session?". Caveat on every card: your real user tier merges into each project instance.
- **Isolated (`--isolated`, and always for `verify`).** `HOME`, `USERPROFILE` and `CODEX_HOME` point at `home/`. Deterministic, matches the cards' expectations, and the only way to exercise Gemini/Codex here if those CLIs are not installed. A real `claude` launched isolated has no credentials and will onboard into the lab home — the launcher warns.

## Quickstart

```bash
npm run qa -- lab                         # generate (idempotent)
npm run qa -- up                          # dashboard on http://127.0.0.1:3000 + watch, both on the lab data dir
# second terminal:
npm run qa -- claude s4-unreviewed-project   # real Claude Code in the recipe, telemetry → /live
# decline the .mcp.json prompt, exit → watch writes a snapshot within ~1 s → Overview drift, S4 gone from /threat-model
npm run qa -- verify                      # deterministic self-check of every recipe (isolated home)
```

`npm run qa -- recipes` lists the recipes; each `projects/<id>/QA.md` says what it triggers, what to do in a session, and what should change afterwards.

## Commands

| Command | What it does |
|---|---|
| `lab [--reset]` | Generate/refresh the lab; `--reset` wipes `projects/` and `home/` (never `data/`) |
| `collect [--isolated]` | One snapshot of the lab projects into `local/qa-lab/data` |
| `dev [--port n]` | `next dev` on 127.0.0.1 reading the lab data dir, with `AGENTLENS_AUTO_REFRESH=5` |
| `watch [--isolated] [--poll sec] [--keep n]` | `agentlens watch` over the lab projects (default `--keep 50`) |
| `up [--port n] [--isolated]` | `dev` + `watch` under one supervisor; Ctrl-C stops both |
| `verify [<lab dir>]` | Generates a fresh lab in a temp dir (or uses the given one), collects it isolated, asserts each recipe's findings, scenarios and notes; exit 1 on mismatch. Also runs in CI (`tests/qa-lab.test.ts`) |
| `claude <recipe> [--isolated] [--no-telemetry] [--no-trace] [--reads] [--port n] [-- args]` | Opens Claude Code in the recipe directory with the `/live` telemetry env **and** the session-trace hook settings (`--settings`, per process) — both on by default; `--reads` adds file reads to the trace. `gemini` / `codex` share the launcher interface and are planned next |
| `reset-data` | Deletes the lab's `data/snapshots` and `data/observed` |

## Watch mode (`agentlens watch`, also outside the lab)

`npm run watch [-- roots…]` / `agentlens watch` re-runs the read-only collection whenever an allowlisted config file changes — `~/.claude.json`, `~/.claude/settings*.json`, `~/.gemini/*`, `$CODEX_HOME/*.toml`, and per project `.mcp.json`, `mcp.json`, `.claude/`, `.gemini/`, `.codex/`, `.vscode/`, `.cursor/` — debounced, and writes a snapshot **only when the content fingerprint changed** (a live Claude session rewrites `~/.claude.json` constantly; most ticks log `unchanged`). `--keep n` prunes its own oldest snapshot files beyond `n` (≥ 2, so drift keeps a previous); `--poll sec` adds a timer for filesystems where `fs.watch` is unreliable and for nested `mcp.json` manifests. With `AGENTLENS_AUTO_REFRESH=<seconds>` set on the dashboard server, every page re-reads the data dir on that interval.

## Recipes

| Recipe | Exercises | Expected (isolated) |
|---|---|---|
| `s1-supply-chain` | unpinned `npx -y` server + credential env + bare `Bash` allow, approval recorded | H2, H3 high, H4; **S1 critical** |
| `s2-gating-collapse` | `bypassPermissions` + hook; legacy `allowedTools` note | H1; **S2 critical** |
| `s3-hook-chain` | `curl … \| sh` hook + `Write` allow + sandbox off | H2, H6, H7; **S3 high** |
| `s4-unreviewed-project` | project `Bash(*)` + `.mcp.json` server with no recorded approval; trust declined | H2; **S4 high** |
| `s5-credential-concentration` | two credential servers + `Read(~/.aws/**)` | H4 ×2; **S5 medium** |
| `reduced-oversight` | `acceptEdits` in the local tier, `skipDangerousModePermissionPrompt`, `additionalDirectories`, sandbox `excludedCommands` | H8 low, H9 low, H6 low; mode-semantics note |
| `approved-by-setting` | S4 near-miss: same allow + server as `s4`, but `enableAllProjectMcpServers` in the project settings and the folder trusted | H2 only; no S4 (approval honoured once trusted) |
| `gemini-project` | `tools.allowed` shell, trusted unpinned server, `TRUST_FOLDER` rule | H2, H3, H4; **S1 high, S4 high** |
| `codex-project` | `never` + `danger-full-access`, `uvx` server, trusted project | H1, H3, H4, H6; **S1 high, S2 high** |
| `generic-mcp` | `.cursor/mcp.json` (pinned, credential) + `.vscode/mcp.json` | 2 instances; H3 medium, H4 |
| `clean-control` | scoped allows, deny, sandbox on | instance only |
| `drift-playground` | quiet project for `claude mcp add`, edits, drift | instance only |

The user tier of the isolated home is itself finding-free and asserted so (`claude-code:user`, `gemini-cli:user`, `codex-cli:user`).

## Safety notes

- `s2` and `s3` are collect/verify recipes. A real session opened there runs with prompts bypassed / sandbox off under **your** account — the cards say to give it no tasks. The `s3` hook's matcher never matches a real tool.
- Live mode leaves entries keyed by the lab paths in your real `~/.claude.json`; remove them when you are done (discovery skips directories that no longer exist).
- The launcher sets exporter env vars on one child process and names only the loopback receiver (SR3). AgentLens never writes telemetry settings (SR1).
- Cards obey the scenario wording contract; `tests/qa-lab.test.ts` asserts the banned-phrase list against every card.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `verify` fails after a collector/heuristic change | the recipe expectation in `scripts/qa/recipes.ts` is now wrong, or the change altered semantics — decide which, deliberately |
| watch never logs a snapshot after an edit | the file is outside the allowlist (nested `mcp.json`) → use `--poll`; or the content did not change (`unchanged`) |
| a recipe shows your own rules/servers | live mode merges your real user tier; use `--isolated` or compare with `verify` |
| `claude` opened in the recipe sees no `.mcp.json` prompt | the project path already has a recorded decision in your real `~/.claude.json` |
| dashboard shows the bundled fixture | the lab data dir has no snapshot yet — run `qa collect` or wait for watch's first tick |

## Session trace — what to look for on `/sessions`

With the dashboard running (`AGENTLENS_AUTO_REFRESH=5 npm run dev`) and a traced session open (`npm run qa -- claude drift-playground`, or `claude --settings "$(npm run -s trace -- hook-settings)"` anywhere):

| Do this in the traced session | Expect on `/sessions` (within one refresh) |
|---|---|
| Run `rm -rf node_modules` or `git status` | Shell count rises; the line under it reads `fs-destructive ×1` / `vcs ×1`; **no** O6 — in-tree deletes and VCS reads are facets only |
| Run `sudo true` or `chmod 777 /tmp/x` | Observed findings gains `O6 ×1` (bold = high when the exit code was 0 under `sudo`); the session page's "Shell commands by class" shows the command under `privileged` with its exit code and an `O6` tag |
| Press Shift+Tab, then run any command | Mode cell shows `default → auto` (or the modes you cycled) with `changed ×n`; the session page header lists the transition time and the timeline gains a Mode column |
| Write a file | Writes count links to `#files`; the sub-line names the path, `⚠ agent config` when it is a settings file (O1 fires too) |
| Exit the session | Disk flips from `pending` to the `+a ~m ·t -r` delta — only if the recipe directory is a scanned root (`AGENTLENS_TRACE_ROOTS` or a project already in a snapshot) |

Mode `—` means no event of that session carried a `permission_mode`: the vendor omits it on `SessionStart`, and events recorded before 2026-10-12 did not store it on tool events. Column meanings live in the collapsible "What the columns mean" legend on the page and in [session-trace.md](session-trace.md) §10.
