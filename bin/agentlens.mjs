#!/usr/bin/env node
import { spawn, spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { createRequire } from "node:module";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

// `agentlens` CLI — the npx entry point. Same read-only contract as the repo
// scripts: collect writes only under the data dir; the dashboard binds
// 127.0.0.1 and makes no outbound requests (NEXT_TELEMETRY_DISABLED=1).
// Data lives OUTSIDE the package (XDG data dir by default) so an npx install
// never writes into itself.

const require = createRequire(import.meta.url);
const PKG_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

const HELP = `agentlens — read-only permission observatory for local AI agents

Usage:
  agentlens scan [root ...]     collect, then serve the dashboard
  agentlens collect [root ...]  read local agent configs into a snapshot
  agentlens serve               serve the dashboard on 127.0.0.1

Roots: project directories to scan. With none given: the current directory
plus every project listed in ~/.claude.json (where Claude Code has run).

Options:
  --port <n>        dashboard port (default 3000)
  --open            open the dashboard in a browser once it is up
  --data-dir <dir>  where snapshots live
                    (default $XDG_DATA_HOME/agentlens or ~/.local/share/agentlens;
                     also AGENTLENS_DATA_DIR)
  -h, --help        this text

AgentLens never modifies agent configuration, never sits in the request
path, and never sends data anywhere. It shows configured declarations —
not proof of enforcement.`;

function parseArgs(argv) {
  const flags = { port: 3000, open: false, dataDir: null, help: false };
  const positional = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--port") flags.port = Number(argv[++i]);
    else if (a.startsWith("--port=")) flags.port = Number(a.slice("--port=".length));
    else if (a === "--open") flags.open = true;
    else if (a === "--data-dir") flags.dataDir = argv[++i];
    else if (a.startsWith("--data-dir=")) flags.dataDir = a.slice("--data-dir=".length);
    else if (a === "-h" || a === "--help") flags.help = true;
    else if (a.startsWith("-")) {
      console.error(`agentlens: unknown option ${a}\n`);
      console.error(HELP);
      process.exit(2);
    } else positional.push(a);
  }
  if (!Number.isInteger(flags.port) || flags.port < 1 || flags.port > 65535) {
    console.error("agentlens: --port must be an integer between 1 and 65535");
    process.exit(2);
  }
  return { flags, positional };
}

function defaultDataDir() {
  const xdg = process.env.XDG_DATA_HOME || path.join(os.homedir(), ".local", "share");
  return path.join(xdg, "agentlens");
}

const childEnv = (dataDir) => ({
  ...process.env,
  NEXT_TELEMETRY_DISABLED: "1",
  AGENTLENS_DATA_DIR: dataDir,
});

// Resolve a dependency's executable through Node's resolver so it works both
// in a dev clone and in an npx/global install where packages are hoisted.
const depBin = (pkg, rel) => path.join(path.dirname(require.resolve(`${pkg}/package.json`)), rel);

function collect(roots, dataDir) {
  const r = spawnSync(
    process.execPath,
    [depBin("tsx", "dist/cli.mjs"), path.join(PKG_ROOT, "collectors", "collect.ts"), ...roots],
    { stdio: "inherit", env: childEnv(dataDir) },
  );
  if (r.status !== 0) process.exit(r.status ?? 1);
}

function ensureBuild(dataDir) {
  if (existsSync(path.join(PKG_ROOT, ".next", "BUILD_ID"))) return;
  console.log("agentlens: no production build found — running `next build` once (dev clone)…");
  const r = spawnSync(process.execPath, [depBin("next", "dist/bin/next"), "build"], {
    cwd: PKG_ROOT,
    stdio: "inherit",
    env: childEnv(dataDir),
  });
  if (r.status !== 0) process.exit(r.status ?? 1);
}

async function waitFor(url, timeoutMs = 60_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(url, { redirect: "manual" });
      if (res.status < 500) return true;
    } catch {
      // not up yet
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  return false;
}

function openBrowser(url) {
  const [cmd, args] =
    process.platform === "darwin"
      ? ["open", [url]]
      : process.platform === "win32"
        ? ["cmd", ["/c", "start", "", url]]
        : ["xdg-open", [url]];
  try {
    spawn(cmd, args, { stdio: "ignore", detached: true }).unref();
  } catch {
    console.log(`agentlens: could not launch a browser — open ${url} yourself`);
  }
}

async function serve(flags, dataDir) {
  ensureBuild(dataDir);
  const url = `http://127.0.0.1:${flags.port}`;
  console.log(`agentlens: data dir   ${dataDir}`);
  console.log(`agentlens: dashboard  ${url}  (loopback only — Ctrl-C to stop)`);
  const child = spawn(
    process.execPath,
    [depBin("next", "dist/bin/next"), "start", "-H", "127.0.0.1", "-p", String(flags.port)],
    { cwd: PKG_ROOT, stdio: "inherit", env: childEnv(dataDir) },
  );
  child.on("exit", (code) => process.exit(code ?? 0));
  for (const sig of ["SIGINT", "SIGTERM"]) process.on(sig, () => child.kill(sig));
  if (flags.open && (await waitFor(url))) openBrowser(url);
}

async function main() {
  const [cmd, ...rest] = process.argv.slice(2);
  if (!cmd || cmd === "-h" || cmd === "--help") {
    console.log(HELP);
    return;
  }
  const { flags, positional } = parseArgs(rest);
  if (flags.help) {
    console.log(HELP);
    return;
  }
  const dataDir = path.resolve(flags.dataDir ?? process.env.AGENTLENS_DATA_DIR ?? defaultDataDir());

  switch (cmd) {
    case "scan":
      collect(positional, dataDir);
      await serve(flags, dataDir);
      break;
    case "collect":
      collect(positional, dataDir);
      console.log(`agentlens: data dir ${dataDir} — run \`agentlens serve\` to view`);
      break;
    case "serve":
      await serve(flags, dataDir);
      break;
    default:
      console.error(`agentlens: unknown command "${cmd}"\n`);
      console.error(HELP);
      process.exit(2);
  }
}

main().catch((err) => {
  console.error("agentlens:", err?.message ?? err);
  process.exit(1);
});
