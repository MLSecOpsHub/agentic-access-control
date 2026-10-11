import { promises as fs } from "fs";
import { createRequire } from "module";
import path from "path";
import { fileURLToPath } from "url";
import { generateLab } from "./qa/lab";
import { launch, type Agent } from "./qa/launchers";
import { supervise, type Proc } from "./qa/proc";
import { labPaths, RECIPES, recipeDir } from "./qa/recipes";
import { verifyLab } from "./qa/verify";

// QA dispatcher: `npm run qa -- <command>`. All commands keep AgentLens data in
// the lab's own data dir (AGENTLENS_DATA_DIR) so your real snapshots are never
// mixed with lab runs. docs/testing-qa-lab.md walks through the workflow.

const require = createRequire(import.meta.url);
const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const DEFAULT_LAB = path.join(REPO_ROOT, "local", "qa-lab");
const depBin = (pkg: string, rel: string) => path.join(path.dirname(require.resolve(`${pkg}/package.json`)), rel);
const TSX = depBin("tsx", "dist/cli.mjs");
const NEXT = depBin("next", "dist/bin/next");

const HELP = `AgentLens QA lab — npm run qa -- <command> [options]

  lab [--reset]                 generate/refresh the lab under local/qa-lab (--reset wipes projects/ and home/)
  collect [--isolated]          snapshot the lab projects into the lab data dir (live: your real HOME; --isolated: lab home)
  dev [--port <n>]              dashboard on 127.0.0.1 reading the lab data dir, auto-refreshing
  watch [--isolated] [--poll <sec>] [--keep <n>]
                                re-collect lab projects whenever a config changes (default --keep 50)
  up [--port <n>] [--isolated]  dev + watch together (Ctrl-C stops both)
  verify [--lab <dir>]          generate a fresh lab in a temp dir and assert every recipe (exit 1 on mismatch)
  claude <recipe> [--isolated] [--no-telemetry] [--no-trace] [--reads] [--port <n>] [-- <claude args>]
                                open Claude Code in a recipe; telemetry → /live and session-trace hook → /sessions
                                (both per-process; --reads adds file reads to the trace)
  reset-data                    delete the lab's snapshots and observed events
  recipes                       list recipe ids

Options: --lab <dir> (default local/qa-lab). Live mode is the default: real user-tier
config + lab projects. Nothing here writes agent configuration (SR1) or leaves the machine (SR3).`;

interface Flags {
  lab: string;
  isolated: boolean;
  reset: boolean;
  port: number;
  poll: number | null;
  keep: number;
  telemetry: boolean;
  trace: boolean;
  reads: boolean;
  positional: string[];
  passthrough: string[];
}

function parse(argv: string[]): Flags {
  const f: Flags = { lab: DEFAULT_LAB, isolated: false, reset: false, port: 3000, poll: null, keep: 50, telemetry: true, trace: true, reads: false, positional: [], passthrough: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--") {
      f.passthrough = argv.slice(i + 1);
      break;
    } else if (a === "--lab") f.lab = path.resolve(argv[++i] ?? "");
    else if (a === "--isolated") f.isolated = true;
    else if (a === "--reset") f.reset = true;
    else if (a === "--no-telemetry") f.telemetry = false;
    else if (a === "--no-trace") f.trace = false;
    else if (a === "--reads") f.reads = true;
    else if (a === "--port") f.port = Number(argv[++i]);
    else if (a === "--poll") f.poll = Number(argv[++i]);
    else if (a === "--keep") f.keep = Number(argv[++i]);
    else if (a.startsWith("-")) fail(`unknown option ${a}`);
    else f.positional.push(a);
  }
  return f;
}

function fail(msg: string): never {
  console.error(`qa: ${msg}\n`);
  console.error(HELP);
  process.exit(2);
}

function labEnv(f: Flags, extra: Record<string, string> = {}): NodeJS.ProcessEnv {
  const lab = labPaths(f.lab);
  const env: NodeJS.ProcessEnv = { ...process.env, AGENTLENS_DATA_DIR: lab.data, NEXT_TELEMETRY_DISABLED: "1", ...extra };
  if (f.isolated) Object.assign(env, { HOME: lab.home, USERPROFILE: lab.home, CODEX_HOME: lab.codexHome });
  return env;
}

async function ensureLab(f: Flags) {
  const lab = labPaths(f.lab);
  try {
    await fs.access(path.join(lab.root, "lab.json"));
  } catch {
    console.error(`qa: no lab at ${lab.root} — generating it first`);
    await generateLab(lab.root);
  }
  return lab;
}

const recipeDirs = (lab: ReturnType<typeof labPaths>) => RECIPES.map((r) => recipeDir(lab, r.id));

function run(cmd: string, args: string[], env: NodeJS.ProcessEnv): Promise<number> {
  return new Promise((resolve) => {
    const { spawn } = require("child_process") as typeof import("child_process");
    const child = spawn(cmd, args, { stdio: "inherit", env });
    for (const sig of ["SIGINT", "SIGTERM"] as const) process.on(sig, () => child.kill(sig));
    child.on("exit", (code) => resolve(code ?? 0));
  });
}

async function main(): Promise<number> {
  const [cmd, ...rest] = process.argv.slice(2);
  if (!cmd || cmd === "-h" || cmd === "--help") {
    console.log(HELP);
    return 0;
  }
  const f = parse(rest);

  switch (cmd) {
    case "lab": {
      const m = await generateLab(f.lab, { reset: f.reset });
      console.log(`qa: lab ${f.reset ? "reset" : "refreshed"} at ${m.lab.root} — ${m.recipes.length} recipes, ${m.owned.length} files. Start with: npm run qa -- up`);
      return 0;
    }
    case "recipes":
      for (const r of RECIPES) console.log(`${r.id.padEnd(30)} ${r.purpose}`);
      return 0;
    case "collect": {
      const lab = await ensureLab(f);
      return run(process.execPath, [TSX, path.join(REPO_ROOT, "collectors", "collect.ts"), ...recipeDirs(lab)], labEnv(f));
    }
    case "dev": {
      const lab = await ensureLab(f);
      console.error(`qa: dashboard → http://127.0.0.1:${f.port} (lab data: ${lab.data}, auto-refresh 5s)`);
      return run(process.execPath, [NEXT, "dev", "-H", "127.0.0.1", "-p", String(f.port)], labEnv(f, { AGENTLENS_AUTO_REFRESH: "5" }));
    }
    case "watch": {
      const lab = await ensureLab(f);
      const args = [TSX, path.join(REPO_ROOT, "collectors", "watch.ts"), ...recipeDirs(lab), "--keep", String(f.keep)];
      if (f.poll) args.push("--poll", String(f.poll));
      return run(process.execPath, args, labEnv(f));
    }
    case "up": {
      const lab = await ensureLab(f);
      console.error(`qa: dashboard → http://127.0.0.1:${f.port} · watching ${RECIPES.length} recipes · lab data: ${lab.data}`);
      const procs: Proc[] = [
        { name: "dev", cmd: process.execPath, args: [NEXT, "dev", "-H", "127.0.0.1", "-p", String(f.port)], env: labEnv(f, { AGENTLENS_AUTO_REFRESH: "5" }) },
        { name: "watch", cmd: process.execPath, args: [TSX, path.join(REPO_ROOT, "collectors", "watch.ts"), ...recipeDirs(lab), "--keep", String(f.keep), ...(f.poll ? ["--poll", String(f.poll)] : [])], env: labEnv(f) },
      ];
      return supervise(procs);
    }
    case "verify": {
      const { ok, lines } = await verifyLab(f.positional[0] ? path.resolve(f.positional[0]) : undefined);
      console.log(lines.join("\n"));
      console.log(ok ? "qa verify: all expectations hold" : "qa verify: FAILED");
      return ok ? 0 : 1;
    }
    case "claude":
    case "gemini":
    case "codex": {
      const lab = await ensureLab(f);
      const id = f.positional[0];
      if (!id) fail(`usage: ${cmd} <recipe>  (ids: ${RECIPES.map((r) => r.id).join(", ")})`);
      if (!RECIPES.some((r) => r.id === id)) fail(`unknown recipe "${id}" — run: npm run qa -- recipes`);
      return launch(cmd as Agent, { recipeDir: recipeDir(lab, id), lab, port: f.port, telemetry: f.telemetry, isolated: f.isolated, args: f.passthrough, trace: f.trace ? { port: f.port, reads: f.reads } : null });
    }
    case "reset-data": {
      const lab = labPaths(f.lab);
      for (const d of ["snapshots", "observed"]) await fs.rm(path.join(lab.data, d), { recursive: true, force: true });
      await fs.mkdir(path.join(lab.data, "snapshots"), { recursive: true });
      console.log(`qa: cleared ${lab.data}/{snapshots,observed}`);
      return 0;
    }
    default:
      fail(`unknown command "${cmd}"`);
  }
}

main().then(
  (code) => process.exit(code),
  (err) => {
    console.error("qa failed:", err instanceof Error ? err.message : String(err));
    process.exit(2);
  },
);
