import { promises as fs, watch as fsWatch, type FSWatcher } from "fs";
import os from "os";
import path from "path";
import { pathToFileURL } from "url";
import { contentFingerprint, rawContentFingerprint } from "../lib/hash";
import { discoverProjectRoots } from "./claude-code";
import { collectSnapshot, OUT_DIR, pruneSnapshots, writeSnapshot } from "./pipeline";

// Watch mode (roadmap Phase 1.5): re-run the read-only collection whenever an
// allowlisted agent config file changes, and write a snapshot only when the
// CONTENT changed (fingerprint excludes generatedAt), so drift stays meaningful
// and a live Claude session rewriting ~/.claude.json does not spam snapshots.
// fs.watch is read-only; the only mutations are the pipeline's own
// writeSnapshot and (opt-in, --keep) pruneSnapshots on its own files.
//
//   agentlens watch [root ...] [--poll <sec>] [--keep <n>] [--data-dir <dir>]

export interface WatchTarget {
  dir: string;
  accept: (name: string | null) => boolean;
}

const PROJECT_CONFIG_DIRS = [".claude", ".gemini", ".codex", ".vscode", ".cursor"];

// Directories to watch (non-recursive) and the file names that matter in each.
// A null name (platform could not report it) is accepted — the fingerprint
// decides whether anything actually changed.
export function buildWatchTargets(o: { home: string; codexHome: string; roots: string[] }): WatchTarget[] {
  const wanted = new Map<string, Set<string>>();
  const add = (dir: string, ...names: string[]) => {
    const abs = path.resolve(dir);
    const set = wanted.get(abs) ?? new Set<string>();
    for (const n of names) set.add(n);
    wanted.set(abs, set);
  };
  add(o.home, ".claude.json");
  add(path.join(o.home, ".claude"), "settings.json", "settings.local.json");
  add(path.join(o.home, ".gemini"), "settings.json", "trustedFolders.json");
  add(o.codexHome, "config.toml", "*.config.toml");
  for (const root of o.roots) {
    add(root, ".mcp.json", "mcp.json", ...PROJECT_CONFIG_DIRS);
    add(path.join(root, ".claude"), "settings.json", "settings.local.json");
    add(path.join(root, ".gemini"), "settings.json");
    add(path.join(root, ".codex"), "config.toml");
    add(path.join(root, ".vscode"), "mcp.json");
    add(path.join(root, ".cursor"), "mcp.json");
  }
  return [...wanted.entries()].map(([dir, set]) => {
    const exact = new Set([...set].filter((n) => !n.startsWith("*")));
    const suffixes = [...set].filter((n) => n.startsWith("*")).map((n) => n.slice(1));
    return {
      dir,
      accept: (name) => name === null || exact.has(name) || suffixes.some((s) => name.endsWith(s)),
    };
  });
}

export interface WatchOptions {
  roots: string[]; // [] → cwd + ~/.claude.json discovery, re-evaluated per tick
  outDir: string;
  pollSec: number | null;
  keep: number | null;
  debounceMs?: number;
  log?: (line: string) => void;
  signal?: AbortSignal;
}

const hhmmss = () => new Date().toISOString().slice(11, 19);

async function isDir(p: string): Promise<boolean> {
  try {
    return (await fs.stat(p)).isDirectory();
  } catch {
    return false;
  }
}

async function seedFingerprint(outDir: string): Promise<string | null> {
  try {
    const files = (await fs.readdir(outDir)).filter((f) => f.endsWith(".json")).sort();
    if (files.length === 0) return null;
    const raw = JSON.parse(await fs.readFile(path.join(outDir, files[files.length - 1]), "utf8"));
    return typeof raw === "object" && raw !== null ? rawContentFingerprint(raw as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

export async function runWatch(o: WatchOptions): Promise<void> {
  const log = o.log ?? ((line: string) => console.log(line));
  const debounceMs = o.debounceMs ?? 750;
  const home = os.homedir();
  const codexHome = process.env.CODEX_HOME ? path.resolve(process.env.CODEX_HOME) : path.join(home, ".codex");

  let last = await seedFingerprint(o.outDir);
  const watchers = new Map<string, FSWatcher>();
  let timer: NodeJS.Timeout | null = null;
  let running = false;
  let dirty = false;
  let trigger = "startup";

  const schedule = (why: string) => {
    trigger = why;
    if (timer) clearTimeout(timer);
    timer = setTimeout(() => void tick(), debounceMs);
  };

  const rearm = async () => {
    const roots = o.roots.length > 0 ? o.roots : [process.cwd(), ...(await discoverProjectRoots())];
    const targets = buildWatchTargets({ home, codexHome, roots });
    const want = new Set(targets.map((t) => t.dir));
    for (const [dir, w] of watchers) {
      if (!want.has(dir)) {
        w.close();
        watchers.delete(dir);
      }
    }
    for (const t of targets) {
      if (watchers.has(t.dir) || !(await isDir(t.dir))) continue;
      try {
        const w = fsWatch(t.dir, { persistent: true }, (_event, filename) => {
          const name = filename ? String(filename) : null;
          if (t.accept(name)) schedule(`${path.basename(t.dir)}/${name ?? "?"}`);
        });
        w.on("error", () => {
          w.close();
          watchers.delete(t.dir);
        });
        watchers.set(t.dir, w);
      } catch {
        // Unwatchable directory (platform limits): --poll still covers it.
      }
    }
  };

  const tick = async () => {
    if (running) {
      dirty = true;
      return;
    }
    running = true;
    const why = trigger;
    try {
      const { snapshot } = await collectSnapshot(o.roots);
      const fp = contentFingerprint(snapshot);
      if (fp === last) {
        log(`[watch ${hhmmss()}] ${why} → unchanged`);
      } else {
        const file = await writeSnapshot(snapshot, o.outDir);
        last = fp;
        const pruned = o.keep !== null ? await pruneSnapshots(o.outDir, o.keep) : [];
        log(
          `[watch ${hhmmss()}] ${why} → ${path.basename(file)} · ${snapshot.instances.length} instances · ${snapshot.mcpServers.length} servers · ${snapshot.findings.length} findings${pruned.length > 0 ? ` · pruned ${pruned.length}` : ""}`,
        );
      }
      await rearm();
    } catch (err) {
      // SR2: never echo error text — collector errors can carry config content.
      log(`[watch ${hhmmss()}] ${why} → collect failed (${err instanceof Error ? err.constructor.name : "error"})`);
    } finally {
      running = false;
      if (dirty) {
        dirty = false;
        schedule("coalesced");
      }
    }
  };

  await tick();
  log(
    `watch: ready — ${watchers.size} directories watched${o.pollSec ? `, polling every ${o.pollSec}s` : ""} → ${o.outDir}`,
  );
  const poll = o.pollSec ? setInterval(() => schedule("poll"), o.pollSec * 1000) : null;

  await new Promise<void>((resolve) => {
    const stop = () => {
      if (timer) clearTimeout(timer);
      if (poll) clearInterval(poll);
      for (const w of watchers.values()) w.close();
      resolve();
    };
    o.signal?.addEventListener("abort", stop, { once: true });
    process.once("SIGINT", stop);
    process.once("SIGTERM", stop);
  });
}

function usage(msg?: string): never {
  if (msg) console.error(`watch: ${msg}`);
  console.error("usage: watch [root ...] [--poll <sec>] [--keep <n>] [--data-dir <dir>]");
  process.exit(2);
}

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  const roots: string[] = [];
  let pollSec: number | null = null;
  let keep: number | null = null;
  let dataDir: string | null = null;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const value = (flag: string) => (a.startsWith(`${flag}=`) ? a.slice(flag.length + 1) : argv[++i] ?? "");
    if (a === "--poll" || a.startsWith("--poll=")) pollSec = Number(value("--poll"));
    else if (a === "--keep" || a.startsWith("--keep=")) keep = Number(value("--keep"));
    else if (a === "--data-dir" || a.startsWith("--data-dir=")) dataDir = value("--data-dir");
    else if (a.startsWith("-")) usage(`unknown option ${a}`);
    else roots.push(a);
  }
  if (pollSec !== null && !(Number.isFinite(pollSec) && pollSec > 0)) usage("--poll must be a positive number of seconds");
  if (keep !== null && !(Number.isInteger(keep) && keep >= 2)) usage("--keep must be an integer ≥ 2");
  const outDir = dataDir ? path.join(path.resolve(dataDir), "snapshots") : OUT_DIR;
  await runWatch({ roots: roots.map((r) => path.resolve(r)), outDir, pollSec, keep });
  process.exit(0);
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main().catch((err) => {
    console.error("watch failed:", err instanceof Error ? err.constructor.name : String(err));
    process.exit(2);
  });
}
