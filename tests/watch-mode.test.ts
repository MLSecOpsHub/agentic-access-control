import { promises as fs } from "fs";
import os from "os";
import path from "path";
import { spawn, type ChildProcess } from "child_process";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { buildMachine, REPO_ROOT, rmMachine, walkFileStates, type FileState, type Machine } from "./helpers/machine";

// Watch mode end to end: a real `watch` process against the fixture machine.
// It must write a snapshot only when content changed, prune its own files when
// asked, and never touch anything it watches (SR1).

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

describe("watch mode", () => {
  let m: Machine;
  let dataDir: string;
  let child: ChildProcess;
  let before: FileState[];
  const out: string[] = [];
  const exited = { code: null as number | null };

  const snapshots = async () => (await fs.readdir(path.join(dataDir, "snapshots"))).filter((f) => f.endsWith(".json")).sort();
  const waitFor = async (pred: () => Promise<boolean>, ms: number) => {
    const deadline = Date.now() + ms;
    while (Date.now() < deadline) {
      if (await pred()) return true;
      await sleep(250);
    }
    return pred();
  };

  beforeAll(async () => {
    m = await buildMachine();
    before = await walkFileStates(m.root);
    dataDir = await fs.mkdtemp(path.join(os.tmpdir(), "agentlens-watch-"));
    child = spawn(
      process.execPath,
      [path.join(REPO_ROOT, "node_modules", "tsx", "dist", "cli.mjs"), path.join(REPO_ROOT, "collectors", "watch.ts"), m.project, "--data-dir", dataDir, "--keep", "2"],
      { cwd: m.workDir, env: { ...process.env, HOME: m.home, CODEX_HOME: path.join(m.home, ".codex") }, stdio: ["ignore", "pipe", "pipe"] },
    );
    child.stdout!.on("data", (d) => out.push(...String(d).split("\n").filter(Boolean)));
    child.stderr!.on("data", (d) => out.push(...String(d).split("\n").filter(Boolean)));
    child.on("exit", (code) => (exited.code = code));
    expect(await waitFor(async () => out.some((l) => l.startsWith("watch: ready")), 60_000), out.join("\n")).toBe(true);
  }, 90_000);

  afterAll(async () => {
    if (child && child.exitCode === null) child.kill("SIGKILL");
    await rmMachine(m);
    await fs.rm(dataDir, { recursive: true, force: true });
  });

  it("writes one snapshot at startup", async () => {
    expect(await snapshots()).toHaveLength(1);
  });

  it("re-collects on a config change and writes a new snapshot", async () => {
    const file = path.join(m.project, ".claude", "settings.json");
    const cfg = JSON.parse(await fs.readFile(file, "utf8"));
    cfg.permissions.allow.push("WebFetch(domain:watch.example)");
    await fs.writeFile(file, JSON.stringify(cfg));
    expect(await waitFor(async () => (await snapshots()).length === 2, 15_000), out.join("\n")).toBe(true);
  });

  it("does not write when the content is unchanged (touch / identical rewrite)", async () => {
    const file = path.join(m.project, ".claude", "settings.json");
    await fs.writeFile(file, await fs.readFile(file, "utf8"));
    await sleep(3000);
    expect(await snapshots()).toHaveLength(2);
    expect(out.some((l) => l.includes("→ unchanged"))).toBe(true);
  });

  it("prunes its own oldest snapshot beyond --keep", async () => {
    const first = (await snapshots())[0];
    const file = path.join(m.project, ".mcp.json");
    const cfg = JSON.parse(await fs.readFile(file, "utf8"));
    cfg.mcpServers.extra = { command: "node", args: ["x.js"] };
    await fs.writeFile(file, JSON.stringify(cfg));
    expect(await waitFor(async () => { const s = await snapshots(); return s.length === 2 && !s.includes(first); }, 15_000), out.join("\n")).toBe(true);
  });

  it("never modified anything it watched, except the files this test edited", async () => {
    const after = await walkFileStates(m.root);
    const edited = new Set([path.join(m.project, ".claude", "settings.json"), path.join(m.project, ".mcp.json")]);
    const strip = (s: FileState[]) => s.filter((f) => !edited.has(f.file) && !f.file.startsWith(path.join(m.workDir, path.sep)));
    expect(strip(after)).toEqual(strip(before));
  });

  it("stops cleanly on SIGTERM", async () => {
    child.kill("SIGTERM");
    expect(await waitFor(async () => exited.code !== null, 10_000)).toBe(true);
    expect(exited.code).toBe(0);
  });
});
