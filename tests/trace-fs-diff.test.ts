import { promises as fs } from "fs";
import os from "os";
import path from "path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { diffFingerprints, fingerprintTree } from "@/lib/fs-fingerprint";
import { onSessionEnd, onSessionStart } from "@/lib/trace-fs";
import { appendTraceEvents, loadTraceSession } from "@/lib/trace-store";
import { toTraceEvent } from "@/lib/trace";
import { walkFileStates } from "./helpers/machine";

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

describe("fingerprint + session window diff", () => {
  let root: string;
  let dataDir: string;
  const prev = { data: process.env.AGENTLENS_DATA_DIR, roots: process.env.AGENTLENS_TRACE_ROOTS };
  beforeAll(async () => {
    root = await fs.mkdtemp(path.join(os.tmpdir(), "agentlens-fsdiff-"));
    dataDir = await fs.mkdtemp(path.join(os.tmpdir(), "agentlens-fsdiff-data-"));
    process.env.AGENTLENS_DATA_DIR = dataDir;
    process.env.AGENTLENS_TRACE_ROOTS = root;
    delete (globalThis as Record<string, unknown>).__agentlensTrace;
    await fs.mkdir(path.join(root, "src"), { recursive: true });
    await fs.mkdir(path.join(root, "node_modules", "dep"), { recursive: true });
    await fs.writeFile(path.join(root, "src", "a.ts"), "a");
    await fs.writeFile(path.join(root, "src", "b.ts"), "bb");
    await fs.writeFile(path.join(root, "gone.txt"), "x");
    await fs.writeFile(path.join(root, "node_modules", "dep", "index.js"), "ignored");
    await fs.symlink("/etc", path.join(root, "etc-link"));
  });
  afterAll(async () => {
    for (const [k, v] of [["AGENTLENS_DATA_DIR", prev.data], ["AGENTLENS_TRACE_ROOTS", prev.roots]] as const) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
    await fs.rm(root, { recursive: true, force: true });
    await fs.rm(dataDir, { recursive: true, force: true });
  });

  it("walk skips node_modules and symlinks and is read-only; diff classifies add/modify/touch/remove", async () => {
    const before = await walkFileStates(root);
    const fp = await fingerprintTree(root);
    expect(Object.keys(fp.files).sort()).toEqual(["gone.txt", "src/a.ts", "src/b.ts"]);
    expect(fp.truncated).toBeNull();
    await sleep(20);
    await fs.writeFile(path.join(root, "src", "a.ts"), "aaaa"); // size change
    const bPath = path.join(root, "src", "b.ts");
    const future = new Date(Date.now() + 5000);
    await fs.utimes(bPath, future, future); // mtime only
    await fs.writeFile(path.join(root, "src", "new.ts"), "n");
    await fs.unlink(path.join(root, "gone.txt"));
    const after = await fingerprintTree(root);
    expect(diffFingerprints(fp, after)).toEqual([
      { path: "gone.txt", change: "removed" },
      { path: "src/a.ts", change: "modified" },
      { path: "src/b.ts", change: "touched" },
      { path: "src/new.ts", change: "added" },
    ]);
    const walked = await walkFileStates(root);
    expect(walked.filter((f) => f.file.includes("node_modules"))).toEqual(before.filter((f) => f.file.includes("node_modules")));
  });

  it("caps truncate instead of lying", async () => {
    const fp = await fingerprintTree(root, { maxFiles: 1, maxBytes: 1e9, maxMs: 10_000, maxDepth: 12 });
    expect(fp.truncated).toBe("files");
  });

  it("session start baselines only under allowed roots; end emits fs-change events with matchedWrite and deletes the baseline", async () => {
    expect(await onSessionStart("sess-fs", "/definitely/not/allowed", "claude-code")).toBe("skipped-outside-roots");
    expect(await onSessionStart("sess-fs", path.join(root, "src"), "claude-code")).toBe("started");
    expect(await onSessionStart("sess-fs", path.join(root, "src"), "claude-code")).toBe("none"); // no re-baseline
    expect((await fs.readdir(path.join(dataDir, "observed", "trace-fs"))).sort()).toEqual(["sess-fs.json"]);
    await sleep(20);
    await fs.writeFile(path.join(root, "src", "a.ts"), "written by tool");
    await fs.writeFile(path.join(root, "src", "c.ts"), "side effect");
    await appendTraceEvents([toTraceEvent({ platform: "claude-code", sessionId: "sess-fs", toolUseId: "t1", kind: "file-write", resource: "a.ts", cwd: path.join(root, "src") }, "vendor-event", new Date().toISOString())]);
    expect(await onSessionEnd("sess-fs")).toBe("closed");
    expect(await onSessionEnd("sess-fs")).toBe("no-baseline");
    const session = (await loadTraceSession("sess-fs"))!;
    const changes = session.events.filter((e) => e.kind === "fs-change").map((e) => [e.resource, e.detail.change, e.detail.matchedWrite, e.confidence]);
    expect(changes).toEqual([
      ["a.ts", "modified", true, "observed-on-disk"],
      ["c.ts", "added", false, "observed-on-disk"],
    ]);
    expect(await fs.readdir(path.join(dataDir, "observed", "trace-fs"))).toEqual([]);
  });
});
