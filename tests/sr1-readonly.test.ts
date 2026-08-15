import { promises as fs } from "fs";
import path from "path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  buildMachine,
  rmMachine,
  runCollector,
  walkFileStates,
  type CollectorRun,
  type FileState,
  type Machine,
} from "./helpers/machine";

// SR1 — read-only guarantee (security-architecture.md §3).
// The collector runs against a throwaway HOME + project tree; every scanned
// file must be byte- and mtime-identical afterwards, and the only write in the
// whole run must be the snapshot under <cwd>/data/snapshots/.

describe("SR1 — collectors are read-only", () => {
  let m: Machine;
  let before: FileState[];
  let after: FileState[];
  let run: CollectorRun;

  beforeAll(async () => {
    m = await buildMachine();
    before = await walkFileStates(m.root);
    run = await runCollector(m);
    after = await walkFileStates(m.root);
  });
  afterAll(async () =>
    rmMachine(m));

  it("collector exits successfully", () => {
    expect(run.result.status, run.result.stderr).toBe(0);
    expect(run.snapshotPath).not.toBeNull();
  });

  it("no scanned file is created, deleted, or modified (mtime + size invariance)", () => {
    const scanned = (states: FileState[]) =>
      states.filter((s) => !s.file.startsWith(path.join(m.workDir, path.sep)));
    expect(scanned(after)).toEqual(scanned(before));
  });

  it("the only write is a single snapshot under data/snapshots/", async () => {
    const created = after.filter((a) => !before.some((b) => b.file === a.file));
    expect(created).toHaveLength(1);
    expect(created[0].file).toBe(run.snapshotPath);
    expect(path.dirname(created[0].file)).toBe(path.join(m.workDir, "data", "snapshots"));
  });

  it("a second run appends a new snapshot and leaves the first untouched", async () => {
    const firstBytes = await fs.readFile(run.snapshotPath!, "utf8");
    const second = await runCollector(m);
    expect(second.result.status, second.result.stderr).toBe(0);
    expect(second.snapshotPath).not.toBe(run.snapshotPath);
    expect(await fs.readFile(run.snapshotPath!, "utf8")).toBe(firstBytes);
  });
});
