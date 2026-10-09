import { promises as fs } from "fs";
import path from "path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { SnapshotSchema } from "@/lib/schema";
import { buildMachine, rmMachine, runCollector, type Machine } from "./helpers/machine";

// Default project roots (collect.ts): with no CLI roots, the collector scans cwd
// plus the keys of `projects` in ~/.claude.json. $HOME, the fs root, relative
// keys and non-directories must be ignored.

describe("project-root discovery from ~/.claude.json", () => {
  let m: Machine;
  let snapshot: ReturnType<typeof SnapshotSchema.parse>;

  beforeAll(async () => {
    m = await buildMachine();
    await fs.writeFile(
      path.join(m.home, ".claude.json"),
      JSON.stringify({
        projects: {
          [m.project]: { allowedTools: [] },
          [m.home]: {},
          "/": {},
          "/nonexistent/agentlens-fixture": {},
          "relative/path": {},
          [path.join(m.home, ".claude", "settings.json")]: {},
        },
      }),
    );
    const run = await runCollector(m, {}, []);
    expect(run.result.status, run.result.stderr).toBe(0);
    snapshot = SnapshotSchema.parse(JSON.parse(run.snapshotText!));
  });
  afterAll(async () => rmMachine(m));

  it("scans the discovered project without any CLI argument", () => {
    const projects = snapshot.instances.filter((i) => i.scope === "project");
    expect(projects.map((i) => i.platform).sort()).toEqual(["claude-code", "gemini-cli"]);
    for (const p of projects) expect(p.projectPath).toBe(m.project);
  });

  it("never treats $HOME or the filesystem root as a project", () => {
    for (const i of snapshot.instances) {
      expect(i.projectPath).not.toBe(m.home);
      expect(i.projectPath).not.toBe("/");
    }
  });

  it("still only writes the snapshot (SR1) and reports the discovered root count", async () => {
    const files = await fs.readdir(path.join(m.workDir, "data", "snapshots"));
    expect(files).toHaveLength(1);
  });
});
