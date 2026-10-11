import { promises as fs } from "fs";
import os from "os";
import path from "path";
import { describe, expect, it } from "vitest";
import { canonicalJson, contentFingerprint, rawContentFingerprint, snapshotHash } from "@/lib/hash";
import { buildWatchTargets } from "@/collectors/watch";
import { pruneSnapshots } from "@/collectors/pipeline";
import { makeSnapshot } from "./helpers/snapshots";

describe("content fingerprint (watch dedupe)", () => {
  it("ignores generatedAt and hash but tracks content, independent of key order", () => {
    const a = makeSnapshot({ generatedAt: "2026-01-01T00:00:00.000Z" });
    const b = makeSnapshot({ generatedAt: "2026-01-02T00:00:00.000Z" });
    expect(snapshotHash(a)).not.toBe(snapshotHash(b)); // SR5 hash differs
    expect(contentFingerprint(a)).toBe(contentFingerprint(b)); // fingerprint does not
    const c = makeSnapshot({ findings: [{ id: "H2:x:0", heuristicId: "H2", severity: "high", title: "t", evidence: "e", instanceId: "claude-code:user", sourceFile: null }] });
    expect(contentFingerprint(c)).not.toBe(contentFingerprint(a));
    const reordered = JSON.parse(JSON.stringify(a)) as Record<string, unknown>;
    const { instances, ...restOfA } = reordered;
    const shuffled = { zzz: undefined, ...restOfA, instances };
    expect(rawContentFingerprint(shuffled)).toBe(contentFingerprint(a));
    expect(canonicalJson({ b: 1, a: [{ d: 2, c: 3 }] })).toBe('{"a":[{"c":3,"d":2}],"b":1}');
  });
});

describe("watch targets", () => {
  it("covers the allowlisted config locations and dedupes directories", () => {
    const targets = buildWatchTargets({ home: "/h", codexHome: "/h/.codex", roots: ["/p", "/p"] });
    const dirs = targets.map((t) => t.dir).sort();
    expect(dirs).toEqual(["/h", "/h/.claude", "/h/.codex", "/h/.gemini", "/p", "/p/.claude", "/p/.codex", "/p/.cursor", "/p/.gemini", "/p/.vscode"]);
    const by = Object.fromEntries(targets.map((t) => [t.dir, t.accept]));
    expect(by["/h"](".claude.json")).toBe(true);
    expect(by["/h"]("other.txt")).toBe(false);
    expect(by["/h"](null)).toBe(true);
    expect(by["/h/.codex"]("config.toml")).toBe(true);
    expect(by["/h/.codex"]("work.config.toml")).toBe(true);
    expect(by["/h/.codex"]("notes.md")).toBe(false);
    expect(by["/p"](".mcp.json")).toBe(true);
    expect(by["/p"](".claude")).toBe(true); // directory creation re-arms
    expect(by["/p"]("README.md")).toBe(false);
    expect(by["/p/.claude"]("settings.local.json")).toBe(true);
  });
});

describe("pruneSnapshots", () => {
  it("deletes only the oldest snapshot-named files beyond keep, never fewer than 2", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "agentlens-prune-"));
    const names = ["2026-01-01T00-00-00-000Z.json", "2026-01-02T00-00-00-000Z.json", "2026-01-03T00-00-00-000Z.json", "2026-01-04T00-00-00-000Z.json"];
    for (const n of names) await fs.writeFile(path.join(dir, n), "{}");
    await fs.writeFile(path.join(dir, "notes.json"), "{}");
    const removed = await pruneSnapshots(dir, 1); // clamps to 2
    expect(removed.map((f) => path.basename(f))).toEqual(names.slice(0, 2));
    expect((await fs.readdir(dir)).sort()).toEqual([...names.slice(2), "notes.json"]);
    await fs.rm(dir, { recursive: true, force: true });
  });
});
