import { promises as fs } from "fs";
import os from "os";
import path from "path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { importTranscript } from "@/lib/trace-import";
import { loadTraceSession } from "@/lib/trace-store";
import { REPO_ROOT } from "./helpers/machine";

// Transcript import (docs/session-trace.md §14): explicit file, tool-call
// structure only, confidence inferred-transcript, fixed codes. Prompt and
// response text must never reach the store.

const FIXTURE = path.join(REPO_ROOT, "tests", "fixtures", "transcript-synthetic.jsonl");

describe("transcript import", () => {
  let dataDir: string;
  let tmp: string;
  const prev = process.env.AGENTLENS_DATA_DIR;
  beforeAll(async () => {
    dataDir = await fs.mkdtemp(path.join(os.tmpdir(), "agentlens-import-"));
    tmp = await fs.mkdtemp(path.join(os.tmpdir(), "agentlens-import-src-"));
    process.env.AGENTLENS_DATA_DIR = dataDir;
    delete (globalThis as Record<string, unknown>).__agentlensTrace;
  });
  afterAll(async () => {
    if (prev === undefined) delete process.env.AGENTLENS_DATA_DIR;
    else process.env.AGENTLENS_DATA_DIR = prev;
    await fs.rm(dataDir, { recursive: true, force: true });
    await fs.rm(tmp, { recursive: true, force: true });
  });

  it("keeps only tool-call structure, marks errored calls, derives from commands, redacts, drops reads by default", async () => {
    const r = await importTranscript(FIXTURE);
    expect(r.ok).toBe(true);
    expect(r.sessionId).toBe("synthetic-session-0001");
    expect(r.formatVersion).toBe("2.1.296");
    expect(r.syntaxErrors).toBe(1);
    expect(r.toolUses).toBe(4);
    const session = (await loadTraceSession("synthetic-session-0001"))!;
    const rows = session.events.map((e) => `${e.kind}:${e.resource}:${e.outcome}`);
    expect(rows).toContain("session-start:/home/u/proj:ok");
    expect(rows).toContain("file-write:src/index.ts:unknown");
    expect(rows.some((r) => r.startsWith("shell:npm install left-pad") && r.endsWith(":failed"))).toBe(true);
    expect(rows).toContain("dependency:npm:left-pad:failed");
    expect(rows).toContain("web:https://x.example/s.sh:failed");
    expect(rows).toContain("mcp-call:github/create_issue:unknown");
    expect(rows.some((r) => r.startsWith("file-read"))).toBe(false);
    expect(new Set(session.events.map((e) => e.confidence))).toEqual(new Set(["inferred-transcript"]));
    expect(session.summary.permissionMode).toBeNull();
    const stored = await fs.readFile(path.join(dataDir, "observed", (await fs.readdir(path.join(dataDir, "observed"))).find((f) => f.startsWith("trace-"))!), "utf8");
    for (const leak of ["PRIVATE", "sk-fixture", "ghp_fixture", "file_text", "description"]) expect(stored).not.toContain(leak);
    const again = await importTranscript(FIXTURE);
    expect(again.duplicates).toBe(r.appended); // idempotent via toolUseId-based ids
  });

  it("reads opt in; fixed codes for missing, symlinked and format-less files", async () => {
    const withReads = await importTranscript(FIXTURE, { reads: true });
    expect(withReads.ok).toBe(true);
    const session = (await loadTraceSession("synthetic-session-0001"))!;
    expect(session.events.some((e) => e.kind === "file-read" && e.resource === ".")).toBe(true);
    expect((await importTranscript(path.join(tmp, "missing.jsonl"))).code).toBe("ERR_NOT_A_FILE");
    await fs.symlink(FIXTURE, path.join(tmp, "link.jsonl"));
    expect((await importTranscript(path.join(tmp, "link.jsonl"))).code).toBe("ERR_SYMLINK");
    await fs.writeFile(path.join(tmp, "empty.jsonl"), '{"type":"user","message":{"content":[{"type":"text","text":"hi"}]}}\n');
    expect((await importTranscript(path.join(tmp, "empty.jsonl"))).code).toBe("ERR_TRANSCRIPT_FORMAT");
  });
});
