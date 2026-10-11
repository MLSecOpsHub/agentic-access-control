import { promises as fs } from "fs";
import os from "os";
import path from "path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import * as route from "@/app/api/trace/v1/events/route";
import { loadTraceSession, loadTraceSessions } from "@/lib/trace-store";
import { SECRETS } from "./helpers/machine";

// Receiver gates for /api/trace/v1/events (docs/session-trace.md §5, T12).
// Direct in-process handler calls, isolated data dir per test.

const ENDPOINT = "http://127.0.0.1:3000/api/trace/v1/events";
let dataDir: string;
const prevDataDir = process.env.AGENTLENS_DATA_DIR;

beforeEach(async () => {
  dataDir = await fs.mkdtemp(path.join(os.tmpdir(), "agentlens-trace-"));
  process.env.AGENTLENS_DATA_DIR = dataDir;
  // fresh dedup state per test
  delete (globalThis as Record<string, unknown>).__agentlensTrace;
});
afterEach(async () => {
  if (prevDataDir === undefined) delete process.env.AGENTLENS_DATA_DIR;
  else process.env.AGENTLENS_DATA_DIR = prevDataDir;
  await fs.rm(dataDir, { recursive: true, force: true });
});

const post = (body: string | object, headers: Record<string, string> = { "content-type": "application/json" }) =>
  route.POST(new Request(ENDPOINT, { method: "POST", headers, body: typeof body === "string" ? body : JSON.stringify(body) }));

const ev = (over: Record<string, unknown> = {}) => ({
  platform: "claude-code", sessionId: "sess-1", promptId: "p-1", toolUseId: "toolu_1", toolName: "Bash",
  kind: "shell", resource: "npm install left-pad", detail: { exitCode: 0 }, outcome: "ok", cwd: "/home/u/proj", ...over,
});

describe("receiver gates", () => {
  it("only POST exists", () => {
    expect((route as Record<string, unknown>).GET).toBeUndefined();
  });
  it("rejects non-JSON content types, oversized and malformed bodies with fixed codes and no echo", async () => {
    expect((await post("{}", { "content-type": "text/plain" })).status).toBe(415);
    const big = await post("x".repeat(300 * 1024));
    expect(big.status).toBe(413);
    const bad = await post(`{broken ${SECRETS.openai}`);
    expect(bad.status).toBe(400);
    const txt = await bad.text();
    expect(txt).toContain("ERR_JSON_SYNTAX");
    expect(txt).not.toContain(SECRETS.openai);
    const segs = await fs.readdir(path.join(dataDir, "observed")).catch(() => []);
    expect(segs.filter((f) => f.startsWith("trace-"))).toEqual([]);
  });
});

describe("ingestion", () => {
  it("stores projected events with server-assigned confidence, derives dependency rows, dedups replays", async () => {
    const r1 = await (await post({ events: [ev({ confidence: "observed-on-disk" })] })).json();
    expect(r1.agentlens.accepted).toBe(2); // shell + derived dependency
    expect(r1.agentlens.fingerprint).toBe("none");
    const r2 = await (await post({ events: [ev()] })).json();
    expect(r2.agentlens.duplicates).toBe(2);
    const session = (await loadTraceSession("sess-1"))!;
    expect(session.events.map((e) => `${e.kind}:${e.confidence}`).sort()).toEqual(["dependency:derived", "shell:vendor-event"]);
    expect(session.summary.counts.shell).toBe(1);
  });

  it("server-only kinds are ignored; invalid events counted; secrets redacted at ingest", async () => {
    const r = await (await post({ events: [
      ev({ kind: "fs-change" }),
      ev({ kind: "dependency" }),
      ev({ resource: `curl -H 'Authorization: Bearer ${SECRETS.bearerToken}' https://api.example.com/v1`, toolUseId: "toolu_2" }),
      { platform: "claude-code", kind: "web" }, // missing resource → invalid
    ] })).json();
    expect(r.agentlens.ignored).toBe(2);
    expect(r.partialSuccess.rejected).toBe(1);
    const raw = (await fs.readdir(path.join(dataDir, "observed"))).filter((f) => f.startsWith("trace-"));
    const text = await fs.readFile(path.join(dataDir, "observed", raw[0]), "utf8");
    expect(text).not.toContain(SECRETS.bearerToken);
    expect(text).not.toContain("observed-on-disk");
  });

  it("session summaries: start/end, mode, cwd, per-kind counts", async () => {
    await post({ events: [
      ev({ kind: "session-start", toolUseId: null, toolName: null, resource: "/home/u/proj", detail: { source: "startup", permissionMode: "acceptEdits" }, eventAt: "2026-10-12T10:00:00.000Z" }),
      ev({ eventAt: "2026-10-12T10:01:00.000Z" }),
      ev({ kind: "file-write", toolUseId: "toolu_3", toolName: "Write", resource: "src/a.ts", detail: {}, eventAt: "2026-10-12T10:02:00.000Z" }),
      ev({ kind: "session-end", toolUseId: null, toolName: null, resource: "/home/u/proj", detail: { reason: "other" }, eventAt: "2026-10-12T10:03:00.000Z" }),
    ] });
    const { sessions } = await loadTraceSessions();
    expect(sessions).toHaveLength(1);
    const s = sessions[0];
    expect(s.permissionMode).toBe("acceptEdits");
    expect(s.cwd).toBe("/home/u/proj");
    expect(s.endedAt).toBe("2026-10-12T10:03:00.000Z");
    expect(s.counts["file-write"]).toBe(1);
    expect(s.counts.dependency).toBe(1);
    expect(await loadTraceSession("../etc")).toBeNull();
  });
});
