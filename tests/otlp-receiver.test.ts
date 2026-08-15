import { promises as fs } from "fs";
import os from "os";
import path from "path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import * as route from "@/app/api/otel/v1/logs/route";
import { loadRecentEvents } from "@/lib/observed-store";

// L8 validation matrix (live-tracking-final-plan.md), landing as part of the
// hardening Step 4 suite: receiver gates, fixed error codes with zero content
// echo, event-name allowlist, identity attributes never persisted, redaction
// at ingest, dedup, decision/result/mode-change/connection paths, and
// per-session isolation. The route handler is exercised in-process; storage is
// isolated per test via the AGENTLENS_DATA_DIR seam.

const ENDPOINT = "http://127.0.0.1:3000/api/otel/v1/logs";

type Attr = { key: string; value: { stringValue?: string; intValue?: number; boolValue?: boolean } };
const attr = (key: string, v: string | number | boolean): Attr =>
  typeof v === "string"
    ? { key, value: { stringValue: v } }
    : typeof v === "number"
      ? { key, value: { intValue: v } }
      : { key, value: { boolValue: v } };

function envelope(records: Array<{ name: string; attrs: Attr[]; timeNano?: string }>): string {
  return JSON.stringify({
    resourceLogs: [
      {
        resource: { attributes: [attr("service.name", "claude-code"), attr("service.version", "2.0.1")] },
        scopeLogs: [
          {
            logRecords: records.map((r) => ({
              timeUnixNano: r.timeNano ?? "1755100000000000000",
              body: { stringValue: r.name },
              attributes: [attr("event.name", r.name), ...r.attrs],
            })),
          },
        ],
      },
    ],
  });
}

const post = (body: string, headers: Record<string, string> = {}) =>
  route.POST(
    new Request(ENDPOINT, {
      method: "POST",
      headers: { "content-type": "application/json", ...headers },
      body,
    }),
  );

const decisionRecord = (session: string, seq: number, opts: Partial<Record<string, string>> = {}) => ({
  name: "tool_decision",
  attrs: [
    attr("session.id", session),
    attr("event.sequence", seq),
    attr("tool_name", opts.toolName ?? "Bash"),
    attr("tool_use_id", opts.toolUseId ?? `toolu_${session}_${seq}`),
    attr("decision", opts.decision ?? "accept"),
    attr("source", opts.source ?? "config"),
    ...(opts.toolSource ? [attr("tool_source", opts.toolSource)] : []),
  ],
});

let dataDir: string;
beforeEach(async () => {
  dataDir = await fs.mkdtemp(path.join(os.tmpdir(), "agentlens-otlp-"));
  process.env.AGENTLENS_DATA_DIR = dataDir;
});
afterEach(async () => {
  delete process.env.AGENTLENS_DATA_DIR;
  await fs.rm(dataDir, { recursive: true, force: true });
});

async function segmentText(): Promise<string> {
  const dir = path.join(dataDir, "observed");
  try {
    const files = (await fs.readdir(dir)).filter((f) => f.endsWith(".ndjson"));
    let out = "";
    for (const f of files) out += await fs.readFile(path.join(dir, f), "utf8");
    return out;
  } catch {
    return "";
  }
}

describe("receiver gates", () => {
  it("only POST is exported — no GET handler exists on the route", () => {
    expect((route as Record<string, unknown>).GET).toBeUndefined();
    expect(typeof route.POST).toBe("function");
  });

  it("rejects non-JSON content types with a fixed code", async () => {
    const res = await post("x=1", { "content-type": "text/plain" });
    expect(res.status).toBe(415);
    expect(await res.json()).toEqual({ error: "ERR_CONTENT_TYPE" });
  });

  it("rejects oversized bodies declared via content-length", async () => {
    const res = await post("{}", { "content-length": String(3 * 1024 * 1024) });
    expect(res.status).toBe(413);
    expect(await res.json()).toEqual({ error: "ERR_BODY_TOO_LARGE" });
  });

  it("rejects bodies over the cap even without a truthful content-length", async () => {
    const big = `{"pad":"${"a".repeat(2 * 1024 * 1024 + 10)}"}`;
    const res = await route.POST(
      new Request(ENDPOINT, { method: "POST", headers: { "content-type": "application/json" }, body: big }),
    );
    expect(res.status).toBe(413);
  });

  it("malformed JSON → fixed code, no payload byte echoed, nothing persisted", async () => {
    const secret = "sk-leakcanary1234567890";
    const res = await post(`{"broken": ${secret}`);
    expect(res.status).toBe(400);
    const text = JSON.stringify(await res.json());
    expect(text).toContain("ERR_JSON_SYNTAX");
    expect(text).not.toContain(secret);
    expect(await segmentText()).toBe("");
  });
});

describe("event allowlist and identity hygiene", () => {
  it("non-allowlisted event names are counted as ignored, never persisted", async () => {
    const res = await post(
      envelope([{ name: "user_prompt", attrs: [attr("session.id", "s1"), attr("prompt", "the prompt text")] }]),
    );
    const body = await res.json();
    expect(body.agentlens.ignored).toBe(1);
    expect(body.agentlens.accepted).toBe(0);
    expect(await segmentText()).toBe("");
  });

  it("identity attributes are never read, so they can never be persisted", async () => {
    const rec = decisionRecord("s-ident", 1);
    rec.attrs.push(
      attr("user.id", "user-uuid-123"),
      attr("user.email", "person@example.com"),
      attr("user.account_uuid", "acct-uuid-456"),
      attr("organization.id", "org-uuid-789"),
    );
    const res = await post(envelope([rec]));
    expect((await res.json()).agentlens.accepted).toBe(1);
    const stored = await segmentText();
    expect(stored).not.toContain("person@example.com");
    expect(stored).not.toContain("user-uuid-123");
    expect(stored).not.toContain("acct-uuid-456");
    expect(stored).not.toContain("org-uuid-789");
  });

  it("secret-shaped attribute values are redacted at ingest", async () => {
    const res = await post(
      envelope([decisionRecord("s-red", 1, { toolName: "Bash(sk-ingestcanary1234567890)" })]),
    );
    expect((await res.json()).agentlens.accepted).toBe(1);
    const stored = await segmentText();
    expect(stored).not.toContain("sk-ingestcanary1234567890");
    expect(stored).toContain("[REDACTED]");
  });
});

describe("evidence-class paths", () => {
  it("accept decision: kind, decision, broad source category, correlation ids preserved", async () => {
    await post(envelope([decisionRecord("s1", 1, { toolUseId: "toolu_A", source: "config" })]));
    const feed = await loadRecentEvents();
    expect(feed.events).toHaveLength(1);
    const e = feed.events[0];
    expect(e.kind).toBe("decision");
    expect(e.decision).toBe("accept");
    expect(e.decisionSource).toBe("config"); // broad category only — never a rule attribution
    expect(e.toolUseId).toBe("toolu_A");
    expect(e.sessionId).toBe("s1");
    expect(e.confidence).toBe("vendor-event");
    expect(e.claudeVersion).toBe("2.0.1");
  });

  it("reject decision is preserved as reject — rejected ≠ executed", async () => {
    await post(envelope([decisionRecord("s1", 2, { decision: "reject", source: "user_temporary" })]));
    const feed = await loadRecentEvents();
    expect(feed.events[0].decision).toBe("reject");
    expect(feed.events[0].execution).toBeNull();
  });

  it("tool_result correlates to its decision by tool_use_id", async () => {
    await post(
      envelope([
        decisionRecord("s1", 3, { toolUseId: "toolu_corr" }),
        {
          name: "tool_result",
          attrs: [
            attr("session.id", "s1"),
            attr("event.sequence", 4),
            attr("tool_name", "Bash"),
            attr("tool_use_id", "toolu_corr"),
            attr("success", "true"),
            attr("duration_ms", 42),
          ],
        },
      ]),
    );
    const feed = await loadRecentEvents();
    const decision = feed.events.find((e) => e.kind === "decision");
    const result = feed.events.find((e) => e.kind === "result");
    expect(decision?.toolUseId).toBe("toolu_corr");
    expect(result?.toolUseId).toBe("toolu_corr");
    expect(result?.execution).toEqual({ success: true, durationMs: 42, errorType: null });
  });

  it("permission_mode_changed carries from/to/trigger", async () => {
    await post(
      envelope([
        {
          name: "permission_mode_changed",
          attrs: [
            attr("session.id", "s1"),
            attr("event.sequence", 5),
            attr("from_mode", "default"),
            attr("to_mode", "acceptEdits"),
            attr("trigger", "user"),
          ],
        },
      ]),
    );
    const feed = await loadRecentEvents();
    expect(feed.events[0].kind).toBe("mode_change");
    expect(feed.events[0].modeChange).toEqual({ from: "default", to: "acceptEdits", trigger: "user" });
  });

  it("mcp_server_connection: server name only in detailed mode, withheld otherwise", async () => {
    await post(
      envelope([
        {
          name: "mcp_server_connection",
          attrs: [
            attr("session.id", "s1"),
            attr("event.sequence", 6),
            attr("status", "connected"),
            attr("transport_type", "stdio"),
            attr("server_name", "github"), // OTEL_LOG_TOOL_DETAILS=1
          ],
        },
        {
          name: "mcp_server_connection",
          attrs: [
            attr("session.id", "s1"),
            attr("event.sequence", 7),
            attr("status", "connected"),
            attr("transport_type", "stdio"), // privacy default: no server_name
          ],
        },
      ]),
    );
    const feed = await loadRecentEvents();
    const [withoutName, withName] = feed.events; // newest (seq 7) first
    expect(withName.mcpConnection?.serverName).toBe("github");
    expect(withoutName.mcpConnection?.serverName).toBeNull();
    expect(withoutName.mcpConnection?.status).toBe("connected");
  });

  it("builtin vs MCP tool attribution is preserved", async () => {
    await post(
      envelope([
        decisionRecord("s1", 8, { toolName: "Bash", toolSource: "builtin" }),
        decisionRecord("s1", 9, { toolName: "mcp__github__search", toolSource: "mcp" }),
      ]),
    );
    const feed = await loadRecentEvents();
    const mcp = feed.events.find((e) => e.toolName === "mcp__github__search");
    const builtin = feed.events.find((e) => e.toolName === "Bash");
    expect(mcp?.toolSource).toBe("mcp");
    expect(builtin?.toolSource).toBe("builtin");
  });
});

describe("dedup and session isolation", () => {
  it("replaying the same envelope stores each event once", async () => {
    const body = envelope([decisionRecord("s-dup", 1)]);
    const first = await (await post(body)).json();
    const second = await (await post(body)).json();
    expect(first.agentlens.accepted).toBe(1);
    expect(second.agentlens.accepted).toBe(0);
    expect(second.agentlens.duplicates).toBe(1);
    const feed = await loadRecentEvents();
    expect(feed.events).toHaveLength(1);
  });

  it("interleaved concurrent sessions stay attributable to their own session", async () => {
    await post(
      envelope([
        decisionRecord("session-A", 1, { toolUseId: "toolu_A1" }),
        decisionRecord("session-B", 1, { toolUseId: "toolu_B1" }),
        decisionRecord("session-A", 2, { toolUseId: "toolu_A2" }),
      ]),
    );
    const feed = await loadRecentEvents();
    expect(feed.events).toHaveLength(3);
    const bySession = (id: string) => feed.events.filter((e) => e.sessionId === id);
    expect(bySession("session-A").map((e) => e.toolUseId).sort()).toEqual(["toolu_A1", "toolu_A2"]);
    expect(bySession("session-B").map((e) => e.toolUseId)).toEqual(["toolu_B1"]);
  });
});
