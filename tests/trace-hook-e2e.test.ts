import http from "http";
import path from "path";
import { spawn } from "child_process";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { REPO_ROOT, SECRETS } from "./helpers/machine";

// The hook must be provably inert (docs/session-trace.md §2 condition 1):
// empty stdout/stderr, exit 0, bounded wall-clock — with a receiver, without
// one, and on oversized or malformed stdin. The real script is spawned.

const HOOK = path.join(REPO_ROOT, "bin", "agentlens-hook.mjs");

function runHook(stdin: string | Buffer, args: string[]) {
  return new Promise<{ code: number | null; stdout: string; stderr: string; ms: number }>((resolve) => {
    const t0 = Date.now();
    const child = spawn(process.execPath, [HOOK, ...args], { stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => (stdout += d));
    child.stderr.on("data", (d) => (stderr += d));
    child.on("exit", (code) => resolve({ code, stdout, stderr, ms: Date.now() - t0 }));
    child.stdin.end(stdin);
  });
}

describe("hook script", () => {
  let server: http.Server;
  let port: number;
  const bodies: Array<{ headers: http.IncomingHttpHeaders; body: string }> = [];

  beforeAll(async () => {
    server = http.createServer((req, res) => {
      let body = "";
      req.on("data", (d) => (body += d));
      req.on("end", () => {
        bodies.push({ headers: req.headers, body });
        res.writeHead(200, { "content-type": "application/json" });
        res.end("{}");
      });
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    port = (server.address() as { port: number }).port;
  });
  afterAll(() => server.close());

  it("posts a projected, redacted event and prints nothing", async () => {
    const payload = {
      session_id: "sess-e2e", cwd: "/home/u/proj", hook_event_name: "PostToolUse", tool_name: "Write", tool_use_id: "toolu_1",
      tool_input: { file_path: "/home/u/proj/.claude/settings.local.json", file_text: `{"token":"${SECRETS.github}"}` },
      tool_response: { ok: true },
    };
    const r = await runHook(JSON.stringify(payload), ["--port", String(port)]);
    expect(r.code).toBe(0);
    expect(r.stdout).toBe("");
    expect(r.stderr).toBe("");
    expect(r.ms).toBeLessThan(2000);
    expect(bodies).toHaveLength(1);
    expect(bodies[0].headers["content-type"]).toBe("application/json");
    const sent = JSON.parse(bodies[0].body);
    expect(sent.events[0]).toMatchObject({ kind: "file-write", resource: ".claude/settings.local.json", sessionId: "sess-e2e", toolUseId: "toolu_1" });
    expect(bodies[0].body).not.toContain("file_text");
    expect(bodies[0].body).not.toContain(SECRETS.github);
  });

  it("drops events it has no projection for without contacting the receiver", async () => {
    const before = bodies.length;
    const r = await runHook(JSON.stringify({ session_id: "s", hook_event_name: "PostToolUse", tool_name: "Read", tool_input: { file_path: "/x" } }), ["--port", String(port)]);
    expect(r.code).toBe(0);
    expect(r.stdout + r.stderr).toBe("");
    expect(bodies.length).toBe(before);
  });

  it("receiver down, malformed stdin and oversized stdin all exit 0 silently within 2 s", async () => {
    const payload = JSON.stringify({ session_id: "s", hook_event_name: "PostToolUse", tool_name: "Bash", tool_input: { command: "ls" } });
    const down = await runHook(payload, ["--port", "9"]); // discard port: refused immediately
    expect(down.code).toBe(0);
    expect(down.stdout + down.stderr).toBe("");
    expect(down.ms).toBeLessThan(2000);
    const bad = await runHook("{not json", ["--port", String(port)]);
    expect(bad.code).toBe(0);
    expect(bad.stdout + bad.stderr).toBe("");
    const big = await runHook(Buffer.alloc(5 * 1024 * 1024, 0x20), ["--port", String(port)]);
    expect(big.code).toBe(0);
    expect(big.stdout + big.stderr).toBe("");
    expect(big.ms).toBeLessThan(2000);
  });
});
