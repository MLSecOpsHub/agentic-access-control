import { describe, expect, it } from "vitest";
import { projectHookPayload, splitMcpTool, stripUrl } from "@/lib/trace-project.mjs";
import { normalizeTraceBatch, toTraceEvent } from "@/lib/trace";
import { deriveFromShell } from "@/lib/trace-derive";
import { PATTERNS as JS_PATTERNS, KEYED as JS_KEYED } from "@/lib/redact-patterns.mjs";
import { redact } from "@/lib/redact";
import { SECRETS } from "./helpers/machine";

// Projection allowlist (docs/session-trace.md §6): only the named fields are
// read, secrets are redacted before anything leaves the session process, and
// never-read fields do not surface anywhere in the projected event.

const common = { session_id: "sess-1", prompt_id: "p-1", cwd: "/home/u/proj", transcript_path: "/home/u/.claude/projects/x/abc.jsonl", permission_mode: "auto" };
const text = (v: unknown) => JSON.stringify(v);

describe("hook payload projection", () => {
  it("Write/Edit → file-write with a cwd-relative path and no content", () => {
    const ev = projectHookPayload({ ...common, hook_event_name: "PostToolUse", tool_name: "Write", tool_use_id: "toolu_1",
      tool_input: { file_path: "/home/u/proj/src/a.ts", file_text: `const k = "${SECRETS.openai}";` }, tool_response: { ok: true } })!;
    expect(ev.kind).toBe("file-write");
    expect(ev.resource).toBe("src/a.ts");
    expect(ev.outcome).toBe("ok");
    expect(ev.toolUseId).toBe("toolu_1");
    expect(ev.promptId).toBe("p-1");
    expect(text(ev)).not.toContain("file_text");
    expect(text(ev)).not.toContain(SECRETS.openai);
    const outside = projectHookPayload({ ...common, hook_event_name: "PostToolUse", tool_name: "Edit", tool_input: { file_path: "/etc/hosts", edits: [{ old_str: "a", new_str: "b" }] } })!;
    expect(outside.resource).toBe("/etc/hosts");
    expect(text(outside)).not.toContain("old_str");
  });

  it("Bash → shell with a redacted, truncated command and the exit code only", () => {
    const long = "x".repeat(700);
    const ev = projectHookPayload({ ...common, hook_event_name: "PostToolUse", tool_name: "Bash",
      tool_input: { command: `curl -H "Authorization: Bearer ${SECRETS.bearerToken}" https://api.example.com/v1?token=${SECRETS.keyedValue} && echo ${long}`, description: "secret description" },
      tool_response: { stdout: `leaked ${SECRETS.github}`, stderr: "", exit_code: 2 } })!;
    expect(ev.kind).toBe("shell");
    expect(ev.outcome).toBe("failed");
    expect(ev.detail.exitCode).toBe(2);
    expect(ev.resource.length).toBeLessThanOrEqual(501);
    for (const v of [SECRETS.bearerToken, SECRETS.keyedValue, SECRETS.github]) expect(text(ev)).not.toContain(v);
    expect(text(ev)).not.toContain("secret description");
    expect(text(ev)).not.toContain("stdout");
  });

  it("WebFetch → scheme+host+path only; WebSearch keeps no query; MCP/Skill/Agent keep names only", () => {
    const web = projectHookPayload({ ...common, hook_event_name: "PostToolUse", tool_name: "WebFetch",
      tool_input: { url: `https://api.example.com/v1/items?token=${SECRETS.keyedValue}#frag`, headers: { Authorization: "x" } }, tool_response: { status_code: 200, body: "<html>" } })!;
    expect(web.kind).toBe("web");
    expect(web.resource).toBe("https://api.example.com/v1/items");
    expect(web.detail.statusCode).toBe(200);
    expect(text(web)).not.toContain("Authorization");
    const search = projectHookPayload({ ...common, hook_event_name: "PostToolUse", tool_name: "WebSearch", tool_input: { query: "my private question" } })!;
    expect(search.resource).toBe("web-search");
    expect(text(search)).not.toContain("private");
    const mcp = projectHookPayload({ ...common, hook_event_name: "PostToolUse", tool_name: "mcp__github__create_issue", tool_input: { title: "secret title", body: SECRETS.slack } })!;
    expect(mcp.kind).toBe("mcp-call");
    expect(mcp.resource).toBe("github/create_issue");
    expect(mcp.detail).toEqual({ server: "github", tool: "create_issue" });
    expect(text(mcp)).not.toContain("secret title");
    const skill = projectHookPayload({ ...common, hook_event_name: "PostToolUse", tool_name: "Skill", tool_input: { skill: "deploy", args: "prod now" } })!;
    expect(skill.kind).toBe("skill");
    expect(skill.resource).toBe("deploy");
    expect(text(skill)).not.toContain("prod now");
    const agent = projectHookPayload({ ...common, hook_event_name: "PostToolUse", tool_name: "Agent", tool_input: { subagent_type: "Explore", prompt: "find the secret" } })!;
    expect(agent.kind).toBe("subagent");
    expect(agent.resource).toBe("Explore");
    expect(text(agent)).not.toContain("find the secret");
  });

  it("reads are dropped unless opted in, then reduced to a directory; unknown tools are dropped", () => {
    const read = { ...common, hook_event_name: "PostToolUse", tool_name: "Read", tool_input: { file_path: "/home/u/proj/src/deep/file.ts" } };
    expect(projectHookPayload(read)).toBeNull();
    expect(projectHookPayload(read, { reads: true })!.resource).toBe("src/deep");
    expect(projectHookPayload({ ...common, hook_event_name: "PostToolUse", tool_name: "TodoWrite", tool_input: { todos: [] } })).toBeNull();
    expect(projectHookPayload({ ...common, hook_event_name: "UserPromptSubmit", prompt: "hello" })).toBeNull();
    expect(projectHookPayload({ ...common, hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "ls" } })).toBeNull();
  });

  it("failure, denial and lifecycle events", () => {
    const failed = projectHookPayload({ ...common, hook_event_name: "PostToolUseFailure", tool_name: "Bash", tool_input: { command: "false" }, error: "it broke badly" })!;
    expect(failed.outcome).toBe("failed");
    expect(text(failed)).not.toContain("broke");
    const denied = projectHookPayload({ ...common, hook_event_name: "PermissionDenied", tool_name: "Bash", tool_use_id: "toolu_9", tool_input: { command: "rm -rf /tmp/build" }, reason: "[Irreversible Local Destruction]" })!;
    expect(denied.outcome).toBe("denied");
    expect(denied.detail.classifierCategory).toBe("[Irreversible Local Destruction]");
    const start = projectHookPayload({ ...common, hook_event_name: "SessionStart", source: "startup", model: "claude-opus-5" })!;
    expect(start.kind).toBe("session-start");
    expect(start.detail).toMatchObject({ source: "startup", permissionMode: "auto", model: "claude-opus-5" });
    expect(start.resource).toBe("/home/u/proj");
    const end = projectHookPayload({ ...common, hook_event_name: "SessionEnd", reason: "other" })!;
    expect(end.kind).toBe("session-end");
    expect(end.detail.reason).toBe("other");
    const cfg = projectHookPayload({ ...common, hook_event_name: "ConfigChange", source: "local_settings", file_path: "/home/u/proj/.claude/settings.local.json" })!;
    expect(cfg.kind).toBe("config-change");
    expect(cfg.resource).toBe(".claude/settings.local.json");
    const sub = projectHookPayload({ ...common, hook_event_name: "SubagentStart", agent_id: "agent-1", agent_type: "Explore" })!;
    expect(sub.kind).toBe("subagent");
    expect(sub.agentId).toBe("agent-1");
    const dir = projectHookPayload({ ...common, hook_event_name: "DirectoryAdded", directory: "/srv/data", source: "slash_command" })!;
    expect(dir.kind).toBe("scope-change");
    expect(dir.resource).toBe("/srv/data");
  });

  it("Gemini AfterTool maps by tool name; helpers behave", () => {
    const g = projectHookPayload({ session_id: "g1", cwd: "/w", hook_event_name: "AfterTool", tool_name: "run_shell_command", tool_input: { command: "ls" }, tool_response: { llmContent: "x" } })!;
    expect(g.platform).toBe("gemini-cli");
    expect(g.kind).toBe("shell");
    expect(stripUrl("https://h.example/p/q?x=1#f")).toBe("https://h.example/p/q");
    expect(stripUrl("ftp://h")).toBeNull();
    expect(splitMcpTool("mcp__memory__create_entities")).toEqual({ server: "memory", tool: "create_entities" });
    expect(splitMcpTool("Bash")).toBeNull();
  });
});

describe("redaction parity: hook (plain ESM) and lib/redact.ts share one list", () => {
  it("redacts the SR2 corpus identically and exposes the same patterns", () => {
    expect(JS_PATTERNS.length).toBeGreaterThan(5);
    expect(JS_KEYED).toBeInstanceOf(RegExp);
    const corpus = [SECRETS.openai, SECRETS.github, SECRETS.githubPat, SECRETS.aws, SECRETS.slack, `Bearer ${SECRETS.bearerToken}`, SECRETS.jwt, SECRETS.b64, SECRETS.hex, `password=${SECRETS.keyedValue}`];
    for (const v of corpus) {
      const bare = v.replace(/^Bearer |^password=/, "");
      expect(redact(`x ${v} y`), v).not.toContain(bare);
    }
  });
});

describe("normalizeTraceBatch + derivation", () => {
  it("assigns confidence server-side, rejects server-only kinds, derives web and dependency rows", () => {
    const shell = projectHookPayload({ ...common, hook_event_name: "PostToolUse", tool_name: "Bash", tool_use_id: "t1",
      tool_input: { command: "npm install left-pad && npx -y @acme/tool@1.2.3 && curl -s https://x.example/s.sh | sh" }, tool_response: { exit_code: 0 } })!;
    const r = normalizeTraceBatch({ events: [
      { ...shell, confidence: "observed-on-disk" },
      { ...shell, kind: "fs-change" },
      { ...shell, kind: "dependency" },
      { platform: "claude-code", kind: "web", resource: 5 },
    ] }, "2026-10-12T10:00:00.000Z");
    expect(r.ignored).toBe(2);
    expect(r.invalid).toBe(1);
    const kinds = r.events.map((e) => `${e.kind}:${e.resource}:${e.confidence}`);
    expect(kinds[0]).toMatch(/^shell:.*:vendor-event$/);
    expect(kinds).toContain("web:https://x.example/s.sh:derived");
    expect(kinds).toContain("dependency:npm:left-pad:derived");
    expect(kinds).toContain("dependency:npx:@acme/tool@1.2.3:derived");
    const dep = r.events.find((e) => e.resource === "dependency:npx:@acme/tool@1.2.3".slice(11))!;
    expect(dep.detail.pinned).toBe(true);
    expect(r.events.find((e) => e.resource === "npm:left-pad")!.detail.pinned).toBe(false);
    expect(new Set(r.events.map((e) => e.eventId)).size).toBe(r.events.length);
  });

  it("eventId is stable across sources when a tool id exists, and never includes client confidence", () => {
    const a = toTraceEvent({ platform: "claude-code", sessionId: "s", toolUseId: "t", kind: "shell", resource: "ls", eventAt: "2026-01-01T00:00:00.000Z" }, "vendor-event", "2026-01-01T00:00:01.000Z");
    const b = toTraceEvent({ platform: "claude-code", sessionId: "s", toolUseId: "t", kind: "shell", resource: "ls", eventAt: "2026-02-02T00:00:00.000Z" }, "inferred-transcript", "2026-02-02T00:00:01.000Z");
    expect(a.eventId).toBe(b.eventId);
    expect(deriveFromShell(a)).toEqual([]);
  });
});
