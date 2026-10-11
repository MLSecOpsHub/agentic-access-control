// Session trace — projection of a vendor hook payload (Claude Code; Gemini
// AfterTool best-effort) to one TraceEvent-shaped object. Plain ESM with no
// dependencies because bin/agentlens-hook.mjs runs it under node inside the
// agent session, before anything leaves that process (SR2). Allowlist per
// tool: fields not named here are never read. docs/session-trace.md §6.

import { redact, truncate } from "./redact-patterns.mjs";

export const TRACE_SCHEMA_VERSION = "0.1.0";

export const TRACE_KINDS = [
  "session-start", "session-end", "scope-change", "file-write", "file-read", "shell", "web",
  "dependency", "mcp-call", "skill", "subagent", "config-change", "fs-change",
];

const FILE_WRITE_TOOLS = new Set(["Write", "Edit", "MultiEdit", "NotebookEdit"]);
const FILE_READ_TOOLS = new Set(["Read", "Grep", "Glob"]);
const GEMINI_EVENTS = new Set(["AfterTool", "BeforeTool", "BeforeAgent", "AfterAgent", "BeforeModel", "AfterModel", "PreCompress"]);
const GEMINI_TOOLS = {
  write_file: "file-write", replace: "file-write",
  run_shell_command: "shell",
  web_fetch: "web", google_web_search: "web",
  read_file: "file-read", glob: "file-read", search_file_content: "file-read", list_directory: "file-read",
};

const str = (v, max = 200) => (typeof v === "string" && v.length > 0 ? truncate(redact(v), max) : null);
const obj = (v) => (typeof v === "object" && v !== null && !Array.isArray(v) ? v : null);

export function relPath(p, cwd) {
  if (typeof p !== "string" || p.length === 0) return null;
  if (typeof cwd === "string" && cwd.length > 0) {
    if (p === cwd) return ".";
    const base = cwd.endsWith("/") ? cwd : cwd + "/";
    if (p.startsWith(base)) return p.slice(base.length);
  }
  return p;
}

// scheme://host/path only — query strings and fragments carry tokens.
export function stripUrl(u) {
  if (typeof u !== "string") return null;
  try {
    const url = new URL(u);
    if (url.protocol !== "http:" && url.protocol !== "https:") return null;
    return `${url.protocol}//${url.host}${url.pathname}`;
  } catch {
    return null;
  }
}

export function splitMcpTool(name) {
  if (typeof name !== "string" || !name.startsWith("mcp__")) return null;
  const rest = name.slice(5);
  const i = rest.indexOf("__");
  if (i <= 0) return { server: rest, tool: null };
  return { server: rest.slice(0, i), tool: rest.slice(i + 2) };
}

const CLASSIFIER_REASON = /^\[[^\]\n]{1,60}\]$/;

function projectTool(payload, platform, outcome, reads) {
  const name = typeof payload.tool_name === "string" ? payload.tool_name : null;
  if (!name) return null;
  const input = obj(payload.tool_input) ?? {};
  const response = obj(payload.tool_response) ?? {};
  const cwd = typeof payload.cwd === "string" ? payload.cwd : null;
  const detail = {};
  let kind = null;
  let resource = null;

  if (platform === "claude-code") {
    const mcp = splitMcpTool(name);
    if (FILE_WRITE_TOOLS.has(name)) {
      kind = "file-write";
      resource = str(relPath(input.file_path ?? input.notebook_path, cwd), 300);
    } else if (name === "Bash") {
      kind = "shell";
      resource = str(input.command, 500);
      if (typeof response.exit_code === "number") detail.exitCode = response.exit_code;
    } else if (name === "WebFetch") {
      kind = "web";
      resource = str(stripUrl(input.url), 300);
      if (typeof response.status_code === "number") detail.statusCode = response.status_code;
    } else if (name === "WebSearch") {
      kind = "web";
      resource = "web-search";
    } else if (mcp) {
      kind = "mcp-call";
      detail.server = str(mcp.server, 100);
      detail.tool = str(mcp.tool, 100);
      resource = `${detail.server ?? "?"}/${detail.tool ?? "?"}`;
    } else if (name === "Skill") {
      kind = "skill";
      resource = str(input.skill ?? input.name ?? input.skill_name ?? input.command, 100);
    } else if (name === "Agent" || name === "Task") {
      kind = "subagent";
      resource = str(input.subagent_type, 100) ?? "subagent";
      detail.phase = "call";
    } else if (FILE_READ_TOOLS.has(name)) {
      if (!reads) return null;
      kind = "file-read";
      const p = relPath(input.file_path ?? input.path ?? cwd, cwd);
      const dir = p === null ? null : name === "Read" ? (p.includes("/") ? p.slice(0, p.lastIndexOf("/")) || "/" : ".") : p;
      resource = str(dir, 300) ?? ".";
    } else {
      return null;
    }
  } else {
    const mapped = GEMINI_TOOLS[name];
    if (name.startsWith("mcp_")) {
      kind = "mcp-call";
      detail.server = null; // Gemini uses single underscores; resolved against declared names server-side
      detail.tool = str(name.slice(4), 100);
      resource = `?/${detail.tool}`;
    } else if (!mapped) {
      return null;
    } else if (mapped === "file-read" && !reads) {
      return null;
    } else {
      kind = mapped;
      if (kind === "file-write" || kind === "file-read") resource = str(relPath(input.file_path ?? input.path ?? input.dir_path, cwd), 300);
      else if (kind === "shell") resource = str(input.command, 500);
      else resource = name === "web_fetch" ? "web-fetch" : "web-search";
    }
    if (obj(response)?.error) outcome = "failed";
  }

  if (kind === "shell" && outcome === "ok" && typeof detail.exitCode === "number" && detail.exitCode !== 0) outcome = "failed";
  if (outcome === "denied" && typeof payload.reason === "string" && CLASSIFIER_REASON.test(payload.reason.trim())) {
    detail.classifierCategory = str(payload.reason.trim(), 64);
  }
  return { kind, resource: resource ?? "", detail, outcome };
}

export function projectHookPayload(payload, opts = {}) {
  const reads = opts.reads === true;
  if (!obj(payload)) return null;
  const ev = typeof payload.hook_event_name === "string" ? payload.hook_event_name : null;
  if (!ev) return null;
  const platform = GEMINI_EVENTS.has(ev) ? "gemini-cli" : "claude-code";
  const cwd = typeof payload.cwd === "string" ? payload.cwd : null;
  const base = {
    schemaVersion: TRACE_SCHEMA_VERSION,
    platform,
    sessionId: str(payload.session_id, 64),
    promptId: str(payload.prompt_id, 64),
    agentId: str(payload.agent_id, 64),
    agentType: str(payload.agent_type, 100),
    toolUseId: str(payload.tool_use_id, 64),
    toolName: str(payload.tool_name, 100),
    cwd: cwd ? redact(cwd) : null,
    eventAt: new Date().toISOString(),
    platformVersion: null,
  };
  let body = null;
  switch (ev) {
    case "SessionStart":
      body = {
        kind: "session-start",
        resource: base.cwd ?? "",
        detail: { source: str(payload.source, 32), permissionMode: str(payload.permission_mode, 32), transcriptPath: str(payload.transcript_path, 300), model: str(payload.model, 64) },
        outcome: "ok",
      };
      break;
    case "SessionEnd":
      body = { kind: "session-end", resource: base.cwd ?? "", detail: { reason: str(payload.reason, 32), permissionMode: str(payload.permission_mode, 32) }, outcome: "ok" };
      break;
    case "SubagentStart":
    case "SubagentStop":
      body = { kind: "subagent", resource: base.agentType ?? "subagent", detail: { phase: ev === "SubagentStart" ? "start" : "stop" }, outcome: "ok" };
      break;
    case "ConfigChange":
      body = { kind: "config-change", resource: str(relPath(payload.file_path, cwd), 300) ?? str(payload.source, 32) ?? "", detail: { source: str(payload.source, 32) }, outcome: "ok" };
      break;
    case "CwdChanged":
      body = { kind: "scope-change", resource: str(payload.new_cwd ?? payload.cwd, 300) ?? "", detail: { change: "cwd", from: str(payload.old_cwd ?? payload.previous_cwd, 300) }, outcome: "ok" };
      break;
    case "DirectoryAdded":
      body = { kind: "scope-change", resource: str(payload.directory, 300) ?? "", detail: { change: "directory-added", source: str(payload.source, 32) }, outcome: "ok" };
      break;
    case "PostToolUse":
    case "AfterTool":
      body = projectTool(payload, platform, "ok", reads);
      break;
    case "PostToolUseFailure":
      body = projectTool(payload, platform, "failed", reads);
      break;
    case "PermissionDenied":
      body = projectTool(payload, platform, "denied", reads);
      break;
    default:
      return null;
  }
  if (!body) return null;
  for (const k of Object.keys(body.detail)) if (body.detail[k] === null || body.detail[k] === undefined) delete body.detail[k];
  return { ...base, ...body };
}
