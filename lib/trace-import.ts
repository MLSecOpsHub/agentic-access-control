import { createReadStream, promises as fs } from "fs";
import path from "path";
import readline from "readline";
import { projectHookPayload } from "./trace-project.mjs";
import { InboundTraceEventSchema, toTraceEvent, type TraceEvent } from "./trace";
import { deriveFromShell } from "./trace-derive";
import { appendTraceEvents } from "./trace-store";

// Explicit, opt-in transcript import (docs/session-trace.md §14). The user
// names ONE regular file; only tool_use blocks (id, name, input) and the
// is_error flag of tool_result blocks are read, through the same projection
// allowlist as the hook. Prompts, responses and tool outputs are never
// parsed. Best-effort against an undocumented format (T5 class).

export type ImportCode = "ERR_NOT_A_FILE" | "ERR_SYMLINK" | "ERR_SIZE_CAP" | "ERR_TRANSCRIPT_FORMAT";

export interface ImportResult {
  ok: boolean;
  code: ImportCode | null;
  sessionId: string | null;
  linesSeen: number;
  syntaxErrors: number; // ERR_TRANSCRIPT_SYNTAX count
  toolUses: number;
  appended: number;
  duplicates: number;
  formatVersion: string | null;
}

const MAX_FILE_BYTES = 200 * 1024 * 1024;
const MAX_LINE_BYTES = 2 * 1024 * 1024;

const obj = (v: unknown): Record<string, unknown> | null =>
  typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : null;

export async function importTranscript(file: string, opts: { reads?: boolean } = {}): Promise<ImportResult> {
  const res: ImportResult = { ok: false, code: null, sessionId: null, linesSeen: 0, syntaxErrors: 0, toolUses: 0, appended: 0, duplicates: 0, formatVersion: null };
  let st;
  try {
    st = await fs.lstat(file);
  } catch {
    return { ...res, code: "ERR_NOT_A_FILE" };
  }
  if (st.isSymbolicLink()) return { ...res, code: "ERR_SYMLINK" };
  if (!st.isFile()) return { ...res, code: "ERR_NOT_A_FILE" };
  if (st.size > MAX_FILE_BYTES) return { ...res, code: "ERR_SIZE_CAP" };

  const receivedAt = new Date().toISOString();
  const fallbackSession = path.basename(file).replace(/\.jsonl?$/, "").slice(0, 64) || null;
  const events: TraceEvent[] = [];
  const failed = new Set<string>();
  let firstCwd: string | null = null;
  let firstAt: string | null = null;

  const rl = readline.createInterface({ input: createReadStream(file, { encoding: "utf8" }), crlfDelay: Infinity });
  for await (const line of rl) {
    if (!line.trim()) continue;
    res.linesSeen++;
    if (Buffer.byteLength(line) > MAX_LINE_BYTES) {
      res.syntaxErrors++;
      continue;
    }
    let rec: Record<string, unknown> | null;
    try {
      rec = obj(JSON.parse(line));
    } catch {
      res.syntaxErrors++;
      continue;
    }
    if (!rec) {
      res.syntaxErrors++;
      continue;
    }
    const sessionId = typeof rec.sessionId === "string" ? rec.sessionId : fallbackSession;
    const cwd = typeof rec.cwd === "string" ? rec.cwd : null;
    const at = typeof rec.timestamp === "string" && !Number.isNaN(Date.parse(rec.timestamp)) ? new Date(rec.timestamp).toISOString() : receivedAt;
    if (!res.formatVersion && typeof rec.version === "string") res.formatVersion = rec.version;
    if (!res.sessionId && sessionId) res.sessionId = sessionId;
    if (!firstCwd && cwd) firstCwd = cwd;
    if (!firstAt) firstAt = at;
    const message = obj(rec.message);
    const content = Array.isArray(message?.content) ? message!.content : [];
    for (const block of content) {
      const b = obj(block);
      if (!b) continue;
      if (rec.type === "user" && b.type === "tool_result" && b.is_error === true && typeof b.tool_use_id === "string") {
        failed.add(b.tool_use_id);
      }
      if (rec.type !== "assistant" || b.type !== "tool_use" || typeof b.name !== "string") continue;
      res.toolUses++;
      const projected = projectHookPayload(
        { hook_event_name: "PostToolUse", session_id: sessionId, cwd, tool_name: b.name, tool_use_id: typeof b.id === "string" ? b.id : null, tool_input: b.input },
        { reads: opts.reads === true },
      );
      if (!projected) continue;
      const parsed = InboundTraceEventSchema.safeParse({ ...projected, eventAt: at, outcome: "unknown" });
      if (!parsed.success) continue;
      const ev = toTraceEvent(parsed.data, "inferred-transcript", receivedAt);
      events.push(ev);
      if (ev.kind === "shell") events.push(...deriveFromShell(ev).map((d) => ({ ...d, confidence: "inferred-transcript" as const })));
    }
  }
  if (res.toolUses === 0) return { ...res, code: "ERR_TRANSCRIPT_FORMAT" };

  for (const e of events) if (e.toolUseId && failed.has(e.toolUseId)) e.outcome = "failed";
  if (res.sessionId) {
    const start = InboundTraceEventSchema.parse({
      platform: "claude-code", sessionId: res.sessionId, kind: "session-start", resource: firstCwd ?? "", cwd: firstCwd,
      detail: { source: "transcript-import", formatVersion: res.formatVersion ?? "unknown" }, outcome: "ok", eventAt: firstAt ?? receivedAt,
    });
    events.unshift(toTraceEvent(start, "inferred-transcript", receivedAt));
  }
  const stored = await appendTraceEvents(events);
  return { ...res, ok: true, appended: stored.appended, duplicates: stored.duplicates };
}
