import { z } from "zod";
import { createHash } from "crypto";
import { redact, truncate } from "./redact";
import { TRACE_SCHEMA_VERSION } from "./trace-project.mjs";
import { deriveFromShell } from "./trace-derive";

// Session trace event model (docs/session-trace.md §3). Versioned
// independently of vendor releases. Clients (the hook, the importer) send a
// projected shape; the receiver assigns eventId, receivedAt and confidence —
// confidence is never accepted from a client.

export { TRACE_SCHEMA_VERSION };

export const TraceKindSchema = z.enum([
  "session-start", "session-end", "scope-change", "file-write", "file-read", "shell", "web",
  "dependency", "mcp-call", "skill", "subagent", "config-change", "fs-change",
]);
export type TraceKind = z.infer<typeof TraceKindSchema>;

export const TraceConfidenceSchema = z.enum(["vendor-event", "derived", "observed-on-disk", "inferred-transcript"]);
export type TraceConfidence = z.infer<typeof TraceConfidenceSchema>;

const DetailSchema = z.record(z.string(), z.union([z.string(), z.number(), z.boolean()]));

export const TraceEventSchema = z.object({
  schemaVersion: z.string(),
  eventId: z.string(),
  platform: z.enum(["claude-code", "gemini-cli", "codex-cli"]),
  sessionId: z.string().nullable(),
  promptId: z.string().nullable(),
  agentId: z.string().nullable(),
  agentType: z.string().nullable(),
  toolUseId: z.string().nullable(),
  toolName: z.string().nullable(),
  kind: TraceKindSchema,
  resource: z.string(),
  detail: DetailSchema,
  outcome: z.enum(["ok", "failed", "denied", "unknown"]),
  cwd: z.string().nullable(),
  confidence: TraceConfidenceSchema,
  eventAt: z.string(),
  receivedAt: z.string(),
  platformVersion: z.string().nullable(),
});
export type TraceEvent = z.infer<typeof TraceEventSchema>;

// What a client may send. `dependency` and `fs-change` are server-generated only.
const INBOUND_KINDS = TraceKindSchema.options.filter((k) => k !== "dependency" && k !== "fs-change");
const nstr = (max: number) => z.string().max(4000).nullable().optional();
export const InboundTraceEventSchema = z.object({
  schemaVersion: z.string().optional(),
  platform: z.enum(["claude-code", "gemini-cli", "codex-cli"]),
  sessionId: nstr(64),
  promptId: nstr(64),
  agentId: nstr(64),
  agentType: nstr(100),
  toolUseId: nstr(64),
  toolName: nstr(100),
  kind: z.enum(INBOUND_KINDS as [string, ...string[]]),
  resource: z.string().max(4000),
  detail: DetailSchema.optional(),
  outcome: z.enum(["ok", "failed", "denied", "unknown"]).optional(),
  cwd: nstr(300),
  eventAt: z.string().optional(),
  platformVersion: nstr(64),
});
export type InboundTraceEvent = z.infer<typeof InboundTraceEventSchema>;

export const MAX_EVENTS_PER_BATCH = 100;

const clean = (v: string | null | undefined, max: number): string | null =>
  typeof v === "string" && v.length > 0 ? truncate(redact(v), max) : null;

export function traceEventId(e: Pick<TraceEvent, "platform" | "sessionId" | "toolUseId" | "kind" | "resource" | "eventAt">): string {
  const key = e.toolUseId
    ? `${e.platform}|${e.sessionId}|${e.toolUseId}|${e.kind}|${e.resource}`
    : `${e.platform}|${e.sessionId}|${e.kind}|${e.resource}|${e.eventAt}`;
  return createHash("sha256").update(key).digest("hex").slice(0, 16);
}

export function toTraceEvent(
  input: InboundTraceEvent,
  confidence: TraceConfidence,
  receivedAt: string,
): TraceEvent {
  const detail: Record<string, string | number | boolean> = {};
  for (const [k, v] of Object.entries(input.detail ?? {}).slice(0, 16)) {
    detail[truncate(redact(k), 40)] = typeof v === "string" ? truncate(redact(v), 300) : v;
  }
  const eventAt = input.eventAt && !Number.isNaN(Date.parse(input.eventAt)) ? new Date(input.eventAt).toISOString() : receivedAt;
  const base = {
    schemaVersion: TRACE_SCHEMA_VERSION,
    platform: input.platform,
    sessionId: clean(input.sessionId, 64),
    promptId: clean(input.promptId, 64),
    agentId: clean(input.agentId, 64),
    agentType: clean(input.agentType, 100),
    toolUseId: clean(input.toolUseId, 64),
    toolName: clean(input.toolName, 100),
    kind: input.kind as TraceKind,
    resource: truncate(redact(input.resource), input.kind === "shell" ? 500 : 300),
    detail,
    outcome: input.outcome ?? "unknown",
    cwd: clean(input.cwd, 300),
    confidence,
    eventAt,
    receivedAt,
    platformVersion: clean(input.platformVersion, 64),
  };
  return { ...base, eventId: traceEventId(base) };
}

export interface NormalizeTraceResult {
  events: TraceEvent[];
  seen: number;
  ignored: number; // kinds a client may not send
  invalid: number;
  sessionStarts: Array<{ sessionId: string; cwd: string; platform: TraceEvent["platform"] }>;
  sessionEnds: string[];
}

export function normalizeTraceBatch(body: unknown, receivedAt: string, confidence: TraceConfidence = "vendor-event"): NormalizeTraceResult {
  const out: NormalizeTraceResult = { events: [], seen: 0, ignored: 0, invalid: 0, sessionStarts: [], sessionEnds: [] };
  const raw = typeof body === "object" && body !== null ? (body as Record<string, unknown>) : null;
  const list = Array.isArray(raw?.events) ? raw!.events.slice(0, MAX_EVENTS_PER_BATCH) : [];
  for (const item of list) {
    out.seen++;
    const kind = typeof item === "object" && item !== null ? (item as Record<string, unknown>).kind : undefined;
    if (kind === "dependency" || kind === "fs-change") {
      out.ignored++;
      continue;
    }
    const parsed = InboundTraceEventSchema.safeParse(item);
    if (!parsed.success) {
      out.invalid++;
      continue;
    }
    const ev = toTraceEvent(parsed.data, confidence, receivedAt);
    out.events.push(ev);
    if (ev.kind === "shell") out.events.push(...deriveFromShell(ev));
    if (ev.kind === "session-start" && ev.sessionId && ev.cwd) out.sessionStarts.push({ sessionId: ev.sessionId, cwd: ev.cwd, platform: ev.platform });
    if (ev.kind === "session-end" && ev.sessionId) out.sessionEnds.push(ev.sessionId);
  }
  return out;
}
