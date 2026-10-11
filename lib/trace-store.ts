import { TraceEventSchema, type TraceEvent, type TraceKind } from "./trace";
import { createNdjsonStore, type AppendResult } from "./ndjson-store";

// Session trace store: daily `trace-YYYY-MM-DD.ndjson` segments next to the
// observed-event feed, same caps and retention (docs/session-trace.md §9).

const store = createNdjsonStore<TraceEvent>({
  prefix: "trace-",
  stateKey: "__agentlensTrace",
  parse: (raw) => {
    const parsed = TraceEventSchema.safeParse(raw);
    return parsed.success ? parsed.data : null;
  },
});

export const appendTraceEvents = (events: TraceEvent[]): Promise<AppendResult> => store.append(events);

export const SESSION_ID_RE = /^[A-Za-z0-9_-]{1,64}$/;

export interface TraceSessionSummary {
  sessionId: string;
  platform: TraceEvent["platform"];
  cwd: string | null;
  startedAt: string;
  lastAt: string;
  endedAt: string | null;
  /** Last permission mode any event of the session reported (hook payload `permission_mode`). */
  permissionMode: string | null;
  /** Distinct modes in order of first appearance; length > 1 means the mode changed mid-session. */
  permissionModes: string[];
  /** Number of mode transitions between consecutive mode-bearing events. */
  permissionModeChanges: number;
  counts: Record<TraceKind, number>;
  confidences: Record<string, number>;
  eventCount: number;
}

const emptyCounts = (): Record<TraceKind, number> =>
  Object.fromEntries(TraceEventSchema.shape.kind.options.map((k) => [k, 0])) as Record<TraceKind, number>;

export function summarizeSessions(events: TraceEvent[]): TraceSessionSummary[] {
  const by = new Map<string, TraceSessionSummary>();
  for (const e of events) {
    if (!e.sessionId) continue;
    let s = by.get(e.sessionId);
    if (!s) {
      s = { sessionId: e.sessionId, platform: e.platform, cwd: null, startedAt: e.eventAt, lastAt: e.eventAt, endedAt: null, permissionMode: null, permissionModes: [], permissionModeChanges: 0, counts: emptyCounts(), confidences: {}, eventCount: 0 };
      by.set(e.sessionId, s);
    }
    s.eventCount++;
    s.counts[e.kind]++;
    s.confidences[e.confidence] = (s.confidences[e.confidence] ?? 0) + 1;
    if (e.eventAt < s.startedAt) s.startedAt = e.eventAt;
    if (e.eventAt > s.lastAt) s.lastAt = e.eventAt;
    if (e.cwd && (!s.cwd || e.kind === "session-start")) s.cwd = e.cwd;
    if (typeof e.detail.permissionMode === "string" && e.detail.permissionMode.length > 0) {
      const mode = e.detail.permissionMode;
      if (s.permissionMode !== null && s.permissionMode !== mode) s.permissionModeChanges++;
      if (!s.permissionModes.includes(mode)) s.permissionModes.push(mode);
      s.permissionMode = mode;
    }
    if (e.kind === "session-end") s.endedAt = e.eventAt;
  }
  return [...by.values()].sort((a, b) => b.lastAt.localeCompare(a.lastAt));
}

export async function loadTraceEvents(): Promise<{ events: TraceEvent[]; invalidLines: number; droppedAtCap: number }> {
  const loaded = await store.load();
  loaded.events.sort((a, b) => a.eventAt.localeCompare(b.eventAt) || a.receivedAt.localeCompare(b.receivedAt));
  return loaded;
}

export async function loadTraceSessions(): Promise<{ sessions: TraceSessionSummary[]; invalidLines: number; droppedAtCap: number }> {
  const { events, invalidLines, droppedAtCap } = await loadTraceEvents();
  return { sessions: summarizeSessions(events), invalidLines, droppedAtCap };
}

export async function loadTraceSession(sessionId: string): Promise<{ summary: TraceSessionSummary; events: TraceEvent[] } | null> {
  if (!SESSION_ID_RE.test(sessionId)) return null;
  const { events } = await loadTraceEvents();
  const own = events.filter((e) => e.sessionId === sessionId);
  if (own.length === 0) return null;
  return { summary: summarizeSessions(own)[0], events: own };
}
