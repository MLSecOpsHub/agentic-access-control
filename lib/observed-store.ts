import { ObservedEventSchema, type ObservedEvent } from "./observed";
import { createNdjsonStore, type AppendResult } from "./ndjson-store";

// Observed-event feed store (/live): daily `events-YYYY-MM-DD.ndjson`
// segments under <data>/observed, 10 MiB per day, 7 days retained. The
// mechanics live in ndjson-store.ts, shared with the session trace.

export type { AppendResult };

const store = createNdjsonStore<ObservedEvent>({
  prefix: "events-",
  stateKey: "__agentlensObserved",
  parse: (raw) => {
    const parsed = ObservedEventSchema.safeParse(raw);
    return parsed.success ? parsed.data : null;
  },
});

export const appendEvents = (events: ObservedEvent[]): Promise<AppendResult> => store.append(events);

export interface ObservedFeed {
  events: ObservedEvent[]; // newest first
  invalidLines: number;
  droppedAtCap: number;
  lastEventAt: string | null;
}

export async function loadRecentEvents(limit = 200): Promise<ObservedFeed> {
  const loaded = await store.load(2);
  const events = [...loaded.events].sort(
    (a, b) => b.eventAt.localeCompare(a.eventAt) || (b.sequence ?? 0) - (a.sequence ?? 0),
  );
  return {
    events: events.slice(0, limit),
    invalidLines: loaded.invalidLines,
    droppedAtCap: loaded.droppedAtCap,
    lastEventAt: events[0]?.receivedAt ?? null,
  };
}
