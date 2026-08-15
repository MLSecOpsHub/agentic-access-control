import { promises as fs } from "fs";
import path from "path";
import { ObservedEventSchema, type ObservedEvent } from "./observed";

// Bounded, append-only, local-only store for observed events.
// data/observed/ is gitignored — behavioral history is at least as sensitive
// as a configuration snapshot (decision doc §security).

// Resolved per call so the test suite can isolate storage (AGENTLENS_DATA_DIR
// is a test seam, not a user-facing setting; default remains ./data).
const obsDir = () =>
  path.join(process.env.AGENTLENS_DATA_DIR ?? path.join(process.cwd(), "data"), "observed");
const MAX_SEGMENT_BYTES = 10 * 1024 * 1024; // per-day cap; excess events are counted, not stored
const RETAIN_SEGMENTS = 7;

const segmentFile = (d = new Date()) => path.join(obsDir(), `events-${d.toISOString().slice(0, 10)}.ndjson`);

// In-memory dedup, seeded from the current segment on first use. Survives
// route hot-reloads via globalThis; cross-day duplicates are acceptable residue.
type DedupState = { ids: Set<string>; seededFor: string | null; dropped: number };
const g = globalThis as { __agentlensObserved?: DedupState };
const state: DedupState = (g.__agentlensObserved ??= { ids: new Set(), seededFor: null, dropped: 0 });

async function seedDedup(file: string): Promise<void> {
  if (state.seededFor === file) return;
  state.ids.clear();
  state.seededFor = file;
  try {
    const raw = await fs.readFile(file, "utf8");
    for (const line of raw.split("\n")) {
      if (!line) continue;
      try {
        const id = (JSON.parse(line) as ObservedEvent).eventId;
        if (typeof id === "string") state.ids.add(id);
      } catch {
        // corrupt line: ignored here; surfaced by loadRecentEvents as invalid
      }
    }
  } catch {
    // no segment yet
  }
}

async function pruneOldSegments(): Promise<void> {
  try {
    const files = (await fs.readdir(obsDir())).filter((f) => f.startsWith("events-") && f.endsWith(".ndjson")).sort();
    for (const f of files.slice(0, Math.max(0, files.length - RETAIN_SEGMENTS))) {
      await fs.unlink(path.join(obsDir(), f));
    }
  } catch {
    // best-effort retention
  }
}

export interface AppendResult {
  appended: number;
  duplicates: number;
  droppedAtCap: number;
}

export async function appendEvents(events: ObservedEvent[]): Promise<AppendResult> {
  const res: AppendResult = { appended: 0, duplicates: 0, droppedAtCap: 0 };
  if (events.length === 0) return res;
  await fs.mkdir(obsDir(), { recursive: true });
  const file = segmentFile();
  await seedDedup(file);
  await pruneOldSegments();

  let size = 0;
  try {
    size = (await fs.stat(file)).size;
  } catch {
    /* new segment */
  }

  const lines: string[] = [];
  for (const e of events) {
    if (state.ids.has(e.eventId)) {
      res.duplicates++;
      continue;
    }
    if (size > MAX_SEGMENT_BYTES) {
      res.droppedAtCap++;
      state.dropped++;
      continue;
    }
    const line = JSON.stringify(e);
    size += line.length + 1;
    lines.push(line);
    state.ids.add(e.eventId);
    res.appended++;
  }
  if (lines.length > 0) await fs.appendFile(file, lines.join("\n") + "\n");
  return res;
}

export interface ObservedFeed {
  events: ObservedEvent[]; // newest first
  invalidLines: number;
  droppedAtCap: number;
  lastEventAt: string | null;
}

export async function loadRecentEvents(limit = 200): Promise<ObservedFeed> {
  const feed: ObservedFeed = { events: [], invalidLines: 0, droppedAtCap: state.dropped, lastEventAt: null };
  let files: string[] = [];
  try {
    files = (await fs.readdir(obsDir())).filter((f) => f.startsWith("events-") && f.endsWith(".ndjson")).sort().reverse().slice(0, 2);
  } catch {
    return feed;
  }
  for (const f of files) {
    let raw = "";
    try {
      raw = await fs.readFile(path.join(obsDir(), f), "utf8");
    } catch {
      continue;
    }
    for (const line of raw.split("\n")) {
      if (!line) continue;
      try {
        const parsed = ObservedEventSchema.safeParse(JSON.parse(line));
        if (parsed.success) feed.events.push(parsed.data);
        else feed.invalidLines++;
      } catch {
        feed.invalidLines++;
      }
    }
  }
  feed.events.sort((a, b) => b.eventAt.localeCompare(a.eventAt) || (b.sequence ?? 0) - (a.sequence ?? 0));
  feed.lastEventAt = feed.events[0]?.receivedAt ?? null;
  feed.events = feed.events.slice(0, limit);
  return feed;
}
