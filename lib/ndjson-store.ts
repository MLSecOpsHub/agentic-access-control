import { promises as fs } from "fs";
import path from "path";

// Bounded, append-only, local-only NDJSON store shared by the observed-event
// feed (`events-*`) and the session trace (`trace-*`). data/observed/ is
// gitignored — behavioural history is at least as sensitive as a snapshot.
// AGENTLENS_DATA_DIR relocates all writable data; default ./data.

export const observedDir = () =>
  path.join(process.env.AGENTLENS_DATA_DIR ?? path.join(process.cwd(), "data"), "observed");

export interface AppendResult {
  appended: number;
  duplicates: number;
  droppedAtCap: number;
}

export interface LoadResult<T> {
  events: T[];
  invalidLines: number;
  droppedAtCap: number;
}

interface DedupState {
  ids: Set<string>;
  seededFor: string | null;
  dropped: number;
}

export interface NdjsonStoreOptions<T extends { eventId: string }> {
  prefix: string; // segment file prefix, e.g. "events-" or "trace-"
  stateKey: string; // globalThis key for the in-memory dedup state
  parse: (raw: unknown) => T | null;
  maxSegmentBytes?: number; // per-day cap; excess events are counted, not stored
  retainSegments?: number;
}

export function createNdjsonStore<T extends { eventId: string }>(opts: NdjsonStoreOptions<T>) {
  const maxSegmentBytes = opts.maxSegmentBytes ?? 10 * 1024 * 1024;
  const retainSegments = opts.retainSegments ?? 7;
  // In-memory dedup, seeded from the current segment on first use. Survives
  // route hot-reloads via globalThis; cross-day duplicates are acceptable residue.
  const g = globalThis as unknown as Record<string, DedupState | undefined>;
  const state: DedupState = (g[opts.stateKey] ??= { ids: new Set(), seededFor: null, dropped: 0 });
  const segmentFile = (d = new Date()) => path.join(observedDir(), `${opts.prefix}${d.toISOString().slice(0, 10)}.ndjson`);
  const isSegment = (f: string) => f.startsWith(opts.prefix) && f.endsWith(".ndjson");

  async function seedDedup(file: string): Promise<void> {
    if (state.seededFor === file) return;
    state.ids.clear();
    state.seededFor = file;
    try {
      const raw = await fs.readFile(file, "utf8");
      for (const line of raw.split("\n")) {
        if (!line) continue;
        try {
          const id = (JSON.parse(line) as { eventId?: unknown }).eventId;
          if (typeof id === "string") state.ids.add(id);
        } catch {
          // corrupt line: ignored here; surfaced by load as invalid
        }
      }
    } catch {
      // no segment yet
    }
  }

  async function pruneOldSegments(): Promise<void> {
    try {
      const files = (await fs.readdir(observedDir())).filter(isSegment).sort();
      for (const f of files.slice(0, Math.max(0, files.length - retainSegments))) {
        await fs.unlink(path.join(observedDir(), f));
      }
    } catch {
      // best-effort retention
    }
  }

  async function append(events: T[]): Promise<AppendResult> {
    const res: AppendResult = { appended: 0, duplicates: 0, droppedAtCap: 0 };
    if (events.length === 0) return res;
    await fs.mkdir(observedDir(), { recursive: true });
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
      if (size > maxSegmentBytes) {
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

  /** Newest `segments` daily files (all retained when undefined), unsorted. */
  async function load(segments?: number): Promise<LoadResult<T>> {
    const out: LoadResult<T> = { events: [], invalidLines: 0, droppedAtCap: state.dropped };
    let files: string[] = [];
    try {
      files = (await fs.readdir(observedDir())).filter(isSegment).sort().reverse();
      if (segments !== undefined) files = files.slice(0, segments);
    } catch {
      return out;
    }
    for (const f of files) {
      let raw = "";
      try {
        raw = await fs.readFile(path.join(observedDir(), f), "utf8");
      } catch {
        continue;
      }
      for (const line of raw.split("\n")) {
        if (!line) continue;
        try {
          const parsed = opts.parse(JSON.parse(line));
          if (parsed) out.events.push(parsed);
          else out.invalidLines++;
        } catch {
          out.invalidLines++;
        }
      }
    }
    return out;
  }

  return { append, load, droppedTotal: () => state.dropped };
}
