import { promises as fs } from "fs";
import path from "path";
import { observedDir } from "./ndjson-store";
import { loadDashboardData } from "./snapshot";
import { diffFingerprints, fingerprintTree, type Fingerprint } from "./fs-fingerprint";
import { TRACE_SCHEMA_VERSION, traceEventId, type TraceEvent } from "./trace";
import { appendTraceEvents, loadTraceSession, SESSION_ID_RE } from "./trace-store";

// Session window diff (docs/session-trace.md §8). Server-side and gated: the
// receiver fingerprints a session's cwd only when it lies under a project root
// AgentLens has already been pointed at (latest verified snapshot, or
// AGENTLENS_TRACE_ROOTS) — a forged session-start cannot make the server walk
// an arbitrary directory (T12). Baselines are AgentLens's own files under
// <data>/observed/trace-fs/ and are deleted once diffed or after 7 days.

export type FingerprintStatus = "none" | "started" | "skipped-outside-roots" | "skipped-caps" | "closed" | "no-baseline";

const BASELINE_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const baselineDir = () => path.join(observedDir(), "trace-fs");
const baselineFile = (sessionId: string) => path.join(baselineDir(), `${sessionId}.json`);

interface Baseline extends Fingerprint {
  sessionId: string;
  platform: TraceEvent["platform"];
}

// One walk at a time: a burst of session starts must not fan out into parallel
// tree walks.
let chain: Promise<unknown> = Promise.resolve();
const serialize = <T>(fn: () => Promise<T>): Promise<T> => {
  const next = chain.then(fn, fn);
  chain = next.catch(() => undefined);
  return next;
};

export async function allowedRoots(): Promise<string[]> {
  const roots = new Set<string>();
  for (const r of (process.env.AGENTLENS_TRACE_ROOTS ?? "").split(path.delimiter)) if (r.trim()) roots.add(path.resolve(r.trim()));
  try {
    const { current } = await loadDashboardData();
    if (!current.isFixture && current.integrityOk) {
      for (const inst of current.snapshot.instances) if (inst.projectPath) roots.add(path.resolve(inst.projectPath));
    }
  } catch {
    // no snapshot → env roots only
  }
  return [...roots];
}

const underRoot = (cwd: string, roots: string[]) => {
  const abs = path.resolve(cwd);
  return roots.some((r) => abs === r || abs.startsWith(r + path.sep));
};

async function pruneBaselines(): Promise<void> {
  try {
    for (const f of await fs.readdir(baselineDir())) {
      const file = path.join(baselineDir(), f);
      const st = await fs.stat(file);
      if (Date.now() - st.mtimeMs > BASELINE_TTL_MS) await fs.unlink(file);
    }
  } catch {
    // no baseline dir yet
  }
}

export function onSessionStart(sessionId: string, cwd: string, platform: TraceEvent["platform"]): Promise<FingerprintStatus> {
  return serialize(async () => {
    if (!SESSION_ID_RE.test(sessionId)) return "none";
    await pruneBaselines();
    try {
      await fs.access(baselineFile(sessionId));
      return "none"; // compact/resume: never re-baseline a session
    } catch {
      /* no baseline yet */
    }
    if (!underRoot(cwd, await allowedRoots())) return "skipped-outside-roots";
    const fp = await fingerprintTree(cwd);
    if (fp.truncated) return "skipped-caps";
    const baseline: Baseline = { ...fp, sessionId, platform };
    await fs.mkdir(baselineDir(), { recursive: true });
    await fs.writeFile(baselineFile(sessionId), JSON.stringify(baseline));
    return "started";
  });
}

export function onSessionEnd(sessionId: string): Promise<FingerprintStatus> {
  return serialize(async () => {
    if (!SESSION_ID_RE.test(sessionId)) return "none";
    let baseline: Baseline;
    try {
      baseline = JSON.parse(await fs.readFile(baselineFile(sessionId), "utf8")) as Baseline;
    } catch {
      return "no-baseline";
    }
    const after = await fingerprintTree(baseline.root);
    const session = await loadTraceSession(sessionId);
    const written = new Set((session?.events ?? []).filter((e) => e.kind === "file-write").map((e) => e.resource));
    const receivedAt = new Date().toISOString();
    const events: TraceEvent[] = diffFingerprints(baseline, after).map((c) => {
      const base = {
        schemaVersion: TRACE_SCHEMA_VERSION,
        platform: baseline.platform,
        sessionId,
        promptId: null,
        agentId: null,
        agentType: null,
        toolUseId: null,
        toolName: null,
        kind: "fs-change" as const,
        resource: c.path,
        detail: { change: c.change, matchedWrite: written.has(c.path), ...(after.truncated ? { truncated: after.truncated } : {}) },
        outcome: "ok" as const,
        cwd: baseline.root,
        confidence: "observed-on-disk" as const,
        eventAt: after.takenAt,
        receivedAt,
        platformVersion: null,
      };
      return { ...base, eventId: traceEventId(base) };
    });
    await appendTraceEvents(events);
    await fs.unlink(baselineFile(sessionId)).catch(() => undefined);
    return "closed";
  });
}
