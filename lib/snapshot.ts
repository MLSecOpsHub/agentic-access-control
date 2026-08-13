import { promises as fs } from "fs";
import path from "path";
import { SnapshotSchema, type McpServer, type PermissionRule, type Snapshot } from "./schema";
import { verifySnapshotHash } from "./hash";

// Read side of the pipeline (boundary B3). Snapshots are user-owned files that
// may have been edited since collection — hash verification detects that; the
// UI renders everything escaped regardless.

const SNAPSHOT_DIR = path.join(process.cwd(), "data", "snapshots");
const FIXTURE = path.join(process.cwd(), "data", "fixtures", "sample-snapshot.json");

export interface LoadedSnapshot {
  snapshot: Snapshot;
  file: string;
  isFixture: boolean;
  integrityOk: boolean;
}

export interface RuleChange extends PermissionRule {
  instanceId: string;
}

export interface Drift {
  previousAt: string;
  addedRules: RuleChange[];
  removedRules: RuleChange[];
  addedServers: McpServer[];
  removedServers: McpServer[];
}

export interface DashboardData {
  current: LoadedSnapshot;
  drift: Drift | null;
}

async function parseSnapshotFile(file: string): Promise<Snapshot> {
  const raw = await fs.readFile(file, "utf8");
  return SnapshotSchema.parse(JSON.parse(raw));
}

async function listSnapshotFiles(): Promise<string[]> {
  try {
    const entries = await fs.readdir(SNAPSHOT_DIR);
    return entries
      .filter((f) => f.endsWith(".json"))
      .sort() // ISO-timestamp filenames sort chronologically
      .reverse()
      .map((f) => path.join(SNAPSHOT_DIR, f));
  } catch {
    return [];
  }
}

const ruleKey = (instanceId: string, r: PermissionRule) =>
  `${instanceId}|${r.effect}|${r.matcher}|${r.sourceLevel}`;
const serverKey = (s: McpServer) => `${s.instanceId}|${s.name}`;

function flattenRules(s: Snapshot): Map<string, RuleChange> {
  const map = new Map<string, RuleChange>();
  for (const inst of s.instances) {
    for (const r of inst.permissionRules) {
      map.set(ruleKey(inst.id, r), { ...r, instanceId: inst.id });
    }
  }
  return map;
}

export function computeDrift(current: Snapshot, previous: Snapshot): Drift {
  const cur = flattenRules(current);
  const prev = flattenRules(previous);
  const curSrv = new Map(current.mcpServers.map((s) => [serverKey(s), s]));
  const prevSrv = new Map(previous.mcpServers.map((s) => [serverKey(s), s]));

  return {
    previousAt: previous.generatedAt,
    addedRules: [...cur.entries()].filter(([k]) => !prev.has(k)).map(([, v]) => v),
    removedRules: [...prev.entries()].filter(([k]) => !cur.has(k)).map(([, v]) => v),
    addedServers: [...curSrv.entries()].filter(([k]) => !prevSrv.has(k)).map(([, v]) => v),
    removedServers: [...prevSrv.entries()].filter(([k]) => !curSrv.has(k)).map(([, v]) => v),
  };
}

export async function loadDashboardData(): Promise<DashboardData> {
  const files = await listSnapshotFiles();

  if (files.length === 0) {
    const snapshot = await parseSnapshotFile(FIXTURE);
    return {
      current: { snapshot, file: FIXTURE, isFixture: true, integrityOk: verifySnapshotHash(snapshot) },
      drift: null,
    };
  }

  const snapshot = await parseSnapshotFile(files[0]);
  const current: LoadedSnapshot = {
    snapshot,
    file: files[0],
    isFixture: false,
    integrityOk: verifySnapshotHash(snapshot),
  };

  let drift: Drift | null = null;
  if (files.length > 1) {
    try {
      drift = computeDrift(snapshot, await parseSnapshotFile(files[1]));
    } catch {
      drift = null; // malformed previous snapshot: no drift rather than a crash
    }
  }
  return { current, drift };
}
