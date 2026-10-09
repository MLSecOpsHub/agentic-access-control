import { promises as fs } from "fs";
import path from "path";
import { SnapshotSchema, type McpServer, type PermissionRule, type Snapshot } from "./schema";
import { verifyRawSnapshotHash } from "./hash";

// Read side of the pipeline (boundary B3). Snapshots are user-owned files that
// may have been edited since collection — hash verification detects that; the
// UI renders everything escaped regardless.
//
// SR5: integrity is checked on the RAW parsed object, before zod validation —
// zod strips unknown fields, which would otherwise hide appended data (P4).

// AGENTLENS_DATA_DIR relocates the writable data directory (snapshots +
// observed events) — set by the `agentlens` CLI so an npx install never
// writes inside the package; default remains <cwd>/data for a dev clone.
const dataDir = (baseDir: string) => process.env.AGENTLENS_DATA_DIR ?? path.join(baseDir, "data");
const snapshotDir = (baseDir: string) => path.join(dataDir(baseDir), "snapshots");
const fixtureFile = (baseDir: string) => path.join(baseDir, "data", "fixtures", "sample-snapshot.json");

export interface LoadedSnapshot {
  snapshot: Snapshot;
  file: string;
  isFixture: boolean;
  integrityOk: boolean;
}

export interface RuleChange extends PermissionRule {
  instanceId: string;
}

// Field-level MCP change (probe P3): the same server name silently swapping
// its command/URL, args, transport, or env keys is the rug-pull drift must
// surface — added/removed alone misses it.
export interface ServerChange {
  name: string;
  instanceId: string;
  changedFields: string[];
  before: McpServer;
  after: McpServer;
}

export interface Drift {
  previousAt: string;
  addedRules: RuleChange[];
  removedRules: RuleChange[];
  addedServers: McpServer[];
  removedServers: McpServer[];
  changedServers: ServerChange[];
}

// Drift is only computed from two hash-verified snapshots (SR5); otherwise the
// UI states why it is unavailable instead of rendering an unverifiable diff.
export type DriftUnavailableReason =
  | "unverified-current"
  | "unverified-previous"
  | "unreadable-previous";

export interface DashboardData {
  current: LoadedSnapshot;
  drift: Drift | null;
  driftUnavailable: DriftUnavailableReason | null;
}

async function parseSnapshotFile(
  file: string,
): Promise<{ snapshot: Snapshot; integrityOk: boolean }> {
  const raw: unknown = JSON.parse(await fs.readFile(file, "utf8"));
  const integrityOk = verifyRawSnapshotHash(raw); // raw object — BEFORE zod strips unknowns
  return { snapshot: SnapshotSchema.parse(raw), integrityOk };
}

async function listSnapshotFiles(baseDir: string): Promise<string[]> {
  try {
    const dir = snapshotDir(baseDir);
    const entries = await fs.readdir(dir);
    return entries
      .filter((f) => f.endsWith(".json"))
      .sort() // ISO-timestamp filenames sort chronologically
      .reverse()
      .map((f) => path.join(dir, f));
  } catch {
    return [];
  }
}

const ruleKey = (instanceId: string, r: PermissionRule) =>
  `${instanceId}|${r.effect}|${r.matcher}|${r.sourceLevel}`;
const serverKey = (s: McpServer) => `${s.instanceId}|${s.name}`;

// Every security-relevant declaration field participates in the fingerprint.
const SERVER_FINGERPRINT_FIELDS = [
  "transport",
  "commandOrUrl",
  "args",
  "envKeys",
  "declaredTools",
  "enablement",
  "sourceFile",
] as const;

function changedServerFields(before: McpServer, after: McpServer): string[] {
  return SERVER_FINGERPRINT_FIELDS.filter(
    (f) => JSON.stringify(before[f]) !== JSON.stringify(after[f]),
  );
}

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

  const changedServers: ServerChange[] = [];
  for (const [key, after] of curSrv) {
    const before = prevSrv.get(key);
    if (!before) continue;
    const changedFields = changedServerFields(before, after);
    if (changedFields.length > 0) {
      changedServers.push({ name: after.name, instanceId: after.instanceId, changedFields, before, after });
    }
  }

  return {
    previousAt: previous.generatedAt,
    addedRules: [...cur.entries()].filter(([k]) => !prev.has(k)).map(([, v]) => v),
    removedRules: [...prev.entries()].filter(([k]) => !cur.has(k)).map(([, v]) => v),
    addedServers: [...curSrv.entries()].filter(([k]) => !prevSrv.has(k)).map(([, v]) => v),
    removedServers: [...prevSrv.entries()].filter(([k]) => !curSrv.has(k)).map(([, v]) => v),
    changedServers,
  };
}

export async function loadDashboardData(baseDir = process.cwd()): Promise<DashboardData> {
  const files = await listSnapshotFiles(baseDir);

  if (files.length === 0) {
    const file = fixtureFile(baseDir);
    const { snapshot, integrityOk } = await parseSnapshotFile(file);
    return {
      current: { snapshot, file, isFixture: true, integrityOk },
      drift: null,
      driftUnavailable: null,
    };
  }

  const { snapshot, integrityOk } = await parseSnapshotFile(files[0]);
  const current: LoadedSnapshot = { snapshot, file: files[0], isFixture: false, integrityOk };

  let drift: Drift | null = null;
  let driftUnavailable: DriftUnavailableReason | null = null;
  if (files.length > 1) {
    if (!current.integrityOk) {
      driftUnavailable = "unverified-current";
    } else {
      try {
        const previous = await parseSnapshotFile(files[1]);
        if (previous.integrityOk) drift = computeDrift(snapshot, previous.snapshot);
        else driftUnavailable = "unverified-previous";
      } catch {
        driftUnavailable = "unreadable-previous"; // malformed previous snapshot: no drift rather than a crash
      }
    }
  }
  return { current, drift, driftUnavailable };
}
