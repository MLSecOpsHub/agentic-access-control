import { createHash } from "crypto";
import type { Snapshot } from "./schema";

// SR5 — tamper-evident snapshots. The hash covers the JSON-serialized body
// with the hash field emptied. The collector must set `hash` LAST, so that a
// parse → clear-hash → re-serialize round trip reproduces the exact bytes.

export function snapshotHash(snapshot: Snapshot): string {
  const body = JSON.stringify({ ...snapshot, hash: "" });
  return createHash("sha256").update(body).digest("hex");
}

export function verifySnapshotHash(snapshot: Snapshot): boolean {
  return snapshot.hash === snapshotHash(snapshot);
}
