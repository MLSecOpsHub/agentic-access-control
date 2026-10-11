import { createHash } from "crypto";
import type { Snapshot } from "./schema";

// SR5 — tamper-evident snapshots. The hash covers the JSON-serialized body
// with the hash field emptied. The collector must set `hash` LAST, so that a
// parse → clear-hash → re-serialize round trip reproduces the exact bytes.
//
// Verification MUST run on the raw parsed object, before zod validation:
// zod strips unknown fields, so hashing the validated object would let an
// attacker append fields undetected (review probe P4).

export function snapshotHash(snapshot: Snapshot): string {
  const body = JSON.stringify({ ...snapshot, hash: "" });
  return createHash("sha256").update(body).digest("hex");
}

/** Hash over the raw parsed JSON object — unknown fields included. */
export function rawSnapshotHash(raw: Record<string, unknown>): string {
  const body = JSON.stringify({ ...raw, hash: "" });
  return createHash("sha256").update(body).digest("hex");
}

export function verifyRawSnapshotHash(raw: unknown): boolean {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) return false;
  const obj = raw as Record<string, unknown>;
  return typeof obj.hash === "string" && obj.hash === rawSnapshotHash(obj);
}

export function verifySnapshotHash(snapshot: Snapshot): boolean {
  return snapshot.hash === snapshotHash(snapshot);
}

// Content fingerprint for change detection (watch mode). Unlike the SR5 hash
// it ignores `generatedAt` and `hash`, and it is key-order independent so a
// fingerprint seeded from a file on disk agrees with one computed in memory
// (zod re-emits keys in schema order). Never used for integrity.
export function canonicalJson(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(",")}]`;
  if (typeof v === "object" && v !== null) {
    const o = v as Record<string, unknown>;
    const keys = Object.keys(o)
      .filter((k) => o[k] !== undefined)
      .sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(o[k])}`).join(",")}}`;
  }
  return JSON.stringify(v) ?? "null";
}

export function rawContentFingerprint(raw: Record<string, unknown>): string {
  const body: Record<string, unknown> = { ...raw };
  delete body.generatedAt;
  delete body.hash;
  return createHash("sha256").update(canonicalJson(body)).digest("hex");
}

export function contentFingerprint(snapshot: Snapshot): string {
  return rawContentFingerprint(snapshot as unknown as Record<string, unknown>);
}
