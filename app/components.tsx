import Link from "next/link";
import type { Effect, RiskFinding, Severity } from "@/lib/schema";
import type { LoadedSnapshot } from "@/lib/snapshot";
import { shortHash, shortPath, timeAgo, isStale } from "@/lib/format";

// Shared server-side presentational pieces. All content renders through React
// escaping — config strings are untrusted (boundary B1); no raw HTML anywhere.

export function EffectBadge({ effect }: { effect: Effect }) {
  return (
    <span className={`badge b-${effect}`}>
      <span className="dot" aria-hidden />
      {effect}
    </span>
  );
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className={`badge b-${severity}`}>
      <span className="dot" aria-hidden />
      {severity}
    </span>
  );
}

const DANGEROUS_MODE = /(bypass|yolo|danger|full-access)/i;

/** Permission mode chip — dangerous modes get critical styling, never color alone. */
export function ModeBadge({ mode }: { mode: string | null }) {
  if (!mode) return <span className="meta">default</span>;
  if (DANGEROUS_MODE.test(mode)) {
    return (
      <span className="badge b-critical">
        <span className="dot" aria-hidden />
        <code>{mode}</code>
      </span>
    );
  }
  return <code>{mode}</code>;
}

export const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export function sortFindings(findings: RiskFinding[]): RiskFinding[] {
  return [...findings].sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
}

export function instanceHref(id: string): string {
  return `/agents/${encodeURIComponent(id)}`;
}

export function SnapshotMeta({ current }: { current: LoadedSnapshot }) {
  const s = current.snapshot;
  return (
    <>
      <p className="meta">
        Snapshot {timeAgo(s.generatedAt)} · machine <code>{s.machineId}</code> · hash{" "}
        <code>{shortHash(s.hash)}</code> · collectors ran: {s.collectors.join(", ")} ·{" "}
        <code>{shortPath(current.file)}</code>
      </p>
      {current.isFixture && (
        <div className="notice">
          Showing the <b>bundled sample fixture</b>. Run <code>npm run collect</code> to snapshot
          this machine.
        </div>
      )}
      {!current.integrityOk && (
        <div className="notice notice-bad">
          <b>Integrity warning (SR5):</b> this snapshot&apos;s content does not match its embedded
          hash — it was modified after collection. Treat every value below as suspect and
          re-collect.
        </div>
      )}
      {!current.isFixture && isStale(s.generatedAt) && (
        <div className="notice notice-warn">
          <b>Stale snapshot:</b> collected {timeAgo(s.generatedAt)}. Permissions may have changed
          since (threat T7) — re-run <code>npm run collect</code>.
        </div>
      )}
    </>
  );
}
