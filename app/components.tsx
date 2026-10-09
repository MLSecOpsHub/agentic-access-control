import Link from "next/link";
import type { Effect, RiskFinding, Severity, ScenarioConfidence, ThreatScenario } from "@/lib/schema";
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

export function ConfidenceBadge({ confidence }: { confidence: ScenarioConfidence }) {
  return <span className="pill">{confidence}</span>;
}

export function sortScenarios(scenarios: ThreatScenario[]): ThreatScenario[] {
  return [...scenarios].sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
}

export function ScenarioList({ scenarios }: { scenarios: ThreatScenario[] }) {
  return (
    <div className="tablewrap">
      {scenarios.map((s) => (
        <div key={s.id} className="scenario">
          <details>
            <summary>
              <SeverityBadge severity={s.severity} />
              <ConfidenceBadge confidence={s.confidence} />
              <span className="title">{s.title}</span>
            </summary>
            <div className="scenario-body">
              <h4>Preconditions</h4>
              <ul>
                {s.preconditions.map((p, i) => (
                  <li key={i}>
                    <strong>{p.kind}:</strong> {p.claim}
                    {p.sourceFile && (
                      <div className="meta">
                        Source: <code>{shortPath(p.sourceFile)}</code>
                      </div>
                    )}
                    {p.evidence && (
                      <div className="meta">
                        Evidence: <code>{p.evidence}</code>
                      </div>
                    )}
                  </li>
                ))}
              </ul>
              {s.categories.owaspAsi.length > 0 && (
                <div>
                  <strong>OWASP ASI:</strong> {s.categories.owaspAsi.join(", ")}
                </div>
              )}
              {s.categories.stride.length > 0 && (
                <div>
                  <strong>STRIDE:</strong> {s.categories.stride.join(", ")}
                </div>
              )}
              {s.severanceHints.length > 0 && (
                <div>
                  <strong>Severance hints:</strong>
                  <ul>
                    {s.severanceHints.map((h, i) => (
                      <li key={i}>{h.text}</li>
                    ))}
                  </ul>
                </div>
              )}
              <div className="meta">
                <strong>Caveat:</strong> {s.caveat}
              </div>
            </div>
          </details>
        </div>
      ))}
    </div>
  );
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
