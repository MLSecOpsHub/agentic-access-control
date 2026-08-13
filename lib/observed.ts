import { z } from "zod";
import { createHash } from "crypto";
import { redact } from "./redact";

// Normalized observed-event model — the runtime side of the evidence-class
// taxonomy (local/live-tracking-final-plan.md). Versioned independently of
// Claude Code releases; raw OTLP envelopes are never retained.

export const OBSERVED_SCHEMA_VERSION = "0.2.0";

export const ObservedEventSchema = z.object({
  schemaVersion: z.string(),
  eventId: z.string(), // deterministic dedup key
  kind: z.enum(["decision", "result", "mode_change", "mcp_connection"]),
  eventAt: z.string(),
  receivedAt: z.string(),
  sessionId: z.string().nullable(),
  promptId: z.string().nullable(),
  sequence: z.number().nullable(),
  toolUseId: z.string().nullable(),
  toolName: z.string().nullable(),
  toolSource: z.string().nullable(),
  decision: z.enum(["accept", "reject"]).nullable(),
  // Broad category only ("config", "user_permanent", …). Deliberately never
  // mapped to a specific native rule — vendor events carry no rule provenance.
  decisionSource: z.string().nullable(),
  execution: z
    .object({
      success: z.boolean().nullable(),
      durationMs: z.number().nullable(),
      errorType: z.string().nullable(),
    })
    .nullable(),
  modeChange: z
    .object({
      from: z.string().nullable(),
      to: z.string().nullable(),
      trigger: z.string().nullable(),
    })
    .nullable(),
  mcpConnection: z
    .object({
      // Vendor emits server_name ONLY when OTEL_LOG_TOOL_DETAILS=1; under the
      // privacy-first default it is intentionally absent — render as withheld,
      // not unknown. Defaults keep pre-0.2.0 stored events parseable.
      serverName: z.string().nullable().default(null),
      status: z.string().nullable().default(null),
      transport: z.string().nullable().default(null),
      scope: z.string().nullable().default(null),
      errorCode: z.string().nullable().default(null),
    })
    .nullable(),
  confidence: z.enum(["vendor-event", "inferred-transcript"]),
  claudeVersion: z.string().nullable(),
});
export type ObservedEvent = z.infer<typeof ObservedEventSchema>;

// --- OTLP HTTP/JSON normalization ------------------------------------------

// Only these vendor events are ingested; everything else is dropped.
const EVENT_KIND: Record<string, ObservedEvent["kind"]> = {
  tool_decision: "decision",
  "claude_code.tool_decision": "decision",
  tool_result: "result",
  "claude_code.tool_result": "result",
  permission_mode_changed: "mode_change",
  "claude_code.permission_mode_changed": "mode_change",
  mcp_server_connection: "mcp_connection",
  "claude_code.mcp_server_connection": "mcp_connection",
};

type OtlpValue = {
  stringValue?: string;
  intValue?: number | string;
  doubleValue?: number;
  boolValue?: boolean;
};
type OtlpAttr = { key?: string; value?: OtlpValue };

function attrMap(attrs: unknown): Map<string, string | number | boolean> {
  const m = new Map<string, string | number | boolean>();
  if (!Array.isArray(attrs)) return m;
  for (const a of attrs as OtlpAttr[]) {
    if (typeof a?.key !== "string" || typeof a.value !== "object" || a.value === null) continue;
    const v = a.value;
    if (typeof v.stringValue === "string") m.set(a.key, v.stringValue);
    else if (v.intValue !== undefined) m.set(a.key, Number(v.intValue));
    else if (typeof v.doubleValue === "number") m.set(a.key, v.doubleValue);
    else if (typeof v.boolValue === "boolean") m.set(a.key, v.boolValue);
  }
  return m;
}

const str = (m: Map<string, unknown>, ...keys: string[]): string | null => {
  for (const k of keys) {
    const v = m.get(k);
    if (typeof v === "string" && v.length > 0) return redact(v).slice(0, 200);
  }
  return null;
};
const num = (m: Map<string, unknown>, ...keys: string[]): number | null => {
  for (const k of keys) {
    const v = m.get(k);
    if (typeof v === "number" && Number.isFinite(v)) return v;
  }
  return null;
};
const bool = (m: Map<string, unknown>, ...keys: string[]): boolean | null => {
  for (const k of keys) {
    const v = m.get(k);
    if (typeof v === "boolean") return v;
    if (v === "true") return true;
    if (v === "false") return false;
  }
  return null;
};

function nanosToIso(nanos: unknown): string | null {
  const n = typeof nanos === "string" ? Number(nanos) : typeof nanos === "number" ? nanos : NaN;
  if (!Number.isFinite(n) || n <= 0) return null;
  return new Date(n / 1e6).toISOString();
}

export interface NormalizeResult {
  events: ObservedEvent[];
  seen: number; // log records inspected
  ignored: number; // records that were not allowlisted events
  invalid: number; // allowlisted events that failed validation
}

/**
 * Normalize an OTLP/HTTP JSON logs envelope into ObservedEvents.
 * Attribute handling is allowlist-only: identity attributes (user.id,
 * user.email, user.account_uuid, organization.id, …) are never read, so they
 * cannot be persisted. Failures are counted, never echoed (SR2).
 */
export function normalizeOtlpLogs(envelope: unknown, receivedAt: string): NormalizeResult {
  const out: NormalizeResult = { events: [], seen: 0, ignored: 0, invalid: 0 };
  const root = envelope as { resourceLogs?: unknown };
  if (!Array.isArray(root?.resourceLogs)) return out;

  for (const rl of root.resourceLogs as Array<Record<string, unknown>>) {
    const resAttrs = attrMap((rl?.resource as Record<string, unknown>)?.attributes);
    const claudeVersion = str(resAttrs, "service.version", "app.version");
    const scopeLogs = rl?.scopeLogs;
    if (!Array.isArray(scopeLogs)) continue;

    for (const sl of scopeLogs as Array<Record<string, unknown>>) {
      const records = sl?.logRecords;
      if (!Array.isArray(records)) continue;

      for (const rec of records as Array<Record<string, unknown>>) {
        out.seen++;
        const attrs = attrMap(rec?.attributes);
        const bodyName =
          typeof (rec?.body as OtlpValue)?.stringValue === "string"
            ? ((rec!.body as OtlpValue).stringValue as string)
            : "";
        const name = (attrs.get("event.name") as string) || bodyName;
        const kind = EVENT_KIND[name];
        if (!kind) {
          out.ignored++;
          continue;
        }

        const eventAt =
          nanosToIso(rec?.timeUnixNano) ?? nanosToIso(rec?.observedTimeUnixNano) ?? receivedAt;
        const sessionId = str(attrs, "session.id", "session_id");
        const sequence = num(attrs, "event.sequence", "sequence");
        const toolUseId = str(attrs, "tool_use_id");

        const candidate: ObservedEvent = {
          schemaVersion: OBSERVED_SCHEMA_VERSION,
          eventId: createHash("sha256")
            .update(`${kind}|${sessionId}|${sequence}|${toolUseId}|${eventAt}`)
            .digest("hex")
            .slice(0, 16),
          kind,
          eventAt,
          receivedAt,
          sessionId,
          promptId: str(attrs, "prompt.id", "prompt_id"),
          sequence,
          toolUseId,
          toolName: str(attrs, "tool_name"),
          toolSource: str(attrs, "tool_source"),
          decision: (() => {
            if (kind !== "decision") return null;
            const d = str(attrs, "decision");
            return d === "accept" || d === "reject" ? d : null; // unknown values → null, event still kept
          })(),
          decisionSource: str(attrs, "source", "decision_source"),
          execution:
            kind === "result"
              ? {
                  success: bool(attrs, "success"),
                  durationMs: num(attrs, "duration_ms"),
                  errorType: str(attrs, "error_type"),
                }
              : null,
          modeChange:
            kind === "mode_change"
              ? {
                  from: str(attrs, "from_mode"),
                  to: str(attrs, "to_mode"),
                  trigger: str(attrs, "trigger"),
                }
              : null,
          mcpConnection:
            kind === "mcp_connection"
              ? {
                  serverName: str(attrs, "server_name"), // detailed mode only
                  status: str(attrs, "status"),
                  transport: str(attrs, "transport_type"),
                  scope: str(attrs, "server_scope"),
                  errorCode: str(attrs, "error_code"),
                }
              : null,
          confidence: "vendor-event",
          claudeVersion,
        };

        const parsed = ObservedEventSchema.safeParse(candidate);
        if (parsed.success) out.events.push(parsed.data);
        else out.invalid++;
      }
    }
  }
  return out;
}
