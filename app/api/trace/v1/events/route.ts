import { normalizeTraceBatch } from "@/lib/trace";
import { appendTraceEvents } from "@/lib/trace-store";
import { onSessionEnd, onSessionStart, type FingerprintStatus } from "@/lib/trace-fs";

// Loopback session-trace receiver (docs/session-trace.md §5). Same controls as
// the OTLP route (threat T12, extended): POST + application/json only, body
// capped BEFORE parsing, fixed error codes with no payload echo, client-sent
// confidence ignored, server-only kinds rejected. middleware.ts applies the
// loopback-Host check and security headers to this route as well.

export const dynamic = "force-dynamic";

const MAX_BODY_BYTES = 256 * 1024;

export async function POST(req: Request): Promise<Response> {
  const contentType = req.headers.get("content-type") ?? "";
  if (!contentType.toLowerCase().includes("application/json")) {
    return Response.json({ error: "ERR_CONTENT_TYPE" }, { status: 415 });
  }
  const declared = Number(req.headers.get("content-length") ?? "0");
  if (Number.isFinite(declared) && declared > MAX_BODY_BYTES) {
    return Response.json({ error: "ERR_BODY_TOO_LARGE" }, { status: 413 });
  }
  let text: string;
  try {
    text = await req.text();
  } catch {
    return Response.json({ error: "ERR_BODY_READ" }, { status: 400 });
  }
  if (text.length > MAX_BODY_BYTES) {
    return Response.json({ error: "ERR_BODY_TOO_LARGE" }, { status: 413 });
  }
  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    return Response.json({ error: "ERR_JSON_SYNTAX" }, { status: 400 });
  }

  const receivedAt = new Date().toISOString();
  const normalized = normalizeTraceBatch(body, receivedAt, "vendor-event");
  const stored = await appendTraceEvents(normalized.events);

  let fingerprint: FingerprintStatus = "none";
  for (const s of normalized.sessionStarts) fingerprint = await onSessionStart(s.sessionId, s.cwd, s.platform);
  for (const id of normalized.sessionEnds) fingerprint = await onSessionEnd(id);

  return Response.json({
    partialSuccess: normalized.invalid > 0 ? { rejected: normalized.invalid, errorMessage: "ERR_EVENT_VALIDATION" } : {},
    agentlens: {
      accepted: stored.appended,
      duplicates: stored.duplicates,
      ignored: normalized.ignored,
      droppedAtCap: stored.droppedAtCap,
      fingerprint,
    },
  });
}
