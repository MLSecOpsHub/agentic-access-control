import { normalizeOtlpLogs } from "@/lib/observed";
import { appendEvents } from "@/lib/observed-store";

// Loopback OTLP HTTP/JSON logs receiver — AgentLens's only ingestion listener.
// Reached exclusively via the dashboard server, which binds 127.0.0.1 (SR3).
// Threat model entry: T12. Controls (decision doc §security):
//  - POST + application/json only; body capped BEFORE parsing
//  - event-name and attribute allowlists inside normalizeOtlpLogs
//  - identity attributes never read; raw bodies never logged or retained
//  - errors return fixed codes with no request content echoed (SR2)

export const dynamic = "force-dynamic";

const MAX_BODY_BYTES = 2 * 1024 * 1024;

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

  let envelope: unknown;
  try {
    envelope = JSON.parse(text);
  } catch {
    // fixed code only — malformed payload content is never echoed
    return Response.json({ error: "ERR_JSON_SYNTAX" }, { status: 400 });
  }

  const normalized = normalizeOtlpLogs(envelope, new Date().toISOString());
  const stored = await appendEvents(normalized.events);

  // OTLP-conformant success body; counts are safe metadata, never content.
  return Response.json({
    partialSuccess:
      normalized.invalid > 0
        ? { rejectedLogRecords: normalized.invalid, errorMessage: "ERR_EVENT_VALIDATION" }
        : {},
    agentlens: {
      accepted: stored.appended,
      duplicates: stored.duplicates,
      ignored: normalized.ignored,
      droppedAtCap: stored.droppedAtCap,
    },
  });
}
