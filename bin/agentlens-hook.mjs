#!/usr/bin/env node
// AgentLens session-trace hook (docs/session-trace.md §4). Runs inside an
// agent session as a vendor "command" hook. Contract, enforced by tests:
//   - reads the vendor payload from stdin only (capped), projects it through
//     the per-tool allowlist and redacts it HERE, before anything leaves the
//     session process (SR2);
//   - POSTs one event to 127.0.0.1:<port> (constant loopback host — the only
//     argument is a port, so an agent that edits settings can repoint a port,
//     never a machine; SR3/T14);
//   - prints nothing, writes no files, always exits 0 within ~1.8 s — exit 0
//     with no output is "no decision" for the vendor, so it can never block,
//     alter a tool result, or feed text back to the model (T14).
import http from "node:http";
import { projectHookPayload, TRACE_SCHEMA_VERSION } from "../lib/trace-project.mjs";

const MAX_STDIN = 4 * 1024 * 1024;
const HARD_EXIT_MS = 1800;

function parseArgs(argv) {
  let port = Number(process.env.AGENTLENS_PORT) || 3000;
  let reads = false;
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--port") port = Number(argv[++i]) || port;
    else if (argv[i].startsWith("--port=")) port = Number(argv[i].slice(7)) || port;
    else if (argv[i] === "--reads") reads = true;
  }
  if (!Number.isInteger(port) || port < 1 || port > 65535) port = 3000;
  return { port, reads };
}

function readStdin() {
  return new Promise((resolve) => {
    const chunks = [];
    let size = 0;
    let over = false;
    process.stdin.on("data", (c) => {
      size += c.length;
      if (size > MAX_STDIN) over = true;
      else chunks.push(c);
    });
    process.stdin.on("end", () => resolve(over ? null : Buffer.concat(chunks).toString("utf8")));
    process.stdin.on("error", () => resolve(null));
  });
}

function post(port, event, timeoutMs) {
  return new Promise((resolve) => {
    const body = JSON.stringify({ schemaVersion: TRACE_SCHEMA_VERSION, events: [event] });
    const req = http.request(
      { host: "127.0.0.1", port, path: "/api/trace/v1/events", method: "POST", headers: { "content-type": "application/json", "content-length": Buffer.byteLength(body) }, timeout: timeoutMs },
      (res) => {
        res.resume();
        res.on("end", resolve);
        res.on("error", resolve);
      },
    );
    req.on("timeout", () => req.destroy());
    req.on("error", resolve);
    req.end(body);
  });
}

async function main() {
  setTimeout(() => process.exit(0), HARD_EXIT_MS).unref();
  const { port, reads } = parseArgs(process.argv.slice(2));
  const text = await readStdin();
  if (text === null) return;
  let payload;
  try {
    payload = JSON.parse(text);
  } catch {
    return;
  }
  const event = projectHookPayload(payload, { reads });
  if (!event) return;
  await post(port, event, event.kind === "session-end" ? 1000 : 1500);
}

main().then(() => process.exit(0), () => process.exit(0));
