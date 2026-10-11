import path from "path";
import { fileURLToPath } from "url";
import { renderHookSettings } from "../lib/hook-settings";
import { loadDashboardData } from "../lib/snapshot";
import { loadTraceSession, loadTraceSessions } from "../lib/trace-store";
import { traceFindings, type DeclaredContext } from "../lib/trace-heuristics";
import { renderTraceText, summarizeResources } from "../lib/trace-render";
import { importTranscript } from "../lib/trace-import";
import { onSessionEnd } from "../lib/trace-fs";

// Session-trace CLI (docs/session-trace.md §15):
//   trace list | print <sessionId> [--json] | import <file.jsonl> [--reads] | close <sessionId>
//   hook-settings [--port n] [--with-reads]
// Data dir comes from AGENTLENS_DATA_DIR (set by bin/agentlens.mjs).

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function usage(msg?: string): never {
  if (msg) console.error(`trace: ${msg}`);
  console.error("usage: trace list | print <sessionId> [--json] | import <file.jsonl> [--reads] | close <sessionId> | hook-settings [--port n] [--with-reads]");
  process.exit(2);
}

async function declaredContext(): Promise<DeclaredContext | null> {
  const { current } = await loadDashboardData();
  return current.isFixture ? null : { instances: current.snapshot.instances, mcpServers: current.snapshot.mcpServers, findings: current.snapshot.findings };
}

async function resolveSession(prefix: string) {
  const { sessions } = await loadTraceSessions();
  const matches = sessions.filter((s) => s.sessionId === prefix || s.sessionId.startsWith(prefix));
  if (matches.length === 1) return loadTraceSession(matches[0].sessionId);
  if (matches.length > 1) usage(`"${prefix}" matches ${matches.length} sessions — use more characters`);
  return null;
}

async function main(): Promise<number> {
  const [cmd, ...rest] = process.argv.slice(2);
  const flag = (name: string) => rest.includes(name);
  const value = (name: string) => {
    const i = rest.indexOf(name);
    return i >= 0 ? rest[i + 1] : undefined;
  };
  const positional = rest.filter((a, i) => !a.startsWith("-") && rest[i - 1] !== "--port");

  switch (cmd) {
    case "hook-settings": {
      const port = Number(value("--port") ?? 3000);
      if (!Number.isInteger(port) || port < 1 || port > 65535) usage("--port must be an integer between 1 and 65535");
      process.stdout.write(renderHookSettings({ port, reads: flag("--with-reads"), scriptPath: path.join(REPO_ROOT, "bin", "agentlens-hook.mjs") }) + "\n");
      return 0;
    }
    case "list": {
      const { sessions } = await loadTraceSessions();
      if (sessions.length === 0) console.log("no session traces");
      for (const s of sessions) console.log(`${s.sessionId.slice(0, 12).padEnd(13)} ${s.platform.padEnd(12)} ${s.startedAt.slice(0, 19)} ${s.endedAt ? "closed" : "open  "} ${String(s.eventCount).padStart(4)} events  ${s.cwd ?? ""}`);
      return 0;
    }
    case "print": {
      const id = positional[0];
      if (!id) usage("print needs a session id (prefix accepted)");
      const session = await resolveSession(id);
      if (!session) {
        console.error(`trace: no session matching "${id}"`);
        return 1;
      }
      const declared = await declaredContext();
      const resources = summarizeResources(session.events, declared);
      const findings = traceFindings(session.summary.sessionId, session.events, declared);
      if (flag("--json")) console.log(JSON.stringify({ summary: session.summary, resources, findings, events: session.events }, null, 2));
      else console.log(renderTraceText(session.summary, session.events, resources, findings));
      return 0;
    }
    case "import": {
      const file = positional[0];
      if (!file) usage("import needs a transcript file path");
      const r = await importTranscript(path.resolve(file), { reads: flag("--reads") });
      if (!r.ok) {
        console.error(`trace import: ${r.code}${r.syntaxErrors ? ` (${r.syntaxErrors} unparseable line(s))` : ""}`);
        return 1;
      }
      console.log(`trace import: session ${r.sessionId ?? "?"} · ${r.linesSeen} lines · ${r.toolUses} tool calls · ${r.appended} events stored (${r.duplicates} duplicates)${r.syntaxErrors ? ` · ${r.syntaxErrors} unparseable line(s) skipped` : ""} · format ${r.formatVersion ?? "unknown"} · confidence inferred-transcript`);
      return 0;
    }
    case "close": {
      const id = positional[0];
      if (!id) usage("close needs a session id (prefix accepted)");
      const session = await resolveSession(id);
      if (!session) {
        console.error(`trace: no session matching "${id}"`);
        return 1;
      }
      const status = await onSessionEnd(session.summary.sessionId);
      console.log(`trace close ${session.summary.sessionId.slice(0, 12)}: ${status}`);
      return status === "closed" ? 0 : 1;
    }
    default:
      usage(cmd ? `unknown command "${cmd}"` : undefined);
  }
}

main().then(
  (code) => process.exit(code),
  (err) => {
    console.error("trace failed:", err instanceof Error ? err.constructor.name : String(err));
    process.exit(2);
  },
);
