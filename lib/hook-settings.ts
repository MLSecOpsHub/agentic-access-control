import path from "path";

// The hook configuration a user passes per launch (`claude --settings '<json>'`)
// or pastes into their own settings. AgentLens prints it; it never writes it
// (SR1). Absolute node and script paths per vendor guidance. Matchers are
// anchored tool-name regexes so node does not spawn on every Read/Grep/Glob;
// reads join only with --with-reads (docs/session-trace.md §4).

export const TRACE_TOOL_MATCHER = "^(Write|Edit|MultiEdit|NotebookEdit|Bash|WebFetch|WebSearch|Skill|Agent|mcp__.+)$";
export const TRACE_TOOL_MATCHER_WITH_READS = "^(Write|Edit|MultiEdit|NotebookEdit|Bash|WebFetch|WebSearch|Skill|Agent|Read|Grep|Glob|mcp__.+)$";

export interface HookSettingsOptions {
  port: number;
  reads?: boolean;
  nodePath?: string; // default process.execPath
  scriptPath?: string; // default <package>/bin/agentlens-hook.mjs
}

const quote = (p: string) => (/[\s"']/.test(p) ? JSON.stringify(p) : p);

export function hookCommand(o: HookSettingsOptions): string {
  const node = o.nodePath ?? process.execPath;
  const script = o.scriptPath ?? path.resolve(path.dirname(new URL(import.meta.url).pathname), "..", "bin", "agentlens-hook.mjs");
  return `${quote(node)} ${quote(script)} --port ${o.port}${o.reads ? " --reads" : ""}`;
}

export function hookSettings(o: HookSettingsOptions): { hooks: Record<string, unknown[]> } {
  const command = hookCommand(o);
  const hook = (timeout: number) => ({ type: "command", command, timeout });
  const matcher = o.reads ? TRACE_TOOL_MATCHER_WITH_READS : TRACE_TOOL_MATCHER;
  const tool = { matcher, hooks: [hook(3)] };
  const plain = { hooks: [hook(3)] };
  return {
    hooks: {
      PostToolUse: [tool],
      PostToolUseFailure: [tool],
      PermissionDenied: [tool],
      SessionStart: [plain],
      SessionEnd: [{ hooks: [hook(1)] }],
      SubagentStart: [plain],
      SubagentStop: [plain],
      ConfigChange: [plain],
      CwdChanged: [plain],
      DirectoryAdded: [plain],
    },
  };
}

export const renderHookSettings = (o: HookSettingsOptions): string => JSON.stringify(hookSettings(o));
