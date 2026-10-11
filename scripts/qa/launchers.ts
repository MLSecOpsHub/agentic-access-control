import { spawn } from "child_process";
import { existsSync } from "fs";
import path from "path";
import { claudeOtelEnv } from "../../lib/telemetry-launch";
import { renderHookSettings } from "../../lib/hook-settings";
import type { LabPaths } from "./recipes";

// Session launchers: open a real agent in a lab recipe directory. The launcher
// sets environment variables on ONE child process you explicitly start — it
// never writes agent settings (SR1) and the only endpoint it names is the
// loopback receiver (SR3). Adding an agent = adding a Launcher entry.

export type Agent = "claude" | "gemini" | "codex";

export interface Launcher {
  agent: Agent;
  bin: string; // resolved on PATH; ".cmd" shim on Windows
  telemetryEnv(endpoint: string): Record<string, string> | null; // null = no loopback exporter path yet
  isolatedEnv(lab: LabPaths): Record<string, string>; // HOME-style overrides for --isolated
  preflight(): string | null; // reason the launch cannot proceed, or null
  notice: string; // printed before spawn (SR3/SR4 line)
}

export function onPath(bin: string): boolean {
  const dirs = (process.env.PATH ?? "").split(path.delimiter).filter(Boolean);
  return dirs.some((d) => existsSync(path.join(d, bin)));
}

const claude: Launcher = {
  agent: "claude",
  bin: process.platform === "win32" ? "claude.cmd" : "claude",
  telemetryEnv: (endpoint) => claudeOtelEnv(endpoint),
  isolatedEnv: (lab) => ({ HOME: lab.home, USERPROFILE: lab.home }),
  preflight: () => (onPath(process.platform === "win32" ? "claude.cmd" : "claude") ? null : "`claude` is not on PATH"),
  notice:
    "Launching Claude Code in the recipe directory. Telemetry env (if enabled) applies to this process only and points at the loopback receiver; AgentLens writes no settings. What you see afterwards are configured declarations, not observed attacks (SR4).",
};

export const LAUNCHERS: Partial<Record<Agent, Launcher>> = { claude };

export const PLANNED_AGENTS: Agent[] = ["gemini", "codex"];

export interface LaunchOptions {
  recipeDir: string;
  lab: LabPaths;
  port: number;
  telemetry: boolean;
  isolated: boolean;
  args: string[];
  trace?: { port: number; reads: boolean } | null; // per-process hook settings (docs/session-trace.md §4)
  log?: (line: string) => void;
}

export function launch(agent: Agent, opts: LaunchOptions): Promise<number> {
  const log = opts.log ?? ((l: string) => console.error(l));
  const launcher = LAUNCHERS[agent];
  if (!launcher) {
    log(`qa: launcher for "${agent}" is not implemented yet (planned: ${PLANNED_AGENTS.join(", ")}). Open the recipe directory with the agent yourself: ${opts.recipeDir}`);
    return Promise.resolve(2);
  }
  const blocker = launcher.preflight();
  if (blocker) {
    log(`qa: ${blocker}`);
    return Promise.resolve(2);
  }
  const endpoint = `http://127.0.0.1:${opts.port}/api/otel/v1/logs`;
  const env: NodeJS.ProcessEnv = { ...process.env };
  if (opts.telemetry) {
    const t = launcher.telemetryEnv(endpoint);
    if (t) Object.assign(env, t);
    else log(`qa: ${agent} has no loopback telemetry path; launching without it`);
  }
  if (opts.isolated) {
    Object.assign(env, launcher.isolatedEnv(opts.lab));
    log("qa: --isolated: the agent runs with the lab HOME — no saved credentials or user settings; it may ask you to log in and will write its state under the lab home.");
  }
  const args = [...opts.args];
  if (opts.trace && agent === "claude") {
    args.push("--settings", renderHookSettings({ port: opts.trace.port, reads: opts.trace.reads }));
    log(`qa: session trace on — hook settings passed with --settings apply to this process only; events → http://127.0.0.1:${opts.trace.port}/api/trace/v1/events`);
  }
  log(launcher.notice);
  log(`qa: cwd ${opts.recipeDir}${opts.telemetry ? ` · telemetry → ${endpoint}` : ""}`);
  return new Promise((resolve) => {
    const child = spawn(launcher.bin, args, { cwd: opts.recipeDir, stdio: "inherit", env });
    child.on("error", (err) => {
      log(`qa: failed to start ${launcher.bin}: ${err.message}`);
      resolve(2);
    });
    child.on("exit", (code) => resolve(code ?? 0));
  });
}
