import { spawn, type ChildProcess } from "child_process";
import readline from "readline";

// Minimal supervisor for `qa up`: run several long-lived processes with
// prefixed output; if any exits or the user presses Ctrl-C, stop the rest.

export interface Proc {
  name: string;
  cmd: string;
  args: string[];
  env?: NodeJS.ProcessEnv;
  cwd?: string;
}

export function supervise(procs: Proc[]): Promise<number> {
  return new Promise((resolve) => {
    const children: ChildProcess[] = [];
    let stopping = false;
    let exitCode = 0;

    const stopAll = () => {
      if (stopping) return;
      stopping = true;
      for (const c of children) if (c.exitCode === null) c.kill("SIGTERM");
      setTimeout(() => {
        for (const c of children) if (c.exitCode === null) c.kill("SIGKILL");
        resolve(exitCode);
      }, 3000).unref();
      Promise.all(children.map((c) => (c.exitCode === null ? new Promise((r) => c.once("exit", r)) : Promise.resolve()))).then(() =>
        resolve(exitCode),
      );
    };

    for (const p of procs) {
      const child = spawn(p.cmd, p.args, { env: p.env ?? process.env, cwd: p.cwd, stdio: ["ignore", "pipe", "pipe"] });
      children.push(child);
      const prefix = `[${p.name}]`.padEnd(8);
      for (const stream of [child.stdout, child.stderr]) {
        if (!stream) continue;
        readline.createInterface({ input: stream }).on("line", (line) => process.stdout.write(`${prefix} ${line}\n`));
      }
      child.on("exit", (code) => {
        if (!stopping) {
          process.stdout.write(`${prefix} exited (${code ?? "signal"}) — stopping the rest\n`);
          exitCode = code ?? 1;
          stopAll();
        }
      });
    }
    for (const sig of ["SIGINT", "SIGTERM"] as const) process.once(sig, () => stopAll());
  });
}
