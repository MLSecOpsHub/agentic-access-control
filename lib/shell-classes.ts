import type { TraceEvent } from "./trace";
import { HOME_OR_CONFIG_PATH } from "./scenario-catalog";
import { MANAGER_RE, specsFrom } from "./trace-derive";

// Shell-command classification for the session trace (docs/session-trace.md
// §10/§12). A command string is split into segments and each segment is
// matched on its PROGRAM and ARGUMENT TOKENS — never on the raw substring —
// so `npm test -- --grep kill` is not a process command and `echo "sudo x"`
// is not privileged. Classes are a display facet; a small subset of patterns
// is *promoted* to the observed finding O6 (lib/trace-heuristics.ts). Nothing
// here is persisted: the store stays class-agnostic and the rules can change
// without a schema bump. The command was declared; whether it ran as parsed
// is known only through the exit code (SR4).

export type ShellClass = "vcs" | "install" | "network" | "fs-destructive" | "privileged" | "process" | "exfil-shaped";
export const SHELL_CLASSES: ShellClass[] = ["vcs", "install", "network", "fs-destructive", "privileged", "process", "exfil-shaped"];

export const SHELL_CLASS_TEXT: Record<ShellClass, string> = {
  vcs: "git / gh / hg / svn invocations",
  install: "package-manager installs (npm, pip, uv, cargo, go, brew, apt, …) — also derived into dependency rows",
  network: "programs that open network connections (curl, wget, ssh, scp, rsync, nc, …), URLs in arguments, git clone/fetch/pull/push",
  "fs-destructive": "recursive or out-of-tree deletes, truncate, shred, dd/mkfs onto devices, git clean -f / reset --hard / push --force",
  privileged: "sudo/doas/su wrappers, chmod with world-writable or setuid bits, chown, service/cron/firewall/mount/user-account mutations",
  process: "kill/pkill/killall, background jobs, nohup/setsid/disown, pm2 lifecycle",
  "exfil-shaped": "upload-shaped network use: curl/wget with a body or upload flag, scp/rsync/sftp to a remote, nc/socat fed from a pipe, or a network command in a pipeline that names a credential path — a shape, not an intent",
};

export type Separator = "start" | "and" | "or" | "seq" | "pipe";
export type PromotionKind = "destructive" | "privileged" | "upload-shaped" | "remote-shell-shaped" | "process-terminating";

export interface Promotion {
  pattern: string;
  kind: PromotionKind;
  target?: string;
  /** Qualifies for severity "high" (with exit code 0): target outside the cwd, a credential path, a device, or an inherently remote-shell/upload shape. */
  strong: boolean;
  note?: string;
}

export interface ShellSegment {
  text: string;
  sep: Separator;
  /** Terminated by a single `&` (background job). */
  background: boolean;
  program: string | null;
  elevated: boolean;
  classes: ShellClass[];
  targets: string[];
  promotions: Promotion[];
}

export interface ShellClassification {
  classes: ShellClass[];
  segments: ShellSegment[];
}

// ---- splitting and tokenising -------------------------------------------------

export function splitSegments(command: string): Array<{ text: string; sep: Separator; background: boolean }> {
  const out: Array<{ text: string; sep: Separator; background: boolean }> = [];
  let buf = "";
  let sep: Separator = "start";
  let quote: '"' | "'" | null = null;
  const flush = (next: Separator, background = false) => {
    if (buf.trim().length > 0) out.push({ text: buf.trim(), sep, background });
    buf = "";
    sep = next;
  };
  for (let i = 0; i < command.length; i++) {
    const c = command[i];
    const n = command[i + 1];
    const p = command[i - 1];
    if (quote) {
      buf += c;
      if (c === quote && p !== "\\") quote = null;
      continue;
    }
    if (c === '"' || c === "'") { quote = c; buf += c; continue; }
    if (c === "&" && n === "&") { flush("and"); i++; continue; }
    if (c === "|" && n === "|") { flush("or"); i++; continue; }
    if (c === "|") { flush("pipe"); continue; }
    if (c === ";" || c === "\n") { flush("seq"); continue; }
    if (c === "&" && n !== ">" && p !== ">" && p !== "<" && n !== "&") { flush("seq", true); continue; }
    buf += c;
  }
  flush("start");
  return out;
}

const TOKEN_RE = /"[^"]*"|'[^']*'|\S+/g;
const unquote = (t: string) => (t.length >= 2 && ((t.startsWith('"') && t.endsWith('"')) || (t.startsWith("'") && t.endsWith("'"))) ? t.slice(1, -1) : t);
export const tokenize = (text: string): string[] => (text.match(TOKEN_RE) ?? []).map(unquote);

const ELEVATING = new Set(["sudo", "doas", "su", "pkexec"]);
const WRAPPERS = new Set([...ELEVATING, "env", "nohup", "setsid", "time", "command", "exec", "nice", "xargs", "timeout", "builtin"]);
const NEVER_CLASSIFY = new Set(["echo", "printf", "#", "true", ":", "test", "["]);
const SHELLS = new Set(["sh", "bash", "zsh", "dash", "ksh", "fish"]);
const SHELL_KEYWORDS = new Set(["do", "then", "else", "elif", "if", "while", "until", "!", "{", "("]);
const basename = (t: string) => t.slice(t.lastIndexOf("/") + 1);

interface Parsed { program: string | null; args: string[]; elevated: boolean; detached: boolean; inner: string | null }

function parseSegment(tokens: string[]): Parsed {
  let i = 0;
  let elevated = false;
  let detached = false;
  // subshell / group openers glued to the first token, and shell keywords (`for … do curl`, `if ! cmd`)
  if (tokens.length > 0) tokens = [tokens[0].replace(/^[({]+/, ""), ...tokens.slice(1)].filter((t) => t.length > 0);
  while (i < tokens.length && (SHELL_KEYWORDS.has(tokens[i]) || /^[A-Za-z_][A-Za-z0-9_]*=/.test(tokens[i]))) i++; // keywords and VAR=val prefixes
  let program: string | null = null;
  let inner: string | null = null;
  while (i < tokens.length) {
    const t = basename(tokens[i]);
    if (!WRAPPERS.has(t)) { program = t; i++; break; }
    if (ELEVATING.has(t)) elevated = true;
    if (t === "nohup" || t === "setsid") detached = true;
    i++;
    // wrapper options: `sudo -u root`, `su -c "cmd"`, `env VAR=x`, `timeout 5`, `nice -n 10`
    while (i < tokens.length) {
      const o = tokens[i];
      if ((t === "su" || t === "sudo" || t === "doas") && o === "-c" && tokens[i + 1] !== undefined) { inner = tokens[i + 1]; i = tokens.length; break; }
      if (o === "-c" && (t === "su" || t === "sudo" || t === "doas")) { i++; continue; }
      if (o.startsWith("-") && o !== "--") { i++; if ((o === "-u" || o === "-g" || o === "-n" || o === "-s") && tokens[i] && !tokens[i].startsWith("-")) i++; continue; }
      if (o === "--") { i++; continue; }
      if (t === "env" && /^[A-Za-z_][A-Za-z0-9_]*=/.test(o)) { i++; continue; }
      if (t === "timeout" && /^\d/.test(o)) { i++; continue; }
      if (t === "su" && /^[a-z_][a-z0-9_-]*$/.test(o) && tokens[i + 1] === "-c") { i++; continue; } // su root -c
      break;
    }
  }
  const args = tokens.slice(i);
  if (program && SHELLS.has(program)) {
    const c = args.indexOf("-c");
    if (c >= 0 && args[c + 1] !== undefined) inner = args[c + 1];
  }
  return { program, args, elevated, detached, inner };
}

// ---- targets --------------------------------------------------------------------

const TMP_RE = /^(\/tmp|\/var\/tmp|\/private\/tmp|\$TMPDIR)(\/|$)/;
const DEVICE_RE = /^\/dev\/(sd[a-z]|nvme\d|hd[a-z]|vd[a-z]|xvd[a-z]|mmcblk\d|disk\d|loop\d|mapper\/|md\d|dm-\d|nbd\d)/;
export const CREDENTIAL_PATH = /(^|[\s/@=:'"])(\.aws|\.ssh|\.gnupg|\.netrc|\.kube|\.docker\/config\.json|\.npmrc|\.pypirc|\.git-credentials|\.env(\.[A-Za-z]+)?|credentials|id_(rsa|ed25519|ecdsa|dsa)|[A-Za-z_-]*token[A-Za-z_-]*\.(json|txt|pem)?|\.pem|\.p12|\.key)(\b|$)/;

export interface TargetFlags { outside: boolean; credential: boolean; device: boolean; tmp: boolean }

export function targetFlags(target: string, cwd: string | null): TargetFlags {
  const t = target.replace(/^["']|["']$/g, "");
  const device = DEVICE_RE.test(t);
  const credential = CREDENTIAL_PATH.test(t);
  const tmp = TMP_RE.test(t);
  let outside = false;
  if (t.startsWith("~") || t.startsWith("$HOME") || t.startsWith("${HOME}")) outside = true;
  else if (t.startsWith("/")) {
    const inCwd = cwd !== null && (t === cwd || t.startsWith(cwd.replace(/\/$/, "") + "/"));
    outside = !inCwd && !tmp && !device;
  } else if (t === ".." || t.startsWith("../")) outside = true;
  else if (/\/\.\.(\/|$)/.test(t)) outside = true;
  return { outside, credential, device, tmp };
}

const isFlag = (t: string) => t.startsWith("-") && t !== "-";
const positional = (args: string[]) => args.filter((a) => !isFlag(a));
const hasFlag = (args: string[], re: RegExp) => args.some((a) => re.test(a));

// ---- classes --------------------------------------------------------------------

const VCS = new Set(["git", "gh", "hg", "svn"]);
const NET = new Set(["curl", "wget", "ssh", "scp", "sftp", "rsync", "nc", "ncat", "netcat", "socat", "telnet", "ftp", "aria2c", "http", "xh", "httpie"]);
const NET_GIT_VERBS = new Set(["clone", "fetch", "pull", "push", "ls-remote", "remote"]);
const PRIV_PROGRAMS = new Set(["iptables", "ip6tables", "nft", "ufw", "pfctl", "mount", "umount", "useradd", "userdel", "usermod", "groupadd", "passwd", "chpasswd", "visudo", "setcap", "modprobe", "insmod", "rmmod", "fdisk", "parted", "sfdisk", "csrutil", "spctl", "tccutil", "dscl", "chroot", "setenforce"]);
const SERVICE_VERBS = /^(start|stop|restart|reload|enable|disable|mask|unmask|daemon-reload|load|unload|bootstrap|bootout|kickstart)$/;
const KILLERS = new Set(["kill", "pkill", "killall"]);
const AGENT_PROCESS = /(claude|gemini|codex|agentlens|node|ssh-agent|gpg-agent|sshd|dockerd|containerd)/i;
const PKG_INSTALL_PROGRAMS = new Set(["apt", "apt-get", "brew", "dnf", "yum", "pacman", "apk", "zypper"]);
const REMOTE_TARGET = /^([A-Za-z0-9._-]+@)?[A-Za-z0-9._-]+:(\/|~|[^/]|$)|^rsync:\/\//;

function worldWritableMode(mode: string): boolean {
  if (/^[0-7]{3,4}$/.test(mode)) {
    const last = Number(mode[mode.length - 1]);
    const setuid = mode.length === 4 && mode[0] !== "0";
    return [2, 3, 6, 7].includes(last) || setuid;
  }
  return /(^|,)([ugoa]*o[ugoa]*|a|)\+[rx]*w|(^|,)[ugoa]*\+[rwx]*s/.test(mode) && !/^[ug]+\+[rx]*w$/.test(mode);
}

function classifyOne(parsed: Parsed, text: string, sep: Separator, background: boolean, cwd: string | null, groupText: string): Pick<ShellSegment, "classes" | "targets" | "promotions"> {
  const classes = new Set<ShellClass>();
  const promotions: Promotion[] = [];
  const { program, args, elevated, detached } = parsed;
  const pos = positional(args);
  const targets: string[] = [];
  const add = (p: Promotion) => promotions.push(p);
  if (!program) return { classes: [], targets, promotions };
  // Rules that do not depend on the program: elevation, background, redirections onto devices/config.
  if (elevated) {
    classes.add("privileged");
    const verb0 = pos[0] ?? "";
    const pkgInstall = PKG_INSTALL_PROGRAMS.has(program) && /^(install|update|upgrade|-S[a-z]*|-Syu?)$/.test(verb0);
    if (!pkgInstall) add({ pattern: "sudo-wrapper", kind: "privileged", strong: false, note: "elevated via sudo/doas/su" });
  }
  if (background || detached) classes.add("process");
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    const redir = /^(\d?>>?|&>)(.*)$/.exec(a);
    if (!redir) continue;
    const t = redir[2] || args[i + 1];
    if (!t || t.startsWith("&")) continue;
    if (DEVICE_RE.test(t)) { classes.add("fs-destructive"); targets.push(t); add({ pattern: "device-clobber", kind: "destructive", strong: true, target: t, note: `device: ${t}` }); }
    else if (HOME_OR_CONFIG_PATH.test(t) && !redir[1].endsWith(">>")) { classes.add("fs-destructive"); targets.push(t); }
  }
  if (NEVER_CLASSIFY.has(program)) return { classes: [...classes], targets, promotions };
  const verb = pos[0] ?? "";
  const flagsOf = (t: string) => targetFlags(t, cwd);
  const outsideNote = (t: string, f: TargetFlags) =>
    f.device ? `device: ${t}` : f.credential && f.outside ? `target outside the session working directory, credential-bearing path: ${t}` : f.outside ? `target outside the session working directory: ${t}` : f.credential ? `credential-bearing path: ${t}` : undefined;

  // vcs
  if (VCS.has(program)) {
    classes.add("vcs");
    if (program === "git" && NET_GIT_VERBS.has(verb)) classes.add("network");
    if (program === "git") {
      if ((verb === "clean" && hasFlag(args, /^-[a-zA-Z]*f/)) || (verb === "reset" && args.includes("--hard"))) classes.add("fs-destructive");
      if (verb === "push" && (hasFlag(args, /^--force(-with-lease|-if-includes)?$/) || args.includes("-f") || pos.some((p) => p.startsWith("+")))) {
        classes.add("fs-destructive");
        add({ pattern: "git-force-push", kind: "destructive", strong: false, target: pos.slice(1).join(" ") || undefined });
      }
    }
  }
  // install
  const m = MANAGER_RE.exec(text.replace(/^(sudo|doas)\s+/, ""));
  if (m) {
    const v = (m[2].trim().split(/\s+/)[0] ?? "");
    if (specsFrom(m[1], m[2]).length > 0 || /^(install|i|ci|add|sync|get|update|upgrade)$/.test(v) || m[1] === "uvx" || (m[1] === "npx" && /\s-y\b|--yes/.test(m[2]))) classes.add("install");
  } else if (PKG_INSTALL_PROGRAMS.has(program) && /^(install|update|upgrade|add|-S[a-z]*)$/.test(verb)) classes.add("install");
  // network
  if (NET.has(program) || args.some((a) => /^https?:\/\//.test(a))) classes.add("network");
  if ((program === "scp" || program === "rsync" || program === "sftp") && pos.some((p) => REMOTE_TARGET.test(p))) classes.add("network");
  // fs-destructive
  if (program === "rm") {
    const recursive = hasFlag(args, /^-[a-zA-Z]*[rR]|^--recursive$/);
    for (const t of pos) {
      const f = flagsOf(t);
      targets.push(t);
      if (recursive || t.startsWith("/") || t.startsWith("~") || t.startsWith("$HOME")) classes.add("fs-destructive");
      if (f.outside || f.credential) add({ pattern: "rm-outside", kind: "destructive", strong: true, target: t, note: outsideNote(t, f) });
    }
  }
  if (program === "rmdir") { classes.add("fs-destructive"); targets.push(...pos); for (const t of pos) { const f = flagsOf(t); if (f.outside) add({ pattern: "rm-outside", kind: "destructive", strong: true, target: t, note: outsideNote(t, f) }); } }
  if (program === "find" && (args.includes("-delete") || (args.includes("-exec") && args[args.indexOf("-exec") + 1] !== undefined && basename(args[args.indexOf("-exec") + 1]) === "rm"))) {
    classes.add("fs-destructive");
    const root = args.find((a) => !a.startsWith("-")) ?? ".";
    targets.push(root);
    const f = flagsOf(root);
    if (f.outside || f.credential) add({ pattern: "find-delete-outside", kind: "destructive", strong: true, target: root, note: outsideNote(root, f) });
  }
  if (program === "truncate") {
    classes.add("fs-destructive");
    const files = pos.filter((p) => !/^\d/.test(p));
    targets.push(...files);
    for (const t of files) { const f = flagsOf(t); if (f.outside || f.credential) add({ pattern: "truncate-outside", kind: "destructive", strong: true, target: t, note: outsideNote(t, f) }); }
  }
  if (program === "shred") {
    classes.add("fs-destructive");
    targets.push(...pos);
    const t = pos[0];
    const f = t ? flagsOf(t) : null;
    add({ pattern: "shred", kind: "destructive", strong: !!f && (f.outside || f.credential || f.device), target: t, note: t && f ? outsideNote(t, f) : undefined });
  }
  if (program === "dd") {
    const of = args.find((a) => a.startsWith("of="))?.slice(3);
    if (of) { classes.add("fs-destructive"); targets.push(of); if (DEVICE_RE.test(of)) add({ pattern: "dd-device", kind: "destructive", strong: true, target: of, note: `device: ${of}` }); }
  }
  if (/^mkfs(\.|$)|^wipefs$|^mkswap$/.test(program)) {
    classes.add("fs-destructive");
    const t = pos.find((p) => p.startsWith("/dev/"));
    add({ pattern: program.startsWith("mkfs") ? "mkfs" : "device-clobber", kind: "destructive", strong: true, target: t, note: t ? `device: ${t}` : undefined });
  }
  // privileged
  if (program === "chmod") {
    const mode = pos[0];
    const files = pos.slice(1);
    targets.push(...files);
    const ww = mode !== undefined && worldWritableMode(mode);
    if (ww || hasFlag(args, /^-R$|^--recursive$/)) classes.add("privileged");
    for (const t of files) {
      const f = flagsOf(t);
      if (ww) add({ pattern: "chmod-world-writable", kind: "privileged", strong: f.outside || f.credential || f.device, target: t, note: outsideNote(t, f) ?? `mode ${mode}` });
      else if (f.outside || f.credential) add({ pattern: "chmod-chown-outside", kind: "privileged", strong: true, target: t, note: outsideNote(t, f) });
    }
  }
  if (program === "chown" || program === "chgrp") {
    classes.add("privileged");
    const files = pos.slice(1);
    targets.push(...files);
    for (const t of files) { const f = flagsOf(t); if (f.outside || f.credential) add({ pattern: "chmod-chown-outside", kind: "privileged", strong: true, target: t, note: outsideNote(t, f) }); }
  }
  if ((program === "systemctl" || program === "launchctl" || program === "service") && pos.some((p) => SERVICE_VERBS.test(p))) {
    classes.add("privileged");
    add({ pattern: "systemctl-mutation", kind: "privileged", strong: true, target: pos.filter((p) => !SERVICE_VERBS.test(p)).join(" ") || undefined });
  }
  if (program === "crontab" && (args.includes("-e") || args.includes("-r") || pos.length > 0) && !args.includes("-l")) {
    classes.add("privileged");
    add({ pattern: "crontab-write", kind: "privileged", strong: true, target: pos[0] });
  }
  if (program === "sysctl" && args.includes("-w")) { classes.add("privileged"); add({ pattern: "sysctl-write", kind: "privileged", strong: true, target: pos[0] }); }
  if (program === "defaults" && verb === "write") classes.add("privileged");
  if (PRIV_PROGRAMS.has(program)) classes.add("privileged");
  // process
  if (KILLERS.has(program) || program === "disown") classes.add("process");
  if (program === "pm2" && /^(start|stop|delete|restart|kill)$/.test(verb)) classes.add("process");
  if (KILLERS.has(program)) {
    const sigkill = hasFlag(args, /^-(9|KILL|SIGKILL|s(9|KILL))$/) || (args.includes("-s") && /^(9|KILL|SIGKILL)$/.test(args[args.indexOf("-s") + 1] ?? ""));
    const pattern = pos.join(" ");
    targets.push(...pos);
    if ((program === "pkill" || program === "killall") && AGENT_PROCESS.test(pattern)) add({ pattern: "pkill-agent", kind: "process-terminating", strong: false, target: pattern });
    else if (sigkill) add({ pattern: "kill-sigkill", kind: "process-terminating", strong: false, target: pattern || undefined });
    if (program === "kill" && sigkill && /^-?1$/.test(pos[0] ?? "")) add({ pattern: "kill-sigkill", kind: "process-terminating", strong: true, target: pos[0], note: "signals every process the user may signal" });
  }
  // exfil-shaped
  let upload = false;
  if (program === "curl") {
    upload = args.some((a, i) =>
      a === "-d" || a.startsWith("-d@") || a.startsWith("--data") || a === "-F" || a.startsWith("--form") || a === "-T" || a.startsWith("--upload-file") || a.startsWith("--json") ||
      /^-X(POST|PUT|PATCH)$/i.test(a) || ((a === "-X" || a === "--request") && /^(POST|PUT|PATCH)$/i.test(args[i + 1] ?? "")));
  }
  if (program === "wget") upload = args.some((a) => /^--(post-data|post-file|body-data|body-file)|^--method=(POST|PUT|PATCH)$/i.test(a));
  if ((program === "scp" || program === "rsync" || program === "sftp") && pos.length > 0 && REMOTE_TARGET.test(pos[pos.length - 1])) upload = true;
  if (program === "nc" || program === "ncat" || program === "netcat" || program === "socat") {
    const exec = hasFlag(args, /^-[a-zA-Z]*[ec]$/) || args.some((a) => /^(exec|system):/i.test(a));
    if (exec) { classes.add("exfil-shaped"); add({ pattern: "nc-exec", kind: "remote-shell-shaped", strong: true, target: pos.filter((p) => !/^\d+$/.test(p)).join(" ") || undefined }); }
    if (sep === "pipe" || args.some((a) => a.startsWith("<"))) upload = true;
  }
  const credentialInGroup = CREDENTIAL_PATH.test(groupText) ? (tokenize(groupText).find((t) => CREDENTIAL_PATH.test(t)) ?? "credential path") : null;
  if (upload) {
    classes.add("exfil-shaped");
    if (credentialInGroup) add({ pattern: "exfil-upload-credential-path", kind: "upload-shaped", strong: true, target: credentialInGroup, note: `credential-bearing path in the same pipeline: ${credentialInGroup}` });
  } else if (classes.has("network") && credentialInGroup) {
    classes.add("exfil-shaped");
  }
  return { classes: [...classes], targets, promotions };
}

// ---- public API ---------------------------------------------------------------

export function classifyShell(command: string, cwd: string | null, depth = 0): ShellClassification {
  const raw = splitSegments(command);
  // pipeline groups: a segment plus everything chained to it with "|"
  const groups: string[][] = [];
  for (const s of raw) {
    if (s.sep === "pipe" && groups.length > 0) groups[groups.length - 1].push(s.text);
    else groups.push([s.text]);
  }
  const groupOf = new Map<number, string>();
  let idx = 0;
  for (const g of groups) { const text = g.join(" | "); for (let k = 0; k < g.length; k++) groupOf.set(idx++, text); }

  const segments: ShellSegment[] = [];
  raw.forEach((s, i) => {
    const parsed = parseSegment(tokenize(s.text));
    const one = classifyOne(parsed, s.text, s.sep, s.background, cwd, groupOf.get(i) ?? s.text);
    const seg: ShellSegment = { text: s.text, sep: s.sep, background: s.background, program: parsed.program, elevated: parsed.elevated, classes: one.classes, targets: one.targets, promotions: one.promotions };
    if (parsed.inner && depth < 2) {
      const inner = classifyShell(parsed.inner, cwd, depth + 1);
      for (const is of inner.segments) {
        seg.classes = [...new Set([...seg.classes, ...is.classes])];
        seg.targets.push(...is.targets);
        seg.promotions.push(...is.promotions.map((p) => ({ ...p, strong: p.strong || parsed.elevated })));
        if (parsed.elevated && !seg.classes.includes("privileged")) seg.classes.push("privileged");
      }
    }
    segments.push(seg);
  });
  const classes = SHELL_CLASSES.filter((c) => segments.some((s) => s.classes.includes(c)));
  return { classes, segments };
}

const memo = new WeakMap<TraceEvent, ShellClassification>();

/** Classification of one `shell` event, memoised per event object (the event's own cwd is the reference). */
export function classifyEvent(e: TraceEvent): ShellClassification {
  let c = memo.get(e);
  if (!c) {
    c = e.kind === "shell" ? classifyShell(e.resource, e.cwd) : { classes: [], segments: [] };
    memo.set(e, c);
  }
  return c;
}

export interface ShellClassCounts {
  total: number;
  failed: number; // non-zero exit code reported
  other: number; // shell events with no class
  byClass: Array<{ cls: ShellClass; count: number }>; // events (not segments) per class, catalogue order
}

export function shellClassCounts(events: TraceEvent[]): ShellClassCounts {
  const shells = events.filter((e) => e.kind === "shell");
  const by = new Map<ShellClass, number>();
  let other = 0;
  let failed = 0;
  for (const e of shells) {
    const c = classifyEvent(e);
    if (c.classes.length === 0) other++;
    for (const cls of c.classes) by.set(cls, (by.get(cls) ?? 0) + 1);
    if (typeof e.detail.exitCode === "number" && e.detail.exitCode !== 0) failed++;
  }
  return { total: shells.length, failed, other, byClass: SHELL_CLASSES.filter((c) => by.has(c)).map((cls) => ({ cls, count: by.get(cls)! })) };
}
