// SR2 — the single source of truth for secret redaction, as plain ESM so the
// zero-dependency hook script (bin/agentlens-hook.mjs, run by node without a
// build step) and the TypeScript code (lib/redact.ts) share one pattern list.
// Bias to over-redaction: a mangled display string is acceptable, a leaked
// token is not. Patterns documented in docs/collectors.md §1.2.

export const REDACTED = "[REDACTED]";

// Order matters: specific token formats first, generic entropy runs last.
export const PATTERNS = [
  /\bsk-[A-Za-z0-9_-]{8,}\b/g, // OpenAI/Anthropic-style keys
  /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b/g, // GitHub tokens
  /\bgithub_pat_[A-Za-z0-9_]{20,}\b/g,
  /\bAKIA[0-9A-Z]{16}\b/g, // AWS access key ids
  /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, // Slack tokens
  /\bBearer\s+[A-Za-z0-9._~+/=-]{16,}/gi,
  /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b/g, // JWTs
  /\b[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=])/g, // long base64 runs
  /\b[a-fA-F0-9]{32,}\b/g, // long hex runs
];

// key=value / key: value captures — keep the key, drop the value.
export const KEYED = /((?:key|token|secret|password|passwd|pwd|credential|api[_-]?key)\s*[=:]\s*)["']?[^\s"'&,;]{6,}["']?/gi;

export function redact(input) {
  let out = input;
  for (const p of PATTERNS) out = out.replace(p, REDACTED);
  out = out.replace(KEYED, `$1${REDACTED}`);
  return out;
}

export function truncate(input, max = 200) {
  return input.length > max ? `${input.slice(0, max)}…` : input;
}
