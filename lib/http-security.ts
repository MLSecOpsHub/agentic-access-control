// Dashboard origin isolation and response hardening (threat T16, SR3).
// Edge-runtime safe: imported by middleware.ts — no Node built-ins here.
//
// "Binds 127.0.0.1" is necessary but not sufficient. A malicious web page can
// point a hostname it controls at 127.0.0.1 (DNS rebinding); the browser then
// treats that page and the dashboard as the same origin and can read the
// complete map of this machine's agent surface (A1) or POST forged events to
// the OTLP receiver (T12). The browser still sends the attacker's hostname in
// the Host header, so serving loopback hosts only closes the trick.

const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost", "[::1]"]);

export function isLoopbackHost(hostHeader: string | null | undefined): boolean {
  if (!hostHeader) return false;
  const m = /^(\[[^\]]+\]|[^:\s]+)(?::\d{1,5})?$/.exec(hostHeader.trim().toLowerCase());
  return m !== null && LOOPBACK_HOSTS.has(m[1]);
}

// Per-request nonce for Next's inline bootstrap scripts; 'strict-dynamic'
// lets those scripts load the chunks they reference. Dev mode needs eval for
// source maps/HMR and inline styles for the dev overlay — production does not.
export function buildContentSecurityPolicy(nonce: string, dev: boolean): string {
  return [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${dev ? " 'unsafe-eval'" : ""}`,
    `style-src 'self'${dev ? " 'unsafe-inline'" : ""}`,
    "img-src 'self' data:",
    "font-src 'self'",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'",
  ].join("; ");
}

export const SECURITY_HEADERS: Record<string, string> = {
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "referrer-policy": "no-referrer",
  "permissions-policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
  "cross-origin-opener-policy": "same-origin",
  "cross-origin-resource-policy": "same-origin",
  "cache-control": "no-store",
};
