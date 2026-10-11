import { NextResponse, type NextRequest } from "next/server";
import { buildContentSecurityPolicy, isLoopbackHost, SECURITY_HEADERS } from "@/lib/http-security";

// Runs on every request (pages, /_next assets, the OTLP receiver). See
// lib/http-security.ts for the threat (T16) and docs/security-architecture.md §SR3.
export function middleware(req: NextRequest) {
  if (!isLoopbackHost(req.headers.get("host"))) {
    return new NextResponse(
      "AgentLens serves loopback hosts only (127.0.0.1, localhost, [::1]) — see docs/security-architecture.md, T16.\n",
      { status: 403, headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" } },
    );
  }

  const nonce = btoa(crypto.randomUUID());
  const csp = buildContentSecurityPolicy(nonce, process.env.NODE_ENV !== "production");

  // Next.js reads the nonce for its inline scripts from the CSP header on the
  // *request*; the same policy is then enforced via the response header.
  const requestHeaders = new Headers(req.headers);
  requestHeaders.set("content-security-policy", csp);
  requestHeaders.set("x-nonce", nonce);

  const res = NextResponse.next({ request: { headers: requestHeaders } });
  res.headers.set("content-security-policy", csp);
  for (const [k, v] of Object.entries(SECURITY_HEADERS)) res.headers.set(k, v);
  return res;
}
