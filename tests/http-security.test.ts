import { describe, expect, it } from "vitest";
import { buildContentSecurityPolicy, isLoopbackHost } from "@/lib/http-security";

describe("T16 — loopback Host validation", () => {
  it("accepts loopback hosts with or without a port", () => {
    for (const h of ["127.0.0.1", "127.0.0.1:3000", "localhost", "LOCALHOST:3777", "[::1]", "[::1]:3000", " 127.0.0.1:3000 "]) {
      expect(isLoopbackHost(h), h).toBe(true);
    }
  });
  it("rejects rebinding hostnames, non-loopback IPs, and malformed values", () => {
    for (const h of [
      "evil.example.com", "evil.example.com:3000", "127.0.0.1.evil.example.com", "localhost.evil.example.com",
      "192.168.1.10:3000", "0.0.0.0:3000", "10.0.0.1", "[::]:3000", "127.0.0.1:3000:1", "", null, undefined,
      "127.0.0.1 evil", "localhost/", "127.0.0.1@evil.example.com",
    ]) {
      expect(isLoopbackHost(h), String(h)).toBe(false);
    }
  });
});

describe("Content-Security-Policy", () => {
  it("production policy has no unsafe sources and pins the nonce", () => {
    const csp = buildContentSecurityPolicy("abc123", false);
    expect(csp).toContain("script-src 'self' 'nonce-abc123' 'strict-dynamic'");
    expect(csp).not.toContain("unsafe-eval");
    expect(csp).not.toContain("unsafe-inline");
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).toContain("base-uri 'none'");
  });
  it("dev policy only adds what HMR and the dev overlay need", () => {
    const csp = buildContentSecurityPolicy("abc123", true);
    expect(csp).toContain("'unsafe-eval'");
    expect(csp).toMatch(/style-src 'self' 'unsafe-inline'/);
    expect(csp).not.toMatch(/script-src[^;]*'unsafe-inline'/);
  });
});
