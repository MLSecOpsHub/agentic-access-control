"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

const LINKS = [
  { href: "/", label: "Overview" },
  { href: "/mcp", label: "MCP servers" },
  { href: "/findings", label: "Findings" },
  { href: "/live", label: "Live" },
];

export function Nav() {
  const pathname = usePathname();
  const isActive = (href: string) =>
    href === "/" ? pathname === "/" || pathname.startsWith("/agents") : pathname.startsWith(href);
  return (
    <nav className="nav">
      {LINKS.map((l) => (
        <Link
          key={l.href}
          href={l.href}
          className={isActive(l.href) ? "active" : undefined}
          aria-current={isActive(l.href) ? "page" : undefined}
        >
          {l.label}
        </Link>
      ))}
    </nav>
  );
}
