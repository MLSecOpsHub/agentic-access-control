import type { Metadata } from "next";
import Link from "next/link";
import { Nav } from "./nav";
import { AutoRefresh } from "./live/auto-refresh";
import "./globals.css";

export const metadata: Metadata = {
  title: { default: "AgentLens — agent permission observatory", template: "%s · AgentLens" },
  description: "Read-only dashboard for local AI agent access-control posture",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  // Set by `agentlens watch` / the QA lab (seconds): every page re-reads the
  // data dir on an interval so a new snapshot shows up without a manual reload.
  const refreshSeconds = Number(process.env.AGENTLENS_AUTO_REFRESH);
  return (
    <html lang="en">
      <body>
        {Number.isFinite(refreshSeconds) && refreshSeconds > 0 ? <AutoRefresh seconds={refreshSeconds} /> : null}
        <div className="wrap">
          <header className="topbar">
            <Link href="/" className="brand">
              Agent<span>Lens</span>
            </Link>
            <Nav />
          </header>
          {/* SR4 — interpretation honesty: on every page, permanently */}
          <div className="sr4">
            <b>Read-only interpretation, not enforcement.</b> AgentLens renders a best-effort
            reading of each platform&apos;s permission precedence from its config files. The
            platform&apos;s own evaluator is the only ground truth — verify against the source
            file shown on each rule. Docs: <code>docs/collectors.md</code>.
          </div>
          {children}
          <footer>
            AgentLens is an L2 observe-only tool by design: it never modifies configs, never sits
            in the request path, and never sends data off this machine (SR1–SR5,{" "}
            <code>docs/security-architecture.md</code>).
          </footer>
        </div>
      </body>
    </html>
  );
}
