import type { NextConfig } from "next";

// SR3: no external assets, no telemetry. Next.js's own anonymous telemetry is
// disabled via NEXT_TELEMETRY_DISABLED=1 in every package.json script so
// `npm run dev` makes zero outbound requests on a fresh clone.
const nextConfig: NextConfig = {};

export default nextConfig;
