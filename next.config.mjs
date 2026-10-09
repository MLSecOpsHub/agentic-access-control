// SR3: no external assets, no telemetry. Next.js's own anonymous telemetry is
// disabled via NEXT_TELEMETRY_DISABLED=1 in every package.json script and in
// the `agentlens` CLI, so a fresh clone or an npx install makes zero outbound
// requests. Plain .mjs on purpose: a next.config.ts would make `next start`
// install TypeScript at runtime inside an npx install (observed 2026-10-09).
/** @type {import('next').NextConfig} */
const nextConfig = {};

export default nextConfig;
