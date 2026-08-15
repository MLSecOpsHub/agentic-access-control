import path from "path";
import { defineConfig } from "vitest/config";

export default defineConfig({
  // tsconfig sets jsx:"preserve" for Next; vitest must compile it instead.
  oxc: { jsx: { runtime: "automatic" } },
  resolve: {
    // Mirror tsconfig's "@/*" alias so app/ modules resolve under vitest.
    alias: { "@": path.resolve(__dirname) },
  },
  test: {
    include: ["tests/**/*.test.{ts,tsx}"],
    environment: "node",
    pool: "forks", // process.chdir + process.env.HOME mutation need real processes

    // SR1/SR3 tests spawn the collector; the SR3 crawl boots a dev server.
    testTimeout: 120_000,
    hookTimeout: 120_000,
  },
});
