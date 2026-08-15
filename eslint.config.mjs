import tseslint from "typescript-eslint";
import react from "eslint-plugin-react";

// Deliberately narrow config: its job is to make the security conventions
// lint-ENFORCED (security-architecture.md §4), not to impose a style guide.
export default [
  { ignores: ["node_modules/**", ".next/**", "data/**", "next-env.d.ts"] },
  {
    files: ["**/*.{ts,tsx,mts,cts}"],
    languageOptions: {
      parser: tseslint.parser,
      parserOptions: { ecmaFeatures: { jsx: true } },
    },
    plugins: { react },
    settings: { react: { version: "detect" } },
    rules: {
      // The HTML-injection ban (B1/B3: config strings are adversarial data,
      // React default escaping is the mitigation).
      "react/no-danger": "error",
      "react/no-danger-with-children": "error",
    },
  },
];
