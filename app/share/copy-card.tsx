"use client";

import { useState } from "react";

export function CopyCard({ text }: { text: string }) {
  const [state, setState] = useState<"idle" | "copied" | "failed">("idle");

  async function copy() {
    try {
      await navigator.clipboard.writeText(text);
      setState("copied");
    } catch {
      setState("failed");
    }
    setTimeout(() => setState("idle"), 2500);
  }

  return (
    <div className="card">
      <pre>{text}</pre>
      <button type="button" className="btn" onClick={copy}>
        {state === "copied"
          ? "Copied"
          : state === "failed"
            ? "Copy failed — select the text above instead"
            : "Copy to clipboard"}
      </button>
    </div>
  );
}
