"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";

/** Polls the server every `seconds` by re-rendering the route (MVP delivery;
 *  SSE is the planned upgrade — local/live-tracking-final-plan.md L6). */
export function AutoRefresh({ seconds = 5 }: { seconds?: number }) {
  const router = useRouter();
  useEffect(() => {
    const t = setInterval(() => router.refresh(), seconds * 1000);
    return () => clearInterval(t);
  }, [router, seconds]);
  return null;
}
