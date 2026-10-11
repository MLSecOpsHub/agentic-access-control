// Vendor wording for each Claude Code permission mode (permission-modes
// reference, verified 2026-10-11). Shared by the collector (instance notes),
// the ModeBadge tooltip and the /sessions legend so the three cannot drift.
//
// In a session trace the mode is what the session itself reported in each
// hook payload (`permission_mode`) — the gate every recorded tool call passed
// through — not a value read from a settings file.

export const MODE_TEXT: Record<string, string> = {
  default: "default (Manual): reads run without asking; edits, shell commands and network requests prompt.",
  acceptEdits: "acceptEdits: file edits and common filesystem commands in the working directories run without prompts.",
  plan: "plan: reads only, plus classifier-approved commands when auto mode is available.",
  auto: "auto: everything runs, with a background classifier reviewing actions instead of you — the vendor's built-in starting mode for interactive sessions since Claude Code v2.1.283.",
  dontAsk: "dontAsk: anything that would prompt is denied; pre-approved tools and reads in the working directories still run.",
  bypassPermissions: "bypassPermissions: skips permission prompts — vendor: isolated containers and VMs only.",
};

export const MODE_UNKNOWN_TEXT = "Not in the vendor's documented mode list (2026-10-11) — shown as reported.";
export const MODE_MISSING_TEXT = "No event of this session carried a permission_mode — the vendor omits it on some lifecycle payloads, and events stored before it was recorded on tool events have none.";

export function modeText(mode: string | null): string {
  if (!mode) return MODE_MISSING_TEXT;
  return MODE_TEXT[mode] ?? MODE_UNKNOWN_TEXT;
}
