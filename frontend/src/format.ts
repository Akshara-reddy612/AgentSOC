// Small display helpers.

export function when(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toISOString().replace("T", " ").slice(0, 19) + " UTC";
}

export function day(iso: string): string {
  return iso.slice(0, 10);
}

export const OUTCOME_COLOR: Record<string, string> = {
  REVIEW: "orange",
  AUTO_APPROVED: "red",
  LOW_PRIORITY: "gray",
  NO_ACTIONABLE: "teal",
};

export const STATUS_COLOR: Record<string, string> = {
  open: "orange",
  claimed: "blue",
  needs_info: "yellow",
  closed: "gray",
  none: "dark",
};

export const VERDICT_COLOR: Record<string, string> = {
  malicious: "red",
  benign: "teal",
  benign_once: "cyan",
  needs_info: "yellow",
};

export const PROVENANCE_COLOR: Record<string, string> = {
  training: "#4dabf7",
  closed_benign: "#38d9a9",
  analyst: "#ffd43b",
  ungated: "#ff8787",
  telemetry: "#adb5bd",
  config: "#868e96",
  retracted: "#fa5252",
};

/** Render any JSON value as a short single line (for table cells). */
export function short(v: unknown): string {
  if (v === null || v === undefined) return "—";
  if (typeof v === "string") return v;
  return JSON.stringify(v);
}
