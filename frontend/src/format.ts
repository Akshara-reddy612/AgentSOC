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
  NO_ACTIONABLE: "gray",
};

export const STATUS_COLOR: Record<string, string> = {
  open: "orange",
  claimed: "gray",
  needs_info: "yellow",
  closed: "gray",
  none: "dark",
};

export const VERDICT_COLOR: Record<string, string> = {
  malicious: "red",
  benign: "green",
  benign_once: "gray",
  needs_info: "yellow",
};

// Where a learned pattern came from. Training is the gray baseline; the three ways of learning afterwards
// share the validated aqua / blue / orange trio (all pairs pass on #1c1c1c); retractions use the status red.
export const PROVENANCE_COLOR: Record<string, string> = {
  training: "#8a8a8a",
  closed_benign: "#199e70",
  analyst: "#3987e5",
  ungated: "#d95926",
  telemetry: "#5c5c5c",
  config: "#4a4a4a",
  retracted: "#d03b3b",
};

export const PROVENANCE_LABEL: Record<string, string> = {
  training: "training weeks",
  closed_benign: "behind the gate",
  analyst: "analyst verdicts",
  ungated: "without the gate",
  telemetry: "seen in telemetry",
  config: "inventory",
  retracted: "retracted",
};

/** Render any JSON value as a short single line (for table cells). */
export function short(v: unknown): string {
  if (v === null || v === undefined) return "—";
  if (typeof v === "string") return v;
  if (Array.isArray(v) && v.every((x) => typeof x !== "object" || x === null)) return v.map((x) => String(x)).join("  ·  ");
  return JSON.stringify(v);
}
