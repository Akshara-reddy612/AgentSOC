// API client for the demo server (soc_server). All requests go through /api (Vite proxy in dev).
// Every string from the server is data: render it as text (React escapes it), never as HTML.

const BASE = "/api";
const TOKEN_KEY = "agentsoc.token";

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

export function getToken(): string | null {
  try {
    return sessionStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}

export function setToken(token: string | null): void {
  try {
    if (token) sessionStorage.setItem(TOKEN_KEY, token);
    else sessionStorage.removeItem(TOKEN_KEY);
  } catch {
    /* storage unavailable: the session lasts until reload */
  }
}

export async function api<T>(path: string, init: { method?: string; body?: unknown } = {}): Promise<T> {
  const token = getToken();
  const res = await fetch(BASE + path, {
    method: init.method ?? "GET",
    headers: {
      ...(init.body !== undefined ? { "Content-Type": "application/json" } : {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: init.body !== undefined ? JSON.stringify(init.body) : undefined,
  });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const j = await res.json();
      detail = typeof j.detail === "string" ? j.detail : JSON.stringify(j.detail);
    } catch {
      /* not JSON */
    }
    throw new ApiError(res.status, detail);
  }
  return (await res.json()) as T;
}

// ---- types (mirroring soc_server / review_api responses) ----

export type Role = "analyst" | "lead" | "admin";
export type Verdict = "malicious" | "benign" | "benign_once" | "needs_info";

export interface LiveStatus {
  state: "paused" | "running" | "finished" | "stopped";
  mode?: "replay" | "follow";
  alerts_test?: number;
  stream_time: string;
  speed: number;
  events_processed: number;
  counts: Record<string, number>;
  last_checkpoint: string | null;
  restored_from_checkpoint: boolean;
}

export interface QueueItem {
  case_id: string;
  title: string;
  host: string | null;
  opened: string;
  alert_count: number;
  review_status: string;
  claimed_by: string | null;
  priority: number;
  priority_reasons: string[];
}

export interface Action {
  action_id: string;
  case_id: string;
  row: number;
  action: string;
  target: string;
  target_kind: string;
  status: string;
  approvals_needed: number;
  approvals: string[];
  watch_id: string | null;
}

export interface CaseRow {
  case_id: string;
  case_key: unknown[];
  kind: string;
  title: string;
  host: string | null;
  host_tier: number | null;
  opened: string;
  last_seen: string;
  closed: string | null;
  close_reason: string | null;
  alert_count: number;
  outcome: string;
  review_status: string;
  claimed_by: string | null;
  verdict: string | null;
}

export interface CaseSummary {
  case_id: string;
  title: string;
  opened: string;
  alert_count: number;
  outcome: string;
  review_status: string;
  verdict: string | null;
}

export interface AlertRecord {
  n: number;
  alert_id: string;
  at: string;
  trusted: Record<string, unknown>;
  untrusted: Record<string, unknown>;
}

export interface CaseView {
  case: CaseRow;
  priority: number;
  priority_reasons: string[];
  trusted: Record<string, unknown>;
  untrusted_notice: string;
  alerts: AlertRecord[];
  alerts_stored: number;
  actions: Action[];
  related: { same_pattern: CaseSummary[]; same_host_in_queue: CaseSummary[] };
  learning_preview: Record<Verdict, string>;
  notes: { note_id: number; at: string; analyst: string; text: string }[];
  audit: { seq: number; at: string; actor: string; op: string; case_id: string; payload: Record<string, unknown> }[];
}

export interface Stage {
  stage: string;
  title: string;
  [key: string]: unknown;
}

export interface Trace {
  case_id: string;
  stages: Stage[];
}

export interface KnowledgeSummary {
  nodes: Record<string, number>;
  edges: Record<string, Record<string, number>>;
  log_entries: number;
  retractions: number;
}

export interface Pattern {
  src: string;
  dst: string;
  key: string;
  type: string;
  learned_from: string;
  learned_at: string;
  attrs: Record<string, unknown>;
}

export interface GraphData {
  nodes: { id: string; label: string; type: string }[];
  edges: { source: string; target: string; type: string; key: string; learned_from: string }[];
}

export interface Retraction {
  seq: number;
  at: string;
  writer: string;
  src: string;
  dst: string;
  key: string;
  reason: string;
}

export interface Metrics {
  cases_per_day: Record<string, Record<string, number>>;
  review_status: Record<string, number>;
  verdicts: Record<string, number>;
  actions: Record<string, number>;
  learning_per_day: Record<string, Record<string, number>>;
  comparison: Record<string, { mean: number; by_day: number[] }>;
}

export interface User {
  username: string;
  role: Role;
  disabled: boolean;
  created: string;
}
