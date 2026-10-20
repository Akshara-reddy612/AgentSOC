import { Tooltip } from "@mantine/core";
import type { Stage } from "../api";

export type Tone = "neutral" | "ok" | "warn" | "alert" | "llm" | "accent";

export interface FlowStep {
  stage: string;
  label: string;
  result: string;
  tone: Tone;
  hint: string;
}

type Row = Record<string, unknown>;

/** One line per pipeline stage, from the trace: what that stage decided for this case. */
export function flowSteps(stages: Stage[], actions: { status: string }[]): FlowStep[] {
  const by = Object.fromEntries(stages.map((s) => [s.stage, s]));
  const alert = by.alert ?? ({} as Stage);
  const trusted = (alert.trusted ?? {}) as Row;
  const hyps = (by.reasoning?.hypotheses ?? []) as Row[];
  const checks = (by.structural_check?.checks ?? []) as Row[];
  const responses = (by.response?.responses ?? []) as Row[];
  const decision = by.decision ?? ({} as Stage);
  const learning = by.learning ?? ({} as Stage);
  const feasible = checks.filter((c) => c.sse_verdict === "FEASIBLE").length;
  const unbound = checks.filter((c) => c.entity_binding === "unbound").length;
  const top = responses.find((r) => r.playbook_status) ?? responses[0];
  const status = String(top?.playbook_status ?? "");
  const nce = String(by.reasoning?.nce_status ?? "");
  const executed = actions.filter((a) => a.status === "executed").length;
  const proposed = actions.filter((a) => a.status === "proposed" || a.status === "approved").length;
  const verdict = learning.verdict ? String(learning.verdict) : "";
  const kind = String(trusted.kind ?? trusted.event_type ?? "");
  return [
    {
      stage: "alert", label: "Sensor alert",
      result: kind === "host" ? `host · ${String(trusted.detector ?? "")}` : `IDS sid ${String(trusted.signature_id ?? "")}`,
      tone: "accent", hint: "What the sensor recorded; trusted fields apart from attacker-writable text",
    },
    {
      stage: "triage_gate", label: "Triage gate",
      result: by.triage_gate?.path === "pipeline" ? "new pattern" : String(by.triage_gate?.path ?? "—"),
      tone: (by.triage_gate?.escalations as unknown[] | undefined)?.length ? "warn" : "neutral",
      hint: "Learned as routine? Cached decision? Otherwise full reasoning",
    },
    {
      stage: "reasoning", label: "LLM hypotheses",
      result: nce === "ran" ? `${hyps.length} hypotheses` : nce ? `NCE ${nce}` : "not run",
      tone: nce === "ran" ? "llm" : "neutral", hint: "LLM output: leads, not findings",
    },
    {
      stage: "structural_check", label: "Structure & binding",
      result: hyps.length ? `${feasible} feasible${unbound ? ` · ${unbound} unbound` : ""}` : "—",
      tone: unbound ? "alert" : feasible ? "warn" : "neutral",
      hint: "SSE checks each hypothesis against the environment; entity binding checks its names against the trusted fields",
    },
    {
      stage: "response", label: "Response & guardrails",
      result: top ? `${String(top.top_action)}${status === "AUTO_APPROVED" ? " · auto" : status ? " · needs approval" : ""}` : "none",
      tone: status === "AUTO_APPROVED" ? "alert" : top ? "warn" : "neutral",
      hint: "RSEM ranks responses; guardrails decide what may run without an analyst",
    },
    {
      stage: "decision", label: "Decision", result: String(decision.outcome ?? "—"),
      tone: decision.outcome === "REVIEW" ? "warn" : decision.outcome === "AUTO_APPROVED" ? "alert" : "ok",
      hint: "Review, dismiss as low priority, or respond",
    },
    {
      stage: "actions", label: "Containment",
      result: executed ? `${executed} executed` : proposed ? `${proposed} proposed` : "none",
      tone: executed ? "alert" : proposed ? "warn" : "neutral", hint: "Simulated actions, each with its own approval and rollback",
    },
    {
      stage: "learning", label: "Learning",
      result: verdict ? `verdict: ${verdict}` : String(learning.review_status ?? "") === "none" ? "gate decides" : "awaits verdict",
      tone: verdict === "malicious" ? "alert" : verdict ? "ok" : "neutral",
      hint: "What the Knowledge Store learns or retracts from this case",
    },
  ];
}

export function PipelineFlow({ steps, onSelect }: { steps: FlowStep[]; onSelect: (stage: string) => void }) {
  return (
    <div className="soc-flow" role="list" aria-label="Pipeline stages">
      {steps.map((s, i) => (
        <Tooltip key={s.stage} label={s.hint} multiline w={260} withArrow>
          <button type="button" className="soc-flow-step" data-tone={s.tone} role="listitem" onClick={() => onSelect(s.stage)}>
            <span className="soc-flow-node">{i + 1}</span>
            <span className="soc-flow-label">{s.label}</span>
            <span className="soc-flow-result">{s.result}</span>
          </button>
        </Tooltip>
      ))}
    </div>
  );
}
