import {
  Alert, Anchor, Badge, Button, Grid, Group, Highlight, Loader, SimpleGrid, Stack, Text, Textarea, Title, Tooltip,
} from "@mantine/core";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { lazy, Suspense, useState, type ReactNode } from "react";
import { Link, useParams } from "react-router-dom";
import { api, type Action, type CaseView, type Stage, type Trace, type Verdict } from "../api";
import { canControl, useAuth } from "../auth";
import { IconBrain, IconHost, IconNetwork, IconWarning } from "../components/Icons";
import { PipelineFlow, flowSteps } from "../components/PipelineFlow";
import { SeverityPill, SeverityStripe } from "../components/Severity";
import { OUTCOME_COLOR, STATUS_COLOR, VERDICT_COLOR, short, when } from "../format";
import { useTechniques } from "../hooks";

const EntityGraph = lazy(() => import("../components/EntityGraph"));

type Row = Record<string, unknown>;

const ROLE_LABEL: Record<string, string> = { source_account: "account", source_host: "source", target_host: "target" };
const TIER: Record<number, string> = { 0: "workstation", 1: "server", 2: "critical server", 3: "domain controller" };
const PLAYBOOK: Record<string, [string, string]> = {
  PENDING_ANALYST_REVIEW: ["needs approval", "warn"],
  AUTO_APPROVED: ["auto-approved", "alert"],
  REJECTED_BY_GUARDRAIL: ["blocked by guardrail", "neutral"],
  LOGGED_EXPECTED_ACTIVITY: ["logged as expected", "neutral"],
  DRY_RUN_FAILED: ["dry run failed", "neutral"],
};
const FEASIBILITY: Record<string, [string, string]> = {
  FEASIBLE: ["feasible", "warn"],
  CONDITIONALLY_FEASIBLE: ["conditionally feasible", "neutral"],
  INFEASIBLE: ["infeasible", "neutral"],
};

/**
 * Names the LLM's hypotheses used that entity binding could not tie to the alert's trusted fields
 * ("unbound"), per hypothesis.  Pipeline output, not a guess: the case view marks where these names
 * appear in the attacker-writable text, i.e. where a steered hypothesis may have come from.
 */
function unboundEntities(stages: Stage[]): string[][] {
  const hyps = (stages.find((s) => s.stage === "reasoning")?.hypotheses ?? []) as Row[];
  const checks = (stages.find((s) => s.stage === "structural_check")?.checks ?? []) as Row[];
  return checks.map((c, i) =>
    Object.entries((c.binding_roles ?? {}) as Record<string, string>)
      .filter(([, label]) => label === "unbound")
      .map(([role]) => `${ROLE_LABEL[role] ?? role}: ${String(hyps[i]?.[role] ?? "")}`),
  );
}

/** Search terms for a name: the name itself and, for DOMAIN\user, the user part. */
function markTerms(unbound: string[][]): string[] {
  const out = new Set<string>();
  for (const entry of unbound.flat()) {
    const name = entry.slice(entry.indexOf(": ") + 2).trim();
    if (name.length < 3) continue;
    out.add(name);
    const user = name.split("\\").pop() ?? "";
    if (user !== name && user.length >= 4) out.add(user);
  }
  return [...out];
}

function Section({ stage, n, title, extra, children }: { stage: string; n: string; title: string; extra?: ReactNode; children: ReactNode }) {
  return (
    <div id={`stage-${stage}`} className="soc-card soc-section-anchor" style={{ padding: 16 }}>
      <Group justify="space-between" mb="sm" wrap="nowrap">
        <Group gap={10} wrap="nowrap">
          <span className="soc-chip" style={{ fontWeight: 700 }}>{n}</span>
          <Text fw={600}>{title}</Text>
        </Group>
        {extra}
      </Group>
      {children}
    </div>
  );
}

function KeyValues({ data }: { data: Row }) {
  const entries = Object.entries(data).filter(([, v]) => v !== null && v !== undefined && v !== "");
  return (
    <dl className="soc-kv" style={{ margin: 0 }}>
      {entries.map(([k, v]) => (
        <div key={k} style={{ display: "contents" }}>
          <dt>{k}</dt>
          <dd>{short(v)}</dd>
        </div>
      ))}
    </dl>
  );
}

function Evidence({ stage, unbound }: { stage: Stage; unbound: string[][] }) {
  const terms = markTerms(unbound);
  const all = Object.entries((stage.untrusted ?? {}) as Row);
  const others = all.filter(([k]) => k !== "raw_log_line");
  const fields = others.length ? others : all; // network alerts: the raw line is the only text
  const marked = fields.some(([, v]) => terms.some((t) => short(v).toLowerCase().includes(t.toLowerCase())));
  return (
    <Grid gap="lg">
      <Grid.Col span={{ base: 12, md: 6 }}>
        <Text size="sm" fw={600} mb={6}>Trusted <Text span size="xs" c="dimmed" fw={400}>· sensor and inventory fields</Text></Text>
        <KeyValues data={(stage.trusted ?? {}) as Row} />
      </Grid.Col>
      <Grid.Col span={{ base: 12, md: 6 }}>
        <Group gap={6} mb={6}>
          <span style={{ color: "var(--soc-critical)", display: "inline-flex" }}><IconWarning size={14} /></span>
          <Text size="sm" fw={600}>Untrusted <Text span size="xs" c="dimmed" fw={400}>· attacker-writable text</Text></Text>
        </Group>
        <Text size="xs" c="dimmed" mb="xs">{String(stage.untrusted_notice ?? "")}</Text>
        {marked && (
          <div className="soc-callout" style={{ marginBottom: 8 }}>
            <Text size="xs" fw={700} c="yellow">Possible steering</Text>
            <Text size="xs" c="dimmed">
              Marked: names that the LLM's hypotheses used but the alert's trusted fields do not support (entity binding:
              unbound). They appear here, in text the attacker can write. The marks inform the analyst; they change no decision.
            </Text>
          </div>
        )}
        <Stack gap="xs">
          {fields.map(([k, v]) => (
            <div key={k}>
              <Text size="xs" c="dimmed" mb={2}>{k}</Text>
              <div className="soc-untrusted">
                {terms.length ? (
                  <Highlight component="span" size="xs" ff="monospace" highlight={terms} color="yellow">{short(v)}</Highlight>
                ) : (
                  short(v)
                )}
              </div>
            </div>
          ))}
          {!fields.length && <Text size="xs" c="dimmed">none</Text>}
        </Stack>
      </Grid.Col>
    </Grid>
  );
}

function Hypothesis({ h, check, response, unbound, names }: { h: Row; check: Row; response?: Row; unbound: string[]; names: Record<string, { name: string; detail: string }> }) {
  const tid = String(h.technique_id ?? "");
  const roles = (check.binding_roles ?? {}) as Record<string, string>;
  const [feasText, feasTone] = FEASIBILITY[String(check.sse_verdict)] ?? [String(check.sse_verdict ?? "—").toLowerCase(), "neutral"];
  const binding = String(check.entity_binding ?? "");
  const [pbText, pbTone] = response ? PLAYBOOK[String(response.playbook_status)] ?? [String(response.playbook_status ?? ""), "neutral"] : ["", ""];
  return (
    <div className="soc-hyp" data-unbound={unbound.length ? true : undefined}>
      <Group justify="space-between" wrap="nowrap" align="flex-start">
        <div style={{ minWidth: 0 }}>
          <Group gap={6}>
            <span className="soc-chip" data-tone="llm">{tid}</span>
            <Text size="sm" fw={600}>{names[tid]?.name ?? "technique"}</Text>
          </Group>
          {names[tid]?.detail && <Text size="xs" c="dimmed" mt={2}>{names[tid].detail}</Text>}
        </div>
        <Tooltip label="LLM output: a lead, not a finding">
          <span style={{ color: "var(--soc-llm)", display: "inline-flex" }}><IconBrain size={16} /></span>
        </Tooltip>
      </Group>
      <dl className="soc-kv" style={{ margin: "10px 0 0", gridTemplateColumns: "70px minmax(0,1fr)" }}>
        {(["source_account", "source_host", "target_host"] as const).map((role) => (
          <div key={role} style={{ display: "contents" }}>
            <dt>{ROLE_LABEL[role]}</dt>
            <dd style={roles[role] === "unbound" ? { color: "#ff8a8a" } : undefined}>
              {short(h[role])}
              {roles[role] === "unbound" && (
                <Text span size="xs" c="dimmed" ff="text" style={{ display: "block" }}>not in the alert's trusted fields</Text>
              )}
            </dd>
          </div>
        ))}
      </dl>
      <Group gap={6} mt="sm">
        <Tooltip label={`Structural feasibility (SSE)${check.path_confidence != null ? `, path confidence ${String(check.path_confidence)}` : ""}`}>
          <span className="soc-chip" data-tone={feasTone}>{feasText}</span>
        </Tooltip>
        <Tooltip label={binding === "unbound" ? "names entities that are not in the alert's trusted fields (possible steering)" : "entity binding: the names match the alert"}>
          <span className="soc-chip" data-tone={binding === "unbound" ? "alert" : binding === "bound" ? "good" : "warn"}>{binding || "—"}</span>
        </Tooltip>
      </Group>
      {response && (
        <div style={{ marginTop: 10, paddingTop: 10, borderTop: "1px solid var(--soc-border)" }}>
          <Group justify="space-between" wrap="nowrap">
            <Text size="xs">
              Best response: <b>{String(response.top_action)}</b>
              {response.top_target_host ? ` → ${String(response.top_target_host)}` : ""}
              <Text span c="dimmed" size="xs">{` · score ${String(response.top_composite)}`}</Text>
            </Text>
            <span className="soc-chip" data-tone={pbTone}>{pbText}</span>
          </Group>
          {response.guardrail_reason ? <Text size="xs" c="dimmed" mt={4}>{String(response.guardrail_reason)}</Text> : null}
        </div>
      )}
    </div>
  );
}

function ActionRow({ a, caseId }: { a: Action; caseId: string }) {
  const qc = useQueryClient();
  const [reason, setReason] = useState("");
  const op = useMutation({
    mutationFn: (p: { path: string; body?: unknown }) => api(p.path, { method: "POST", body: p.body }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["case", caseId] });
      void qc.invalidateQueries({ queryKey: ["trace", caseId] });
    },
  });
  const tone = a.status === "executed" ? "alert" : a.status === "proposed" || a.status === "approved" ? "warn" : "neutral";
  return (
    <div className="soc-hyp" style={{ borderTopColor: "var(--soc-border-strong)" }}>
      <Group justify="space-between" wrap="nowrap">
        <div>
          <Group gap={6}>
            <Text size="sm" fw={600}>{a.action}</Text>
            <Text size="sm" c="dimmed">→ {a.target}</Text>
            <span className="soc-chip" data-tone={tone}>{a.status}</span>
          </Group>
          <Text size="xs" c="dimmed" mt={2}>
            Simulated · approvals {a.approvals.length}/{a.approvals_needed}
            {a.approvals_needed > 1 ? " (four-eyes: critical host)" : ""}
            {a.approvals.length ? ` · ${a.approvals.join(", ")}` : ""}
          </Text>
        </div>
        <Group gap="xs" wrap="nowrap">
          {a.status === "proposed" && (
            <>
              <Button size="xs" color="red" onClick={() => op.mutate({ path: `/actions/${a.action_id}/approve` })}>Approve</Button>
              <Button size="xs" variant="default" disabled={!reason.trim()}
                onClick={() => op.mutate({ path: `/actions/${a.action_id}/reject`, body: { reason } })}>Reject</Button>
            </>
          )}
          {a.status === "executed" && (
            <Button size="xs" variant="default" disabled={!reason.trim()}
              onClick={() => op.mutate({ path: `/actions/${a.action_id}/rollback`, body: { reason } })}>Roll back</Button>
          )}
        </Group>
      </Group>
      {(a.status === "proposed" || a.status === "executed") && (
        <Textarea mt="xs" size="xs" autosize placeholder="Reason (required to reject or roll back)" value={reason}
          onChange={(e) => setReason(e.currentTarget.value)} />
      )}
      {op.error && <Alert color="red" mt="xs" p="xs">{String((op.error as Error).message)}</Alert>}
    </div>
  );
}

function VerdictPanel({ view }: { view: CaseView }) {
  const { session } = useAuth();
  const qc = useQueryClient();
  const [note, setNote] = useState("");
  const c = view.case;
  const id = c.case_id;
  const refresh = () => {
    for (const k of [["case", id], ["trace", id], ["queue"]]) void qc.invalidateQueries({ queryKey: k });
  };
  const op = useMutation({ mutationFn: (p: { path: string; body?: unknown }) => api(p.path, { method: "POST", body: p.body }), onSuccess: refresh });
  const reviewable = ["open", "claimed", "needs_info"].includes(c.review_status);
  const mine = c.claimed_by === session?.username;
  const withdrawable = c.review_status === "closed" && c.verdict === "malicious" && canControl(session?.role);

  return (
    <div className="soc-card" style={{ padding: 16 }}>
      <Text className="soc-card-title" mb="xs">Analyst decision</Text>
      {!reviewable ? (
        <Stack gap="xs">
          <Text size="sm" c="dimmed">
            {c.review_status === "closed" ? `Closed as ${c.verdict} by ${c.claimed_by}.` : "The pipeline did not send this case for review."}
          </Text>
          {withdrawable && (
            <>
              <Textarea size="xs" autosize placeholder="Why the verdict was wrong (required)" value={note} onChange={(e) => setNote(e.currentTarget.value)} />
              <Tooltip multiline w={380} label="The case returns to the queue. The loop ends the host's watch, restores the patterns this verdict retracted and a blocked destination's previous reputation. Executed containment keeps its own rollback.">
                <Button size="xs" variant="default" disabled={!note.trim()} onClick={() => op.mutate({ path: `/cases/${id}/withdraw`, body: { reason: note } })}>
                  Withdraw verdict
                </Button>
              </Tooltip>
            </>
          )}
        </Stack>
      ) : (
        <Stack gap="xs">
          <Group gap="xs">
            {c.review_status === "claimed" && !mine ? (
              <Text size="sm">Claimed by {c.claimed_by}.</Text>
            ) : mine ? (
              <Button size="xs" variant="default" onClick={() => op.mutate({ path: `/cases/${id}/release` })}>Release</Button>
            ) : (
              <Button size="xs" variant="light" onClick={() => op.mutate({ path: `/cases/${id}/claim` })}>Claim</Button>
            )}
          </Group>
          <Textarea size="xs" autosize minRows={2} placeholder="Note (optional; stays in the case store, never learned)" value={note} onChange={(e) => setNote(e.currentTarget.value)} />
          <SimpleGrid cols={2} spacing="xs">
            {(["malicious", "benign", "benign_once", "needs_info"] as Verdict[]).map((v) => (
              <Tooltip key={v} multiline w={360} label={view.learning_preview[v]}>
                <Button size="xs" color={VERDICT_COLOR[v]} variant={v === "malicious" ? "filled" : v === "benign_once" ? "default" : "light"}
                  disabled={c.review_status === "claimed" && !mine}
                  onClick={() => op.mutate({ path: `/cases/${id}/verdict`, body: { verdict: v, note: note || undefined } })}>
                  {v.replace("_", " ")}
                </Button>
              </Tooltip>
            ))}
          </SimpleGrid>
          <Text size="xs" c="dimmed">Hover a verdict to see what the Knowledge Store will learn.</Text>
        </Stack>
      )}
      {op.error && <Alert color="red" mt="xs" p="xs">{String((op.error as Error).message)}</Alert>}
    </div>
  );
}

export default function CasePage() {
  const { caseId = "" } = useParams();
  const view = useQuery({ queryKey: ["case", caseId], queryFn: () => api<CaseView>(`/cases/${caseId}`), refetchInterval: 4000 });
  const trace = useQuery({ queryKey: ["trace", caseId], queryFn: () => api<Trace>(`/cases/${caseId}/trace`), refetchInterval: 4000 });
  const techniques = useTechniques();
  if (view.isLoading || trace.isLoading) return <Loader />;
  if (view.error || !view.data || !trace.data) return <Alert color="red">{String(view.error ?? trace.error)}</Alert>;
  const v = view.data;
  const c = v.case;
  const stages = trace.data.stages;
  const by = Object.fromEntries(stages.map((s) => [s.stage, s])) as Record<string, Stage>;
  const hyps = (by.reasoning?.hypotheses ?? []) as Row[];
  const checks = (by.structural_check?.checks ?? []) as Row[];
  const responses = [...((by.response?.responses ?? []) as Row[])];
  const unbound = unboundEntities(stages);
  const steps = flowSteps(stages, v.actions);
  const names = techniques.data ?? {};
  const go = (stage: string) => {
    const id = ["structural_check", "response"].includes(stage) ? "reasoning" : stage;
    document.getElementById(`stage-${id}`)?.scrollIntoView({ behavior: "smooth", block: "start" });
  };
  const responseFor = (h: Row) => {
    const i = responses.findIndex((r) => r.technique_id === h.technique_id);
    return i >= 0 ? responses.splice(i, 1)[0] : undefined;
  };
  const decision = by.decision ?? ({} as Stage);
  const learning = by.learning ?? ({} as Stage);
  const network = c.kind === "network";

  return (
    <Stack gap="lg">
      <Anchor component={Link} to="/" size="sm">← Review queue</Anchor>

      <div className="soc-card" style={{ display: "flex", overflow: "hidden" }}>
        <div style={{ display: "flex", width: 4 }}><SeverityStripe priority={v.priority} /></div>
        <Group justify="space-between" align="flex-start" p="md" style={{ flex: 1 }} wrap="wrap" gap="md">
          <div style={{ minWidth: 0, flex: 1 }}>
            <Group gap="sm" wrap="nowrap" align="center">
              <SeverityPill priority={v.priority} reasons={v.priority_reasons} />
              <Title order={3} style={{ wordBreak: "break-word" }}>{c.title}</Title>
            </Group>
            <Group gap={6} mt="xs">
              <span className="soc-chip">
                {network ? <IconNetwork size={13} /> : <IconHost size={13} />}
                {c.host ?? "—"}{c.host_tier != null ? ` · ${TIER[c.host_tier] ?? `tier ${c.host_tier}`}` : ""}
              </span>
              <span className="soc-chip">{network ? "network alert (IDS)" : "host alert"}</span>
              <span className="soc-chip">{c.case_id}</span>
              <span className="soc-chip">opened {when(c.opened).slice(0, 16)}</span>
              <span className="soc-chip">{c.alert_count} {c.alert_count === 1 ? "alert" : "alerts"}</span>
            </Group>
          </div>
          <Group gap="xs">
            <Badge size="lg" color={OUTCOME_COLOR[c.outcome] ?? "gray"}>{c.outcome}</Badge>
            <Badge size="lg" variant="light" color={STATUS_COLOR[c.review_status] ?? "gray"}>{c.review_status.replace("_", " ")}</Badge>
            {c.verdict && <Badge size="lg" color={VERDICT_COLOR[c.verdict]}>{c.verdict}</Badge>}
          </Group>
        </Group>
      </div>

      <div className="soc-card" style={{ padding: "16px 12px 14px" }}>
        <Group justify="space-between" mb="sm" px={4}>
          <Text className="soc-card-title">Pipeline</Text>
          <Text size="xs" c="dimmed">Each stage and what it decided for this case. Click a stage for its detail.</Text>
        </Group>
        <PipelineFlow steps={steps} onSelect={go} />
      </div>

      <Grid gap="lg">
        <Grid.Col span={{ base: 12, lg: 8 }}>
          <Stack gap="lg">
            {by.alert && (
              <Section stage="alert" n="1" title="Sensor alert" extra={<Text size="xs" c="dimmed">{String(by.alert.pattern ?? "")}</Text>}>
                <Evidence stage={by.alert} unbound={unbound} />
              </Section>
            )}
            {by.triage_gate && (
              <Section stage="triage_gate" n="2" title="Triage gate">
                <Group gap="xs">
                  <span className="soc-chip" data-tone="accent">{String(by.triage_gate.path ?? "—")}</span>
                  <Text size="sm">{String(by.triage_gate.explanation ?? "")}</Text>
                </Group>
                {((by.triage_gate.escalations ?? []) as string[]).map((e, i) => (
                  <Alert key={i} color="orange" variant="light" p="xs" mt="xs">{e}</Alert>
                ))}
              </Section>
            )}
            <Section stage="reasoning" n="3–5" title="LLM hypotheses, checks and responses"
              extra={<span className="soc-chip" data-tone="llm">LLM output · NCE {String(by.reasoning?.nce_status ?? "—")}</span>}>
              <Text size="xs" c="dimmed" mb="sm">{String(by.reasoning?.notice ?? "")}</Text>
              {hyps.length ? (
                <SimpleGrid cols={{ base: 1, md: 2 }} spacing="sm">
                  {hyps.map((h, i) => (
                    <Hypothesis key={i} h={h} check={checks[i] ?? {}} response={responseFor(h)} unbound={unbound[i] ?? []} names={names} />
                  ))}
                </SimpleGrid>
              ) : (
                <Text size="sm" c="dimmed">No hypotheses: the LLM did not run for this case, or proposed none.</Text>
              )}
            </Section>
            <Section stage="decision" n="6" title="Decision">
              <Group gap="xs" mb={6}>
                <Badge size="lg" color={OUTCOME_COLOR[String(decision.outcome)] ?? "gray"}>{String(decision.outcome ?? "—")}</Badge>
                {decision.pipeline_outcome && decision.pipeline_outcome !== decision.outcome ? (
                  <Text size="xs" c="dimmed">pipeline alone: {String(decision.pipeline_outcome)}</Text>
                ) : null}
              </Group>
              {((decision.reasons ?? []) as string[]).map((r, i) => (
                <Text key={i} size="sm">• {r}</Text>
              ))}
            </Section>
            <Section stage="actions" n="7" title="Containment">
              <Stack gap="xs">
                {v.actions.length ? v.actions.map((a) => <ActionRow key={a.action_id} a={a} caseId={c.case_id} />)
                  : <Text size="sm" c="dimmed">No containment proposed.</Text>}
              </Stack>
            </Section>
            <Section stage="learning" n="8" title="What the Knowledge Store learns">
              <Stack gap={6}>
                {Object.entries((learning.preview ?? {}) as Record<string, string>).map(([k, text]) => (
                  <Group key={k} gap="xs" wrap="nowrap" align="flex-start">
                    <Badge size="sm" w={96} color={VERDICT_COLOR[k]} variant={c.verdict === k ? "filled" : "light"}>{k.replace("_", " ")}</Badge>
                    <Text size="sm" style={{ flex: 1 }}>{text}</Text>
                  </Group>
                ))}
              </Stack>
            </Section>
          </Stack>
        </Grid.Col>
        <Grid.Col span={{ base: 12, lg: 4 }}>
          <Stack gap="lg" style={{ position: "sticky", top: 76 }}>
            <VerdictPanel view={v} />
            <div className="soc-card" style={{ padding: 16 }}>
              <Text className="soc-card-title">Entities</Text>
              <Text size="xs" c="dimmed" mb={4}>
                From the trusted fields, plus what each hypothesis named (violet). Red dashed: a name the trusted fields do not support.
              </Text>
              <Suspense fallback={<Loader size="sm" />}>
                <EntityGraph trusted={(by.alert?.trusted ?? {}) as Row} hypotheses={hyps} checks={checks} />
              </Suspense>
            </div>
            <div className="soc-card" style={{ padding: 16 }}>
              <Text className="soc-card-title" mb="xs">Related cases</Text>
              <Stack gap={4}>
                {[...v.related.same_pattern.map((r) => ({ ...r, why: "same pattern" })), ...v.related.same_host_in_queue.map((r) => ({ ...r, why: "same host" }))]
                  .slice(0, 10)
                  .map((r) => (
                    <Text key={r.case_id + r.why} size="xs">
                      <Anchor component={Link} to={`/cases/${r.case_id}`}>{r.case_id}</Anchor>
                      <Text span c="dimmed" size="xs">{` · ${r.why} · `}</Text>
                      {r.title}
                    </Text>
                  ))}
                {!v.related.same_pattern.length && !v.related.same_host_in_queue.length && <Text size="xs" c="dimmed">none</Text>}
              </Stack>
            </div>
            <div className="soc-card" style={{ padding: 16 }}>
              <Text className="soc-card-title" mb="xs">Notes and audit trail</Text>
              <Stack gap={4}>
                {v.notes.map((n) => (
                  <Text key={n.note_id} size="xs"><b>{n.analyst}</b> · {when(n.at).slice(0, 16)}: {n.text}</Text>
                ))}
                {v.audit.map((e) => (
                  <Text key={e.seq} size="xs" ff="monospace" c="dimmed">{when(e.at).slice(5, 16)} {e.actor} {e.op}</Text>
                ))}
              </Stack>
            </div>
          </Stack>
        </Grid.Col>
      </Grid>
    </Stack>
  );
}
