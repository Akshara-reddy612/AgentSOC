import {
  Alert, Anchor, Badge, Button, Card, Code, Grid, Group, Loader, Stack, Table, Text, Textarea, Timeline, Title, Tooltip,
} from "@mantine/core";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api, type Action, type CaseView, type Stage, type Trace, type Verdict } from "../api";
import { useAuth } from "../auth";
import { OUTCOME_COLOR, STATUS_COLOR, VERDICT_COLOR, short, when } from "../format";

type Row = Record<string, unknown>;

function KeyValues({ data }: { data: Record<string, unknown> }) {
  const entries = Object.entries(data).filter(([, v]) => v !== null && v !== undefined && v !== "");
  return (
    <Table withRowBorders={false} verticalSpacing={2}>
      <Table.Tbody>
        {entries.map(([k, v]) => (
          <Table.Tr key={k}>
            <Table.Td w={170}>
              <Text size="xs" c="dimmed">
                {k}
              </Text>
            </Table.Td>
            <Table.Td>
              <Text size="xs" ff="monospace" style={{ wordBreak: "break-all" }}>
                {short(v)}
              </Text>
            </Table.Td>
          </Table.Tr>
        ))}
      </Table.Tbody>
    </Table>
  );
}

function RowsTable({ rows, cols }: { rows: Row[]; cols: [string, string][] }) {
  if (!rows.length)
    return (
      <Text size="sm" c="dimmed">
        none
      </Text>
    );
  return (
    <Table verticalSpacing={4} fz="xs">
      <Table.Thead>
        <Table.Tr>
          {cols.map(([, label]) => (
            <Table.Th key={label}>{label}</Table.Th>
          ))}
        </Table.Tr>
      </Table.Thead>
      <Table.Tbody>
        {rows.map((r, i) => (
          <Table.Tr key={i}>
            {cols.map(([k]) => (
              <Table.Td key={k}>
                <CellValue name={k} value={r[k]} />
              </Table.Td>
            ))}
          </Table.Tr>
        ))}
      </Table.Tbody>
    </Table>
  );
}

function CellValue({ name, value }: { name: string; value: unknown }) {
  const v = short(value);
  if (name === "sse_verdict") {
    const c = v === "FEASIBLE" ? "orange" : v === "INFEASIBLE" ? "gray" : "yellow";
    return <Badge color={c} variant="light" size="sm">{v}</Badge>;
  }
  if (name === "entity_binding") {
    const c = v === "unbound" ? "red" : v === "partial" ? "yellow" : "green";
    return (
      <Tooltip label={v === "unbound" ? "names entities that are not in the alert's trusted fields (possible steering)" : "entities match the alert"}>
        <Badge color={c} variant="light" size="sm">{v}</Badge>
      </Tooltip>
    );
  }
  if (name === "playbook_status") return <Badge variant="outline" size="sm">{v}</Badge>;
  return <Text size="xs" ff="monospace">{v}</Text>;
}

function StageBody({ stage }: { stage: Stage }) {
  switch (stage.stage) {
    case "alert":
      return (
        <Stack gap="xs">
          <Text size="sm" fw={500}>{String(stage.pattern)}</Text>
          <Text size="xs" c="dimmed">Trusted (structured sensor and inventory fields)</Text>
          <KeyValues data={stage.trusted as Row} />
          <Alert color="red" variant="light" title="Untrusted text" p="xs">
            <Text size="xs">{String(stage.untrusted_notice)}</Text>
          </Alert>
          {Object.entries(stage.untrusted as Row)
            .filter(([k]) => k !== "raw_log_line")
            .map(([k, v]) => (
              <div key={k}>
                <Text size="xs" c="dimmed">{k}</Text>
                <Code block style={{ borderLeft: "3px solid var(--mantine-color-red-6)", whiteSpace: "pre-wrap" }}>
                  {short(v)}
                </Code>
              </div>
            ))}
        </Stack>
      );
    case "triage_gate":
      return (
        <Stack gap={4}>
          <Group gap="xs">
            <Badge variant="light">{String(stage.path)}</Badge>
            <Text size="sm">{String(stage.explanation)}</Text>
          </Group>
          {(stage.escalations as string[]).map((e, i) => (
            <Alert key={i} color="orange" p="xs">{e}</Alert>
          ))}
        </Stack>
      );
    case "reasoning":
      return (
        <Stack gap={4}>
          <Group gap="xs">
            <Badge color="grape">LLM output</Badge>
            <Text size="xs" c="dimmed">NCE status: {String(stage.nce_status)}</Text>
          </Group>
          <Text size="xs" c="dimmed">{String(stage.notice)}</Text>
          <RowsTable rows={stage.hypotheses as Row[]} cols={[["technique_id", "Technique"], ["source_account", "Account"], ["source_host", "Source"], ["target_host", "Target"]]} />
        </Stack>
      );
    case "structural_check":
      return (
        <RowsTable
          rows={stage.checks as Row[]}
          cols={[["technique_id", "Technique"], ["sse_verdict", "Feasibility"], ["path_confidence", "Path confidence"], ["entity_binding", "Entity binding"]]}
        />
      );
    case "response":
      return (
        <RowsTable
          rows={stage.responses as Row[]}
          cols={[["technique_id", "Technique"], ["top_action", "Best response"], ["top_target_host", "Target host"], ["top_composite", "Score"], ["playbook_status", "Guardrails"], ["guardrail_reason", "Why"]]}
        />
      );
    case "decision":
      return (
        <Stack gap={4}>
          <Badge color={OUTCOME_COLOR[String(stage.outcome)] ?? "gray"} size="lg">{String(stage.outcome)}</Badge>
          {(stage.reasons as string[]).map((r, i) => (
            <Text key={i} size="sm">• {r}</Text>
          ))}
        </Stack>
      );
    case "actions":
      return null; // rendered with controls below
    case "learning":
      return (
        <Stack gap={4}>
          <Group gap="xs">
            <Badge color={STATUS_COLOR[String(stage.review_status)] ?? "gray"} variant="light">{String(stage.review_status)}</Badge>
            {stage.verdict ? <Badge color={VERDICT_COLOR[String(stage.verdict)]}>{String(stage.verdict)}</Badge> : null}
          </Group>
          <Text size="xs" c="dimmed">What each verdict would do to the Knowledge Store:</Text>
          {Object.entries(stage.preview as Record<string, string>).map(([k, v]) => (
            <Text key={k} size="xs">
              <Badge size="xs" color={VERDICT_COLOR[k]} mr={6}>{k}</Badge>
              {v}
            </Text>
          ))}
        </Stack>
      );
    default:
      return <KeyValues data={stage as Row} />;
  }
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
  return (
    <Card withBorder p="xs">
      <Group justify="space-between">
        <div>
          <Text size="sm" fw={500}>
            {a.action} → {a.target}
          </Text>
          <Text size="xs" c="dimmed">
            {a.status} · approvals {a.approvals.length}/{a.approvals_needed}
            {a.approvals_needed > 1 ? " (four-eyes: critical host)" : ""}
            {a.approvals.length ? ` · ${a.approvals.join(", ")}` : ""}
          </Text>
        </div>
        <Group gap="xs">
          {a.status === "proposed" && (
            <>
              <Button size="xs" color="red" onClick={() => op.mutate({ path: `/actions/${a.action_id}/approve` })}>
                Approve (simulated)
              </Button>
              <Button size="xs" variant="default" disabled={!reason.trim()} onClick={() => op.mutate({ path: `/actions/${a.action_id}/reject`, body: { reason } })}>
                Reject
              </Button>
            </>
          )}
          {a.status === "executed" && (
            <Button size="xs" variant="default" disabled={!reason.trim()} onClick={() => op.mutate({ path: `/actions/${a.action_id}/rollback`, body: { reason } })}>
              Roll back
            </Button>
          )}
        </Group>
      </Group>
      {(a.status === "proposed" || a.status === "executed") && (
        <Textarea mt="xs" size="xs" autosize placeholder="Reason (required to reject or roll back)" value={reason} onChange={(e) => setReason(e.currentTarget.value)} />
      )}
      {op.error && <Alert color="red" mt="xs" p="xs">{String((op.error as Error).message)}</Alert>}
    </Card>
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

  return (
    <Card withBorder>
      <Title order={5} mb="xs">Analyst decision</Title>
      {!reviewable ? (
        <Text size="sm" c="dimmed">
          {c.review_status === "closed" ? `Closed as ${c.verdict} by ${c.claimed_by}.` : "This case was not sent for review."}
        </Text>
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
          <Group gap="xs">
            {(["malicious", "benign", "benign_once", "needs_info"] as Verdict[]).map((v) => (
              <Tooltip key={v} multiline w={360} label={view.learning_preview[v]}>
                <Button
                  size="xs"
                  color={VERDICT_COLOR[v]}
                  variant={v === "malicious" ? "filled" : "light"}
                  disabled={c.review_status === "claimed" && !mine}
                  onClick={() => op.mutate({ path: `/cases/${id}/verdict`, body: { verdict: v, note: note || undefined } })}
                >
                  {v.replace("_", " ")}
                </Button>
              </Tooltip>
            ))}
          </Group>
        </Stack>
      )}
      {op.error && <Alert color="red" mt="xs" p="xs">{String((op.error as Error).message)}</Alert>}
    </Card>
  );
}

export default function CasePage() {
  const { caseId = "" } = useParams();
  const view = useQuery({ queryKey: ["case", caseId], queryFn: () => api<CaseView>(`/cases/${caseId}`), refetchInterval: 4000 });
  const trace = useQuery({ queryKey: ["trace", caseId], queryFn: () => api<Trace>(`/cases/${caseId}/trace`), refetchInterval: 4000 });
  if (view.isLoading || trace.isLoading) return <Loader />;
  if (view.error || !view.data || !trace.data) return <Alert color="red">{String(view.error ?? trace.error)}</Alert>;
  const v = view.data;
  const c = v.case;

  return (
    <Stack>
      <Anchor component={Link} to="/" size="sm">← Queue</Anchor>
      <Group justify="space-between" align="flex-start">
        <div>
          <Title order={3}>{c.title}</Title>
          <Text size="sm" c="dimmed">
            {c.case_id} · host {c.host ?? "—"}{c.host_tier !== null ? ` (tier ${c.host_tier})` : ""} · opened {when(c.opened)} · {c.alert_count} alerts
          </Text>
        </div>
        <Group gap="xs">
          <Badge color={OUTCOME_COLOR[c.outcome] ?? "gray"} size="lg">{c.outcome}</Badge>
          <Tooltip multiline w={420} label={v.priority_reasons.join("\n") || "no priority factors"} style={{ whiteSpace: "pre-line" }}>
            <Badge variant="outline" size="lg">priority {v.priority}</Badge>
          </Tooltip>
        </Group>
      </Group>

      <Grid>
        <Grid.Col span={{ base: 12, lg: 8 }}>
          <Card withBorder>
            <Title order={5} mb="sm">Pipeline trace</Title>
            <Timeline active={trace.data.stages.length} bulletSize={22} lineWidth={2}>
              {trace.data.stages.map((s, i) => (
                <Timeline.Item key={s.stage} title={`${i + 1}. ${s.title}`}>
                  {s.stage === "actions" ? (
                    <Stack gap="xs" mt={4}>
                      {v.actions.length ? v.actions.map((a) => <ActionRow key={a.action_id} a={a} caseId={c.case_id} />) : <Text size="sm" c="dimmed">No containment proposed.</Text>}
                    </Stack>
                  ) : (
                    <div style={{ marginTop: 4 }}>
                      <StageBody stage={s} />
                    </div>
                  )}
                </Timeline.Item>
              ))}
            </Timeline>
          </Card>
        </Grid.Col>
        <Grid.Col span={{ base: 12, lg: 4 }}>
          <Stack>
            <VerdictPanel view={v} />
            <Card withBorder>
              <Title order={6} mb="xs">Related cases</Title>
              {[...v.related.same_pattern.map((r) => ({ ...r, why: "same pattern" })), ...v.related.same_host_in_queue.map((r) => ({ ...r, why: "same host" }))]
                .slice(0, 12)
                .map((r) => (
                  <Text key={r.case_id + r.why} size="xs">
                    <Anchor component={Link} to={`/cases/${r.case_id}`}>{r.case_id}</Anchor> · {r.why} · {r.title} · {r.review_status}
                    {r.verdict ? ` (${r.verdict})` : ""}
                  </Text>
                ))}
              {!v.related.same_pattern.length && !v.related.same_host_in_queue.length && <Text size="xs" c="dimmed">none</Text>}
            </Card>
            <Card withBorder>
              <Title order={6} mb="xs">Notes</Title>
              {v.notes.length ? v.notes.map((n) => (
                <Text key={n.note_id} size="xs">
                  <b>{n.analyst}</b> · {when(n.at).slice(0, 16)}: {n.text}
                </Text>
              )) : <Text size="xs" c="dimmed">none</Text>}
            </Card>
            <Card withBorder>
              <Title order={6} mb="xs">Audit trail</Title>
              {v.audit.map((e) => (
                <Text key={e.seq} size="xs" ff="monospace">
                  {when(e.at).slice(5, 16)} {e.actor} {e.op}
                </Text>
              ))}
            </Card>
          </Stack>
        </Grid.Col>
      </Grid>
    </Stack>
  );
}
