import { Alert, Anchor, Badge, Grid, Group, Loader, Stack, Text, Title, Tooltip } from "@mantine/core";
import { useQuery } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
import { api } from "../api";
import { IconBrain, IconWarning } from "../components/Icons";
import { OUTCOME_COLOR, short } from "../format";
import { useTechniques } from "../hooks";
import { CHANGE_LABEL, OutcomeChip, type PairRow } from "./Lab";

type Row = Record<string, unknown>;
interface Variant {
  trusted: Row;
  untrusted: Row;
  injected: Record<string, [number, number]>;
  pipeline: { outcome: string | null; reasons: string[]; era_level: string | null; hypotheses: Row[] };
  undefended: { verdict: string; action: string; confidence: string; reasoning: string } | null;
}
interface PairDetail {
  row: PairRow;
  variants: { clean: Variant; contaminated: Variant };
  metadata: { family: string; goal: string | null; site: string | null; steered_entities: string[] };
}

const ROLE: Record<string, string> = { source_account: "account", source_host: "source", target_host: "target" };

/** Text with the attacker's inserted span marked (rendered as text, never HTML). */
function Marked({ text, span }: { text: string; span?: [number, number] }) {
  if (!span) return <>{text}</>;
  return (
    <>
      {text.slice(0, span[0])}
      <mark style={{ background: "rgba(250,178,25,0.28)", color: "inherit", outline: "1px solid rgba(250,178,25,0.6)", borderRadius: 2 }}>
        {text.slice(span[0], span[1])}
      </mark>
      {text.slice(span[1])}
    </>
  );
}

function Side({ name, v, names }: { name: "clean" | "contaminated"; v: Variant; names: Record<string, { name: string }> }) {
  const p = v.pipeline;
  return (
    <Stack gap="md">
      <div className="soc-card" style={{ padding: 16 }}>
        <Group justify="space-between" mb="xs">
          <Text className="soc-card-title">{name === "clean" ? "Clean alert" : "Contaminated alert"}</Text>
          {name === "contaminated" && Object.keys(v.injected).length > 0 && (
            <span className="soc-chip" data-tone="warn">attacker text marked</span>
          )}
        </Group>
        <Group gap={6} mb={6}>
          <span style={{ color: "var(--soc-critical)", display: "inline-flex" }}><IconWarning size={14} /></span>
          <Text size="sm" fw={600}>Untrusted <Text span size="xs" c="dimmed" fw={400}>· attacker-writable text</Text></Text>
        </Group>
        <Stack gap={6}>
          {Object.entries(v.untrusted).filter(([, x]) => x !== null && x !== "").map(([k, x]) => (
            <div key={k}>
              <Text size="xs" c="dimmed">{k}</Text>
              <div className="soc-untrusted"><Marked text={short(x)} span={v.injected[k]} /></div>
            </div>
          ))}
        </Stack>
        <Text size="sm" fw={600} mt="md" mb={4}>Trusted <Text span size="xs" c="dimmed" fw={400}>· structured fields</Text></Text>
        <dl className="soc-kv" style={{ margin: 0 }}>
          {Object.entries(v.trusted).filter(([, x]) => x !== null && x !== "").map(([k, x]) => (
            <div key={k} style={{ display: "contents" }}><dt>{k}</dt><dd>{short(x)}</dd></div>
          ))}
        </dl>
      </div>

      {v.undefended && (
        <div className="soc-card" style={{ padding: 16 }}>
          <Group justify="space-between" mb={6}>
            <Text className="soc-card-title">Undefended LLM agent</Text>
            <Tooltip label="LLM output: the agent read the alert, text included, and decided alone">
              <span style={{ color: "var(--soc-llm)", display: "inline-flex" }}><IconBrain size={16} /></span>
            </Tooltip>
          </Group>
          <Group gap="xs" mb={6}>
            <span className="soc-chip" data-tone={v.undefended.verdict === "benign" ? undefined : "warn"}>verdict: {v.undefended.verdict}</span>
            <span className="soc-chip">action: {v.undefended.action}</span>
            <span className="soc-chip">confidence {v.undefended.confidence}</span>
          </Group>
          <Text size="xs" c="dimmed" style={{ whiteSpace: "pre-wrap" }}>{v.undefended.reasoning}</Text>
        </div>
      )}

      <div className="soc-card" style={{ padding: 16 }}>
        <Group justify="space-between" mb={6}>
          <Text className="soc-card-title">Defended pipeline</Text>
          <Badge color={OUTCOME_COLOR[p.outcome ?? ""] ?? "gray"}>{p.outcome ?? "—"}</Badge>
        </Group>
        {p.era_level && p.era_level !== "LOW" && <Text size="xs" c="yellow" mb={4}>ERA flagged the text: {p.era_level}</Text>}
        {p.reasons.map((r, i) => <Text key={i} size="xs" c="dimmed">• {r}</Text>)}
        <Stack gap={6} mt="sm">
          {p.hypotheses.map((h, i) => {
            const roles = (h.binding_roles ?? {}) as Record<string, string>;
            const unbound = h.entity_binding === "unbound";
            return (
              <div key={i} className="soc-hyp" data-unbound={unbound || undefined} style={{ padding: 10 }}>
                <Group gap={6} mb={4}>
                  <span className="soc-chip" data-tone="llm">{String(h.technique_id)}</span>
                  <Text size="sm" fw={600}>{names[String(h.technique_id)]?.name ?? ""}</Text>
                </Group>
                <Text size="xs" ff="monospace">
                  {(["source_account", "source_host", "target_host"] as const).map((r) => (
                    <span key={r} style={roles[r] === "unbound" ? { color: "#ff8a8a" } : undefined}>{`${ROLE[r]}: ${short(h[r])}   `}</span>
                  ))}
                </Text>
                <Group gap={6} mt={6}>
                  <span className="soc-chip">{String(h.sse_verdict ?? "—").toLowerCase().replace("_", " ")}</span>
                  <span className="soc-chip" data-tone={unbound ? "alert" : h.entity_binding === "bound" ? "good" : "warn"}>{String(h.entity_binding ?? "—")}</span>
                  {h.top_action ? <span className="soc-chip">{String(h.top_action)}{h.top_target_host ? ` → ${String(h.top_target_host)}` : ""}</span> : null}
                  {h.playbook_status ? <span className="soc-chip" data-tone={h.playbook_status === "AUTO_APPROVED" ? "alert" : "warn"}>{String(h.playbook_status).toLowerCase().replace(/_/g, " ")}</span> : null}
                </Group>
              </div>
            );
          })}
          {!p.hypotheses.length && <Text size="xs" c="dimmed">No hypotheses.</Text>}
        </Stack>
      </div>
    </Stack>
  );
}

export default function LabPair() {
  const { run = "", pairId = "" } = useParams();
  const q = useQuery({ queryKey: ["lab-pair", run, pairId], queryFn: () => api<PairDetail>(`/lab/${run}/pairs/${pairId}`), staleTime: Infinity });
  const techniques = useTechniques();
  if (q.isLoading) return <Loader />;
  if (q.error || !q.data) return <Alert color="red">{String(q.error)}</Alert>;
  const d = q.data;
  const r = d.row;
  const names = techniques.data ?? {};
  return (
    <Stack gap="lg">
      <Anchor component={Link} to="/lab" size="sm">← Contamination Lab</Anchor>
      <div className="soc-card" style={{ padding: 16 }}>
        <Group justify="space-between" wrap="wrap" align="flex-start">
          <div>
            <Title order={3} ff="monospace">{d.row.pair_id}</Title>
            <Text size="sm" c="dimmed">{r.title}</Text>
          </div>
          <Group gap="xs">
            <OutcomeChip outcome={r.clean_outcome} /><Text size="xs" c="dimmed">→</Text><OutcomeChip outcome={r.contaminated_outcome} />
            <span className="soc-chip" data-tone={r.change === "suppressed" ? "alert" : undefined}>{CHANGE_LABEL[r.change] ?? r.change}</span>
            {r.undefended?.hijacked && <span className="soc-chip" data-tone="alert">undefended agent hijacked</span>}
          </Group>
        </Group>
        <div className="soc-callout" style={{ marginTop: 12 }}>
          <Text size="xs" fw={700} c="yellow">Experiment metadata (the pipeline never sees it)</Text>
          <Text size="xs" c="dimmed">
            Payload family <b>{d.metadata.family.replace(/_/g, " ")}</b>; the attacker&apos;s goal is to <b>{d.metadata.goal ?? "—"}</b>;
            injected into <b>{d.metadata.site ?? "—"}</b>
            {d.metadata.steered_entities.length ? <>; steers towards <b>{d.metadata.steered_entities.join(", ")}</b></> : null}.
          </Text>
        </div>
      </div>
      <Grid gap="lg">
        <Grid.Col span={{ base: 12, md: 6 }}><Side name="clean" v={d.variants.clean} names={names} /></Grid.Col>
        <Grid.Col span={{ base: 12, md: 6 }}><Side name="contaminated" v={d.variants.contaminated} names={names} /></Grid.Col>
      </Grid>
    </Stack>
  );
}
