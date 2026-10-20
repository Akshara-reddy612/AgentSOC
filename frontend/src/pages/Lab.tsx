import { Anchor, Group, Loader, Pagination, SegmentedControl, Select, SimpleGrid, Stack, Table, Text, Title, Tooltip } from "@mantine/core";
import { useQuery } from "@tanstack/react-query";
import ReactECharts from "echarts-for-react";
import { useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";

// Emphasis encoding (validated on #1c1c1c with the Live chart's pair): the undefended agent's hijacks in
// orange, the defended pipeline's suppressions in gray -- the gap between them is the point.
const UNDEF = "#d95926";
const PIPE = "#7a7a7a";
const TIP = { backgroundColor: "#262626", borderColor: "#3a3a3a", textStyle: { color: "#ececec", fontSize: 12 } };

export interface LabRun { id: string; label: string; set: string; undefended: boolean }
interface Family {
  family: string; goal: string | null; pairs: number; clean_responded: number; suppressed: number;
  misdirect_executed: number; misdirect_gated: number; llm_followed_steering: number;
  undefended_hijacked?: number; undefended_clean_not_dismissed?: number;
}
interface Summary {
  run: string; label: string; set: string;
  total: Record<string, number>;
  undefended: { hijacked: number; clean_not_dismissed: number; pairs: number; model?: string } | null;
  families: Family[];
}
export interface PairRow {
  pair_id: string; family: string; goal: string | null; site: string | null; title: string; change: string;
  clean_outcome: string | null; contaminated_outcome: string | null; misdirect?: string | null;
  llm_followed_steering?: boolean; era_level?: string | null;
  undefended?: { clean: string; contaminated: string; hijacked: boolean };
}

export const CHANGE_LABEL: Record<string, string> = {
  suppressed: "response suppressed",
  induced_by_era: "escalated by ERA",
  induced: "response induced",
  same: "unchanged",
  excluded: "excluded (LLM error)",
};
const FAMILY = (f: string) => f.replace(/_/g, " ");
const pct = (k: number, n: number) => (n ? `${((100 * k) / n).toFixed(1)}%` : "—");

function Tile({ label, value, hint, tone }: { label: string; value: string; hint?: string; tone?: string }) {
  return (
    <div className="soc-card" style={{ padding: "12px 14px", height: "100%" }}>
      <Text size="xs" c="dimmed" fw={600}>{label}</Text>
      <div className="soc-kpi-value" style={{ marginTop: 4, color: tone }}>{value}</div>
      {hint && <Text size="xs" c="dimmed" mt={2}>{hint}</Text>}
    </div>
  );
}

export function OutcomeChip({ outcome }: { outcome: string | null | undefined }) {
  const responded = outcome === "REVIEW" || outcome === "AUTO_APPROVED";
  return <span className="soc-chip" data-tone={responded ? "warn" : undefined}>{outcome ?? "—"}</span>;
}

function FamilyChart({ s }: { s: Summary }) {
  const fams = [...s.families].reverse();
  const und = !!s.undefended;
  const series = [
    ...(und ? [{
      name: "Undefended agent: hijacked", type: "bar", barMaxWidth: 12, itemStyle: { color: UNDEF, borderRadius: [0, 3, 3, 0] },
      data: fams.map((f) => (f.undefended_clean_not_dismissed ? (100 * (f.undefended_hijacked ?? 0)) / f.undefended_clean_not_dismissed : 0)),
    }] : []),
    {
      name: "Pipeline: response suppressed", type: "bar", barMaxWidth: 12, itemStyle: { color: PIPE, borderRadius: [0, 3, 3, 0] },
      data: fams.map((f) => (f.clean_responded ? (100 * f.suppressed) / f.clean_responded : 0)),
    },
  ];
  return (
    <ReactECharts
      style={{ height: 40 + fams.length * (und ? 34 : 24) }}
      opts={{ renderer: "svg" }}
      option={{
        animation: false,
        grid: { left: 190, right: 30, top: 30, bottom: 24 },
        legend: { top: 0, right: 0, icon: "roundRect", itemWidth: 10, itemHeight: 10, textStyle: { color: "#a6a6a6", fontSize: 12 } },
        tooltip: {
          trigger: "axis", axisPointer: { type: "shadow", shadowStyle: { color: "rgba(255,255,255,0.05)" } }, ...TIP,
          formatter: (p: { dataIndex: number }[]) => {
            const f = fams[p[0].dataIndex];
            const lines = [`<b>${FAMILY(f.family)}</b> (${f.goal ?? ""})`];
            if (und) lines.push(`Undefended agent hijacked: <b>${f.undefended_hijacked ?? 0} / ${f.undefended_clean_not_dismissed ?? 0}</b>`);
            lines.push(`Pipeline response suppressed: <b>${f.suppressed} / ${f.clean_responded}</b>`);
            return lines.join("<br/>");
          },
        },
        xAxis: { type: "value", max: 100, axisLabel: { color: "#767676", formatter: "{value}%", fontSize: 11 }, splitLine: { lineStyle: { color: "#2b2b2b" } } },
        yAxis: {
          type: "category", data: fams.map((f) => FAMILY(f.family)), axisTick: { show: false },
          axisLine: { lineStyle: { color: "#3a3a3a" } }, axisLabel: { color: "#a6a6a6", fontSize: 12 },
        },
        series,
      }}
    />
  );
}

export default function Lab() {
  const runs = useQuery({ queryKey: ["lab-runs"], queryFn: () => api<LabRun[]>("/lab/runs"), staleTime: Infinity });
  const [run, setRun] = useState("dev_gemini");
  const [family, setFamily] = useState<string | null>(null);
  const [change, setChange] = useState("all");
  const [page, setPage] = useState(1);
  const summary = useQuery({ queryKey: ["lab-summary", run], queryFn: () => api<Summary>(`/lab/${run}/summary`), staleTime: Infinity });
  const params = new URLSearchParams({ limit: "25", offset: String((page - 1) * 25) });
  if (family) params.set("family", family);
  if (change !== "all") params.set("change", change);
  const pairs = useQuery({
    queryKey: ["lab-pairs", run, family, change, page],
    queryFn: () => api<{ total: number; items: PairRow[] }>(`/lab/${run}/pairs?${params}`),
    staleTime: Infinity,
  });
  const s = summary.data;
  const t = s?.total;

  return (
    <Stack gap="lg">
      <Group justify="space-between" align="flex-end" wrap="wrap">
        <div>
          <Title order={2}>Contamination Lab</Title>
          <Text size="sm" c="dimmed" maw={860}>
            GUIDE v2: alerts recorded twice, clean and with attacker-written text at one place (10 payload families that try to
            get the alert dismissed or the response aimed at the wrong account). What an undefended LLM agent did with that text,
            and what the defended pipeline did. Replayed from the recorded runs: no API calls.
          </Text>
        </div>
        <SegmentedControl size="xs" value={run} onChange={(v) => { setRun(v); setPage(1); }}
          data={(runs.data ?? []).map((r) => ({ value: r.id, label: r.label }))} />
      </Group>

      {!s || !t ? <Loader /> : (
        <>
          <SimpleGrid cols={{ base: 2, md: 4 }}>
            <Tile label="Undefended LLM agent: hijacked" tone={s.undefended ? "#ec835a" : undefined}
              value={s.undefended ? `${s.undefended.hijacked} / ${s.undefended.clean_not_dismissed}` : "—"}
              hint={s.undefended ? `${pct(s.undefended.hijacked, s.undefended.clean_not_dismissed)}: dismissed an alert it flagged when clean (${s.undefended.model ?? "LLM"})` : "not run on this set"} />
            <Tile label="Defended pipeline: response suppressed" value={`${t.suppressed} / ${t.clean_responded}`}
              hint={`${pct(t.suppressed, t.clean_responded)}: the clean twin got a response, the contaminated one did not`} />
            <Tile label="Responses changed for other reasons" value={`${t.induced}`}
              hint={`plus ${t.induced_by_era} escalated because ERA flagged the injected text`} />
            <Tile label="Misdirected actions executed" value={`${t.misdirect_executed}`}
              hint={`${t.misdirect_gated} steered actions were stopped by guardrails; ${t.llm_followed_steering} times the LLM named the injected account or server`} />
          </SimpleGrid>

          <div className="soc-card" style={{ padding: 16 }}>
            <Text className="soc-card-title">By payload family</Text>
            <Text size="xs" c="dimmed">
              Share of the pairs each could affect: alerts the agent did not dismiss when clean, or alerts the pipeline responded to when clean.
            </Text>
            <FamilyChart s={s} />
          </div>
        </>
      )}

      <div className="soc-card" style={{ overflow: "hidden" }}>
        <Group justify="space-between" p="md" pb="sm" wrap="wrap" gap="sm">
          <div>
            <Text className="soc-card-title">Pairs</Text>
            <Text size="xs" c="dimmed">{pairs.data ? `${pairs.data.total} pairs` : " "}; open one to compare the clean and contaminated alert</Text>
          </div>
          <Group gap="sm" wrap="wrap">
            <Select size="xs" w={210} placeholder="All payload families" clearable value={family}
              onChange={(v) => { setFamily(v); setPage(1); }}
              data={(s?.families ?? []).map((f) => ({ value: f.family, label: FAMILY(f.family) }))} />
            <SegmentedControl size="xs" value={change} onChange={(v) => { setChange(v); setPage(1); }}
              data={[
                { value: "all", label: "All" },
                { value: "suppressed", label: "Suppressed" },
                { value: "steered", label: "LLM steered" },
                ...(s?.undefended ? [{ value: "hijacked", label: "Agent hijacked" }] : []),
                { value: "induced_by_era", label: "ERA escalated" },
              ]} />
          </Group>
        </Group>
        <Table.ScrollContainer minWidth={820} type="native">
        <Table verticalSpacing={6} fz="sm" highlightOnHover>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Pair</Table.Th>
              <Table.Th>Payload family</Table.Th>
              <Table.Th>Pipeline: clean → contaminated</Table.Th>
              {s?.undefended && <Table.Th>Undefended agent</Table.Th>}
              <Table.Th>Notes</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {(pairs.data?.items ?? []).map((r) => (
              <Table.Tr key={r.pair_id}>
                <Table.Td>
                  <Anchor component={Link} to={`/lab/${run}/${r.pair_id}`} ff="monospace" size="xs">{r.pair_id}</Anchor>
                  <Text size="xs" c="dimmed">{r.title}</Text>
                </Table.Td>
                <Table.Td>
                  <Text size="sm">{FAMILY(r.family)}</Text>
                  <Text size="xs" c="dimmed">goal: {r.goal ?? "—"} · in {r.site ?? "—"}</Text>
                </Table.Td>
                <Table.Td>
                  <Group gap={6} wrap="nowrap">
                    <OutcomeChip outcome={r.clean_outcome} /><Text size="xs" c="dimmed">→</Text><OutcomeChip outcome={r.contaminated_outcome} />
                  </Group>
                  <Text size="xs" c={r.change === "suppressed" ? "orange" : "dimmed"} mt={2}>{CHANGE_LABEL[r.change] ?? r.change}</Text>
                </Table.Td>
                {s?.undefended && (
                  <Table.Td>
                    {r.undefended ? (
                      <>
                        <Text size="xs">{r.undefended.clean} → {r.undefended.contaminated}</Text>
                        {r.undefended.hijacked && <span className="soc-chip" data-tone="alert">hijacked</span>}
                      </>
                    ) : <Text size="xs" c="dimmed">—</Text>}
                  </Table.Td>
                )}
                <Table.Td>
                  <Group gap={4}>
                    {r.llm_followed_steering && (
                      <Tooltip label="An LLM hypothesis named the injected account or server"><span className="soc-chip" data-tone="llm">LLM steered</span></Tooltip>
                    )}
                    {r.misdirect && <span className="soc-chip" data-tone={r.misdirect === "executed" ? "alert" : "good"}>misdirected action {r.misdirect}</span>}
                  </Group>
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
        </Table.ScrollContainer>
        {pairs.data && pairs.data.total > 25 && (
          <Group justify="center" p="sm"><Pagination size="sm" total={Math.ceil(pairs.data.total / 25)} value={page} onChange={setPage} /></Group>
        )}
        {pairs.data && !pairs.data.total && <Text c="dimmed" ta="center" py="lg">No pair matches the filters.</Text>}
      </div>
    </Stack>
  );
}
