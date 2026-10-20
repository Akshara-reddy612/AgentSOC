import { Grid, Group, SimpleGrid, Stack, Table, Text, Title } from "@mantine/core";
import { useQuery } from "@tanstack/react-query";
import ReactECharts from "echarts-for-react";
import { api, type Metrics } from "../api";
import { PROVENANCE_COLOR, PROVENANCE_LABEL } from "../format";

// Colours follow the meaning used on every page (validated on the graphite surface #1c1c1c):
// learning modes and provenance share the aqua / blue / orange trio (all pairs pass); routine work is gray,
// work for an analyst orange (the Live page's emphasis encoding); retractions use the critical status red.
const MODE_COLOR: Record<string, string> = {
  "learning behind the gate": "#199e70",
  "gate + analyst (4 h)": "#3987e5",
  "learning without the gate": "#d95926",
};
const INK_2 = "#a6a6a6";
const MUTED = "#767676";
const GRID = "#2b2b2b";
const SURFACE = "#1c1c1c";
const TIP = { backgroundColor: "#262626", borderColor: "#3a3a3a", textStyle: { color: "#ececec", fontSize: 12 } };
const TEST_DAYS = Array.from({ length: 14 }, (_, i) => new Date(Date.UTC(2025, 0, 6 + i)).toISOString().slice(0, 10));

const axis = {
  axisLine: { lineStyle: { color: "#3a3a3a" } },
  axisTick: { show: false },
  axisLabel: { color: MUTED, fontSize: 11 },
  splitLine: { lineStyle: { color: GRID } },
};
const legend = { top: 0, right: 0, icon: "roundRect", itemWidth: 10, itemHeight: 10, textStyle: { color: INK_2, fontSize: 12 } };

function Tile({ label, value, hint, color }: { label: string; value: string; hint?: string; color?: string }) {
  return (
    <div className="soc-card" style={{ padding: "12px 14px", borderTop: color ? `2px solid ${color}` : undefined }}>
      <Text size="xs" c="dimmed" fw={600}>{label}</Text>
      <div className="soc-kpi-value" style={{ marginTop: 4 }}>{value}</div>
      {hint && <Text size="xs" c="dimmed" mt={2}>{hint}</Text>}
    </div>
  );
}

function lineOption(series: { name: string; data: number[] }[]) {
  return {
    animation: false,
    tooltip: { trigger: "axis", ...TIP, axisPointer: { type: "line", lineStyle: { color: MUTED } }, valueFormatter: (v: number) => `${v} reviews` },
    legend,
    grid: { left: 44, right: 16, top: 36, bottom: 30 },
    xAxis: { type: "category", data: TEST_DAYS.map((d) => d.slice(5)), ...axis, splitLine: { show: false } },
    yAxis: { type: "value", name: "reviews / day", nameTextStyle: { color: MUTED, fontSize: 11 }, ...axis },
    series: series.map((s) => ({
      name: s.name, type: "line", data: s.data, symbolSize: 8,
      lineStyle: { width: 2, color: MODE_COLOR[s.name] }, itemStyle: { color: MODE_COLOR[s.name], borderColor: SURFACE, borderWidth: 2 },
      emphasis: { focus: "series" },
    })),
  };
}

function stackedOption(days: string[], series: { name: string; data: number[]; color: string }[], unit: string) {
  return {
    animation: false,
    tooltip: { trigger: "axis", ...TIP, axisPointer: { type: "shadow", shadowStyle: { color: "rgba(255,255,255,0.05)" } }, valueFormatter: (v: number) => `${v} ${unit}` },
    legend,
    grid: { left: 44, right: 12, top: 36, bottom: 30 },
    xAxis: { type: "category", data: days.map((d) => d.slice(5)), ...axis, splitLine: { show: false } },
    yAxis: { type: "value", minInterval: 1, ...axis },
    series: series.map((s, i) => ({
      name: s.name, type: "bar", stack: "total", data: s.data, barMaxWidth: 28,
      itemStyle: { color: s.color, borderColor: SURFACE, borderWidth: 1, borderRadius: i === series.length - 1 ? [3, 3, 0, 0] : 0 },
      emphasis: { focus: "series" },
    })),
  };
}

function Counts({ title, rows }: { title: string; rows: Record<string, number> }) {
  return (
    <div className="soc-card" style={{ padding: 16 }}>
      <Text className="soc-card-title" mb="xs">{title}</Text>
      <Table fz="sm" verticalSpacing={3} style={{ fontVariantNumeric: "tabular-nums" }}>
        <Table.Tbody>
          {Object.entries(rows).map(([k, n]) => (
            <Table.Tr key={k}>
              <Table.Td>{k.replace(/_/g, " ")}</Table.Td>
              <Table.Td ta="right">{n.toLocaleString("en-US")}</Table.Td>
            </Table.Tr>
          ))}
        </Table.Tbody>
      </Table>
      {!Object.keys(rows).length && <Text size="sm" c="dimmed">none yet</Text>}
    </div>
  );
}

export default function MetricsPage() {
  const { data } = useQuery({ queryKey: ["metrics"], queryFn: () => api<Metrics>("/metrics"), refetchInterval: 5000 });
  if (!data) return null;
  const cmp = data.comparison;
  const modes = ["learning behind the gate", "gate + analyst (4 h)", "learning without the gate"].filter((k) => cmp[k]);

  const liveDays = Object.keys(data.cases_per_day).filter((d) => d >= "2025-01-06");
  const day = (d: string, o: string) => data.cases_per_day[d]?.[o] ?? 0;
  const learnDays = Object.keys(data.learning_per_day).filter((d) => d >= "2025-01-06");
  const learnKinds = ["closed_benign", "analyst", "retracted"];
  const trainingTotal = Object.values(data.learning_per_day).reduce((a, d) => a + (d.training ?? 0), 0);

  return (
    <Stack gap="lg">
      <div>
        <Title order={2}>Metrics</Title>
        <Text size="sm" c="dimmed" maw={820}>
          What learning does to the analyst&apos;s workload: the frozen DEDALE runs (14 test days, exact labels; the paper&apos;s
          numbers), and this session so far.
        </Text>
      </div>

      <SimpleGrid cols={{ base: 2, md: 4 }}>
        {Object.entries(cmp).map(([label, v]) => (
          <Tile key={label} label={label} value={`${v.mean.toLocaleString("en-US")} / day`} hint="mean analyst reviews, host logs"
            color={MODE_COLOR[label]} />
        ))}
      </SimpleGrid>

      {modes.length > 0 && (
        <div className="soc-card" style={{ padding: 16 }}>
          <Text className="soc-card-title">Reviews per day by learning mode</Text>
          <Text size="xs" c="dimmed">Frozen DEDALE runs. &quot;No learning&quot; (6,095 a day) is off this scale.</Text>
          <ReactECharts style={{ height: 320 }} opts={{ renderer: "svg" }} option={lineOption(modes.map((k) => ({ name: k, data: cmp[k].by_day })))} />
        </div>
      )}

      <Grid gap="lg">
        <Grid.Col span={{ base: 12, lg: 6 }}>
          <div className="soc-card" style={{ padding: 16 }}>
            <Text className="soc-card-title">This session: cases per day</Text>
            <Text size="xs" c="dimmed">Closed by the pipeline, sent to an analyst, or contained automatically</Text>
            {liveDays.length ? (
              <ReactECharts style={{ height: 280 }} opts={{ renderer: "svg" }} option={stackedOption(liveDays, [
                // red and orange are never adjacent (dE 6.8 side by side); gray separates them
                { name: "Contained automatically", data: liveDays.map((d) => day(d, "AUTO_APPROVED")), color: "#d03b3b" },
                { name: "Closed automatically", data: liveDays.map((d) => day(d, "LOW_PRIORITY") + day(d, "NO_ACTIONABLE")), color: "#7a7a7a" },
                { name: "Sent to an analyst", data: liveDays.map((d) => day(d, "REVIEW")), color: "#d95926" },
              ], "cases")} />
            ) : (
              <Text size="sm" c="dimmed" mt="sm">No test-period cases yet: start the replay.</Text>
            )}
          </div>
        </Grid.Col>
        <Grid.Col span={{ base: 12, lg: 6 }}>
          <div className="soc-card" style={{ padding: 16 }}>
            <Text className="soc-card-title">This session: patterns learned and retracted</Text>
            <Text size="xs" c="dimmed">{trainingTotal.toLocaleString("en-US")} patterns were learned in the two training weeks (not shown).</Text>
            {learnDays.length ? (
              <ReactECharts style={{ height: 280 }} opts={{ renderer: "svg" }} option={stackedOption(learnDays,
                learnKinds.map((k) => ({ name: PROVENANCE_LABEL[k] ?? k, data: learnDays.map((d) => data.learning_per_day[d]?.[k] ?? 0), color: PROVENANCE_COLOR[k] })),
                "patterns")} />
            ) : (
              <Text size="sm" c="dimmed" mt="sm">Nothing learned after training yet.</Text>
            )}
          </div>
        </Grid.Col>
      </Grid>

      <SimpleGrid cols={{ base: 1, md: 3 }}>
        <Counts title="Review status" rows={data.review_status} />
        <Counts title="Verdicts" rows={data.verdicts} />
        <Counts title="Containment actions" rows={data.actions} />
      </SimpleGrid>
      <Group><Text size="xs" c="dimmed">Containment is simulated: nothing touches a real network.</Text></Group>
    </Stack>
  );
}
