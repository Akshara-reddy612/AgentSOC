import { Card, Grid, Group, Paper, SimpleGrid, Stack, Table, Text, Title } from "@mantine/core";
import { useQuery } from "@tanstack/react-query";
import ReactECharts from "echarts-for-react";
import { api, type Metrics } from "../api";

// Categorical slots (dark steps of the validated reference palette; slots 1-4 pass all dark checks).
const SLOT = ["#3987e5", "#d95926", "#199e70", "#c98500"];
const INK = "#c1c2c5";
const MUTED = "#909296";
const GRID = "#2c2e33";
const SURFACE = "#1a1b1e";
const TEST_DAYS = Array.from({ length: 14 }, (_, i) => new Date(Date.UTC(2025, 0, 6 + i)).toISOString().slice(0, 10));

const axis = {
  axisLine: { lineStyle: { color: GRID } },
  axisTick: { show: false },
  axisLabel: { color: MUTED, fontSize: 11 },
  splitLine: { lineStyle: { color: GRID } },
};

function Tile({ label, value, hint }: { label: string; value: string; hint?: string }) {
  return (
    <Paper withBorder p="sm">
      <Text size="xs" c="dimmed" tt="uppercase">{label}</Text>
      <Text size="xl" fw={600}>{value}</Text>
      {hint && <Text size="xs" c="dimmed">{hint}</Text>}
    </Paper>
  );
}

function lineOption(series: { name: string; data: number[] }[]) {
  return {
    backgroundColor: "transparent",
    textStyle: { color: INK },
    tooltip: { trigger: "axis", axisPointer: { type: "line" }, valueFormatter: (v: number) => `${v} reviews` },
    legend: { top: 0, textStyle: { color: INK } },
    grid: { left: 44, right: 24, top: 36, bottom: 30 },
    xAxis: { type: "category", data: TEST_DAYS.map((d) => d.slice(5)), ...axis, splitLine: { show: false } },
    yAxis: { type: "value", name: "reviews / day", nameTextStyle: { color: MUTED }, ...axis },
    series: series.map((s, i) => ({
      name: s.name,
      type: "line",
      data: s.data,
      lineStyle: { width: 2, color: SLOT[i] },
      itemStyle: { color: SLOT[i], borderColor: SURFACE, borderWidth: 2 },
      symbolSize: 8,
      emphasis: { focus: "series" },
    })),
  };
}

function stackedOption(days: string[], series: { name: string; data: number[] }[], unit: string) {
  return {
    backgroundColor: "transparent",
    textStyle: { color: INK },
    tooltip: { trigger: "axis", axisPointer: { type: "shadow" }, valueFormatter: (v: number) => `${v} ${unit}` },
    legend: { top: 0, textStyle: { color: INK } },
    grid: { left: 44, right: 16, top: 36, bottom: 30 },
    xAxis: { type: "category", data: days.map((d) => d.slice(5)), ...axis, splitLine: { show: false } },
    yAxis: { type: "value", ...axis },
    series: series.map((s, i) => ({
      name: s.name,
      type: "bar",
      stack: "total",
      data: s.data,
      barMaxWidth: 28,
      itemStyle: { color: SLOT[i], borderColor: SURFACE, borderWidth: 2, borderRadius: [4, 4, 0, 0] },
      emphasis: { focus: "series" },
    })),
  };
}

export default function MetricsPage() {
  const { data } = useQuery({ queryKey: ["metrics"], queryFn: () => api<Metrics>("/metrics"), refetchInterval: 5000 });
  if (!data) return null;
  const cmp = data.comparison;
  const learningModes = ["learning behind the gate", "learning without the gate", "gate + analyst (4 h)"].filter((k) => cmp[k]);

  const liveDays = Object.keys(data.cases_per_day).filter((d) => d >= "2025-01-06");
  const outcomes = ["REVIEW", "NO_ACTIONABLE", "LOW_PRIORITY", "AUTO_APPROVED"];
  const learnDays = Object.keys(data.learning_per_day).filter((d) => d >= "2025-01-06");
  const learnKinds = ["closed_benign", "analyst", "retracted"];
  const trainingTotal = Object.values(data.learning_per_day).reduce((a, d) => a + (d.training ?? 0), 0);

  return (
    <Stack>
      <div>
        <Title order={3}>Metrics</Title>
        <Text size="sm" c="dimmed">
          What learning does to the analyst&apos;s workload, from the frozen DEDALE runs (14 test days, exact labels), and the
          live session so far.
        </Text>
      </div>

      <SimpleGrid cols={{ base: 2, md: 4 }}>
        {Object.entries(cmp).map(([label, v]) => (
          <Tile key={label} label={label} value={`${v.mean.toLocaleString()} / day`} hint="mean analyst reviews, host logs" />
        ))}
      </SimpleGrid>

      {learningModes.length > 0 && (
        <Card withBorder>
          <Group justify="space-between" mb="xs">
            <Title order={6}>Reviews per day by learning mode (frozen DEDALE runs)</Title>
            <Text size="xs" c="dimmed">&quot;no learning&quot; is off this scale: see its tile</Text>
          </Group>
          <ReactECharts style={{ height: 320 }} option={lineOption(learningModes.map((k) => ({ name: k, data: cmp[k].by_day })))} />
        </Card>
      )}

      <Grid>
        <Grid.Col span={{ base: 12, lg: 6 }}>
          <Card withBorder>
            <Title order={6} mb="xs">This session: cases per day by triage outcome</Title>
            {liveDays.length ? (
              <ReactECharts
                style={{ height: 280 }}
                option={stackedOption(liveDays, outcomes.map((o) => ({ name: o, data: liveDays.map((d) => data.cases_per_day[d]?.[o] ?? 0) })), "cases")}
              />
            ) : (
              <Text size="sm" c="dimmed">No test-window cases yet: start the replay.</Text>
            )}
          </Card>
        </Grid.Col>
        <Grid.Col span={{ base: 12, lg: 6 }}>
          <Card withBorder>
            <Title order={6} mb="xs">This session: patterns learned and retracted per day</Title>
            <Text size="xs" c="dimmed" mb="xs">
              {trainingTotal.toLocaleString()} patterns were learned in the two benign training weeks (not shown).
            </Text>
            {learnDays.length ? (
              <ReactECharts
                style={{ height: 260 }}
                option={stackedOption(learnDays, learnKinds.map((k) => ({ name: k, data: learnDays.map((d) => data.learning_per_day[d]?.[k] ?? 0) })), "patterns")}
              />
            ) : (
              <Text size="sm" c="dimmed">Nothing learned after training yet.</Text>
            )}
          </Card>
        </Grid.Col>
      </Grid>

      <SimpleGrid cols={{ base: 1, md: 3 }}>
        {[["Review status", data.review_status], ["Verdicts", data.verdicts], ["Containment actions", data.actions]].map(([title, rows]) => (
          <Card withBorder key={title as string}>
            <Title order={6} mb="xs">{title as string}</Title>
            <Table fz="sm" verticalSpacing={2}>
              <Table.Tbody>
                {Object.entries(rows as Record<string, number>).map(([k, n]) => (
                  <Table.Tr key={k}>
                    <Table.Td>{k}</Table.Td>
                    <Table.Td ta="right">{n}</Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
            {!Object.keys(rows as object).length && <Text size="sm" c="dimmed">none yet</Text>}
          </Card>
        ))}
      </SimpleGrid>
    </Stack>
  );
}
