import { Alert, Anchor, Group, Loader, SegmentedControl, SimpleGrid, Stack, Text, Title } from "@mantine/core";
import { useQuery } from "@tanstack/react-query";
import ReactECharts from "echarts-for-react";
import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api } from "../api";
import { IconHost, IconNetwork } from "../components/Icons";
import { VERDICT_COLOR } from "../format";

// Same emphasis encoding as the Live page: cases closed by the pipeline gray, cases sent to an analyst
// orange; a confirmed-malicious case adds a critical-red ring (with its label in the list below).
const CLOSED = "#7a7a7a";
const REVIEW = "#d95926";
const CRITICAL = "#d03b3b";
const TIER: Record<number, string> = { 0: "workstation", 1: "server", 2: "critical server", 3: "domain controller" };
const WAITING = ["open", "claimed", "needs_info"];

interface TimelineCase {
  case_id: string; title: string; kind: string; opened: string; last_seen: string; alert_count: number; outcome: string;
  review_status: string; verdict: string | null; techniques: string[]; actions: { action: string; target: string; status: string }[];
}
interface Timeline { host: string; tier: number | null; total: number; cases: TimelineCase[] }

function Tile({ label, value, tone }: { label: string; value: number | string; tone?: string }) {
  return (
    <div className="soc-card" style={{ padding: "12px 14px" }}>
      <Text size="xs" c="dimmed" fw={600}>{label}</Text>
      <div className="soc-kpi-value" style={{ marginTop: 4, color: tone }}>{value}</div>
    </div>
  );
}

function Strip({ cases, onOpen }: { cases: TimelineCase[]; onOpen: (id: string) => void }) {
  const point = (c: TimelineCase) => ({
    value: [c.opened, c.outcome === "REVIEW" || c.outcome === "AUTO_APPROVED" ? 1 : 0],
    id: c.case_id, title: c.title,
    itemStyle: {
      color: c.review_status === "none" ? CLOSED : REVIEW,
      borderColor: c.verdict === "malicious" ? CRITICAL : "#1c1c1c", borderWidth: c.verdict === "malicious" ? 3 : 1,
    },
  });
  return (
    <ReactECharts
      style={{ height: 150 }}
      opts={{ renderer: "svg" }}
      onEvents={{ click: (e: { data?: { id?: string } }) => e.data?.id && onOpen(e.data.id) }}
      option={{
        animation: false,
        useUTC: true, // stream times are UTC everywhere in the console
        grid: { left: 130, right: 16, top: 10, bottom: 28 },
        tooltip: {
          trigger: "item", backgroundColor: "#262626", borderColor: "#3a3a3a", textStyle: { color: "#ececec", fontSize: 12 },
          formatter: (p: { data: { value: [string, number]; title: string; id: string } }) =>
            `<b>${p.data.value[0].slice(0, 16).replace("T", " ")} UTC</b><br/>${p.data.title.replace(/[<>&]/g, "")}<br/><span style="color:#a6a6a6">${p.data.id} · click to open</span>`,
        },
        xAxis: { type: "time", axisLine: { lineStyle: { color: "#3a3a3a" } }, axisLabel: { color: "#767676", fontSize: 11 }, splitLine: { lineStyle: { color: "#2b2b2b" } } },
        yAxis: {
          type: "category", data: ["Closed by the pipeline", "Sent to an analyst"], axisTick: { show: false },
          axisLine: { lineStyle: { color: "#3a3a3a" } }, axisLabel: { color: "#a6a6a6", fontSize: 12 },
        },
        series: [{ type: "scatter", symbolSize: 11, data: cases.map(point), cursor: "pointer" }],
      }}
    />
  );
}

export default function HostPage() {
  const { host = "" } = useParams();
  const navigate = useNavigate();
  const [show, setShow] = useState("all");
  const q = useQuery({ queryKey: ["timeline", host], queryFn: () => api<Timeline>(`/hosts/${encodeURIComponent(host)}/timeline`), refetchInterval: 5000 });
  if (q.isLoading) return <Loader />;
  if (q.error || !q.data) return <Alert color="red">{String(q.error)}</Alert>;
  const t = q.data;
  const waiting = t.cases.filter((c) => WAITING.includes(c.review_status)).length;
  const malicious = t.cases.filter((c) => c.verdict === "malicious").length;
  const executed = t.cases.flatMap((c) => c.actions).filter((a) => a.status === "executed").length;
  const shown = t.cases.filter((c) => show === "all" || (show === "review" ? c.review_status !== "none" : c.verdict === "malicious"));
  const byDay = new Map<string, TimelineCase[]>();
  for (const c of shown) byDay.set(c.opened.slice(0, 10), [...(byDay.get(c.opened.slice(0, 10)) ?? []), c]);

  return (
    <Stack gap="lg">
      <Anchor component={Link} to="/" size="sm">← SOC overview</Anchor>
      <div>
        <Group gap="sm">
          <span style={{ color: "var(--soc-text-2)", display: "flex" }}><IconHost size={22} /></span>
          <Title order={2}>{t.host}</Title>
          {t.tier != null && <span className="soc-chip">{TIER[t.tier] ?? `tier ${t.tier}`}</span>}
        </Group>
        <Text size="sm" c="dimmed" maw={820}>
          Everything the SOC opened on this host, in stream order: what the pipeline saw and what happened to each case.
          {t.total > t.cases.length ? ` Showing the latest ${t.cases.length} of ${t.total}.` : ""}
        </Text>
      </div>
      <SimpleGrid cols={{ base: 2, md: 4 }}>
        <Tile label="Cases on this host" value={t.total.toLocaleString("en-US")} />
        <Tile label="Waiting for an analyst" value={waiting} />
        <Tile label="Confirmed malicious" value={malicious} tone={malicious ? "var(--soc-critical)" : undefined} />
        <Tile label="Containment executed (simulated)" value={executed} />
      </SimpleGrid>

      <div className="soc-card" style={{ padding: 16 }}>
        <Text className="soc-card-title">Activity over stream time</Text>
        <Text size="xs" c="dimmed">Each dot is a case; a red ring marks a confirmed-malicious one. Click a dot to open it.</Text>
        {t.cases.length ? <Strip cases={t.cases} onOpen={(id) => navigate(`/cases/${id}`)} /> : <Text size="sm" c="dimmed">No cases on this host.</Text>}
      </div>

      <div className="soc-card" style={{ padding: 16 }}>
        <Group justify="space-between" mb="sm" wrap="wrap">
          <Text className="soc-card-title">Chronology</Text>
          <SegmentedControl size="xs" value={show} onChange={setShow}
            data={[{ value: "all", label: "All cases" }, { value: "review", label: "Sent to an analyst" }, { value: "malicious", label: "Confirmed malicious" }]} />
        </Group>
        <Stack gap="md">
          {[...byDay.entries()].map(([day, items]) => (
            <div key={day}>
              <Text size="xs" fw={600} c="dimmed" mb={4}>
                {new Date(day + "T00:00:00Z").toLocaleDateString("en-GB", { weekday: "long", day: "numeric", month: "long", year: "numeric", timeZone: "UTC" })}
              </Text>
              <Stack gap={0}>
                {items.map((c) => (
                  <Group key={c.case_id} gap="sm" wrap="nowrap" align="flex-start"
                    style={{ padding: "6px 0", borderBottom: "1px solid var(--soc-border)" }}>
                    <Text size="xs" ff="monospace" c="dimmed" w={44} style={{ flexShrink: 0, paddingTop: 2 }}>{c.opened.slice(11, 16)}</Text>
                    <span className="soc-stripe" style={{ minHeight: 18, background: c.verdict === "malicious" ? CRITICAL : c.review_status === "none" ? "var(--soc-surface-3)" : REVIEW }} />
                    <span style={{ color: "var(--soc-muted)", display: "inline-flex", paddingTop: 2 }}>
                      {c.kind === "network" ? <IconNetwork size={14} /> : <IconHost size={14} />}
                    </span>
                    <div style={{ minWidth: 0, flex: 1 }}>
                      <Anchor component={Link} to={`/cases/${c.case_id}`} size="sm">{c.title}</Anchor>
                      <Group gap={4} mt={2}>
                        <span className="soc-chip">{c.review_status === "none" ? `closed by the pipeline (${c.outcome.toLowerCase().replace("_", " ")})` : c.review_status.replace("_", " ")}</span>
                        {c.verdict && <span className="soc-chip" data-tone={c.verdict === "malicious" ? "alert" : "good"} style={{ color: VERDICT_COLOR[c.verdict] }}>{c.verdict.replace("_", " ")}</span>}
                        {c.techniques.map((x) => <span key={x} className="soc-chip">{x}</span>)}
                        {c.alert_count > 1 && <span className="soc-chip">{c.alert_count} alerts</span>}
                        {c.actions.map((a, i) => (
                          <span key={i} className="soc-chip" data-tone={a.status === "executed" ? "alert" : "warn"}>{a.action} {a.status}</span>
                        ))}
                      </Group>
                    </div>
                  </Group>
                ))}
              </Stack>
            </div>
          ))}
          {!shown.length && <Text size="sm" c="dimmed">No case matches.</Text>}
        </Stack>
      </div>
    </Stack>
  );
}
