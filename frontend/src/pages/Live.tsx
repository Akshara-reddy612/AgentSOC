import { Alert, Anchor, Button, Grid, Group, SegmentedControl, Stack, Switch, Text, TextInput, Title, Tooltip } from "@mantine/core";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useMemo, useState, type ReactNode } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api, type LiveStatus, type QueueItem } from "../api";
import { canControl, useAuth } from "../auth";
import { ActivityChart, Sparkline, type HourBucket } from "../components/Charts";
import { IconChevron, IconHost, IconNetwork, IconSearch } from "../components/Icons";
import { SeverityPill, SeverityStripe } from "../components/Severity";
import { useLive } from "../hooks";

const SPEEDS = ["60", "600", "3600", "7200"];
const TIER: Record<number, string> = { 0: "workstation", 1: "server", 2: "critical server", 3: "domain controller" };

function Tile({ label, value, hint, children }: { label: string; value: ReactNode; hint?: ReactNode; children?: ReactNode }) {
  return (
    <div className="soc-card" style={{ padding: "12px 14px", height: "100%" }}>
      <Text size="xs" c="dimmed" fw={600}>{label}</Text>
      <div className="soc-kpi-value" style={{ marginTop: 4 }}>{value}</div>
      {hint && <Text size="xs" c="dimmed" mt={2}>{hint}</Text>}
      {children}
    </div>
  );
}

/** Stream minutes or hours between two ISO times, as a short "age". */
function age(from: string, to: string): string {
  const m = Math.max(0, Math.round((Date.parse(to) - Date.parse(from)) / 60000));
  if (m < 60) return `${m} min`;
  if (m < 48 * 60) return `${Math.floor(m / 60)} h ${m % 60} min`;
  return `${Math.floor(m / 1440)} d`;
}

interface Row {
  key: string;
  items: QueueItem[];
  top: QueueItem;
}

/** A group's title and what varies in it: network groups drop the external endpoint, host groups the host. */
function groupLabel(r: Row): { title: string; varies: string } {
  const t = r.top.title;
  if (r.top.kind === "network") {
    const parts = r.items.map((i) => i.title.match(/^(.*\[sid \d+\])\s+(\S+)\s+->\s+(\S+)$/));
    const m = parts[0];
    if (!m || parts.some((p) => !p)) return { title: t, varies: "" };
    const ip = (e: string) => e.replace(/:\d+$/, ""); // compare addresses, not ports
    const srcs = new Set(parts.map((p) => ip(p![2]))).size;
    const dsts = new Set(parts.map((p) => ip(p![3]))).size;
    const varies = srcs === 1 ? `${ip(m[2])} → ${dsts} destinations` : dsts === 1 ? `${srcs} sources → ${ip(m[3])}` : `${srcs} sources, ${dsts} destinations`;
    return { title: m[1], varies };
  }
  const hosts = new Set(r.items.map((i) => i.host)).size;
  return hosts > 1 ? { title: t.replace(/ on \S+$/, ""), varies: `on ${hosts} hosts` } : { title: t, varies: "" };
}

function KindIcon({ kind }: { kind?: string }) {
  return (
    <Tooltip label={kind === "network" ? "network alert (IDS)" : "host alert (Windows events)"}>
      <span style={{ color: "var(--soc-muted)", display: "inline-flex" }}>
        {kind === "network" ? <IconNetwork size={15} /> : <IconHost size={15} />}
      </span>
    </Tooltip>
  );
}

function QueueRow({ item, now, child, onOpen }: { item: QueueItem; now: string; child?: boolean; onOpen: () => void }) {
  return (
    <div className="soc-queue-row" data-child={child || undefined} onClick={onOpen} role="button" tabIndex={0}
      onKeyDown={(e) => e.key === "Enter" && onOpen()}>
      <SeverityStripe priority={item.priority} />
      <SeverityPill priority={item.priority} reasons={item.priority_reasons} />
      <div style={{ minWidth: 0 }}>
        <Group gap={6} wrap="nowrap">
          <KindIcon kind={item.kind} />
          <Text size="sm" fw={500} truncate="end">{item.title}</Text>
        </Group>
        <Group gap={6} mt={4}>
          {(item.techniques ?? []).map((t) => <span key={t} className="soc-chip">{t}</span>)}
          {item.alert_count > 1 && <span className="soc-chip">{item.alert_count} alerts</span>}
        </Group>
      </div>
      <div>
        <Text size="sm">{item.host ?? "—"}</Text>
        {item.host_tier != null && <Text size="xs" c="dimmed">{TIER[item.host_tier] ?? `tier ${item.host_tier}`}</Text>}
      </div>
      <div>
        <Text size="xs" ff="monospace">{item.opened.slice(5, 16).replace("T", " ")}</Text>
        <Text size="xs" c="dimmed">{age(item.opened, now)} ago</Text>
      </div>
      <Text size="xs" fw={700} tt="uppercase" c={item.review_status === "claimed" ? "gray.4" : item.review_status === "needs_info" ? "yellow" : "orange"}
        style={{ whiteSpace: "nowrap" }}>
        {item.review_status.replace("_", " ")}
        {item.claimed_by ? <Text span size="xs" c="dimmed" tt="none" fw={400}>{` · ${item.claimed_by}`}</Text> : null}
      </Text>
    </div>
  );
}

function GroupRow({ row, now, onOpen }: { row: Row; now: string; onOpen: (id: string) => void }) {
  const [open, setOpen] = useState(false);
  const t = row.top;
  const hostCount = new Set(row.items.map((i) => i.host)).size;
  const label = groupLabel(row);
  const open_ = row.items.filter((i) => i.review_status === "open").length;
  return (
    <>
      <div className="soc-queue-row" onClick={() => setOpen(!open)} role="button" tabIndex={0} aria-expanded={open}
        onKeyDown={(e) => e.key === "Enter" && setOpen(!open)}>
        <SeverityStripe priority={t.priority} />
        <SeverityPill priority={t.priority} reasons={t.priority_reasons} />
        <div style={{ minWidth: 0 }}>
          <Group gap={6} wrap="nowrap">
            <IconChevron size={15} open={open} />
            <KindIcon kind={t.kind} />
            <Text size="sm" fw={500} truncate="end">{label.title}</Text>
          </Group>
          <Group gap={6} mt={4}>
            <span className="soc-chip" data-tone="accent">{row.items.length} similar cases</span>
            {label.varies && <span className="soc-chip">{label.varies}</span>}
            {(t.techniques ?? []).map((x) => <span key={x} className="soc-chip">{x}</span>)}
          </Group>
        </div>
        <div>
          <Text size="sm">{hostCount > 1 ? `${hostCount} hosts` : t.host}</Text>
          {hostCount === 1 && t.host_tier != null && <Text size="xs" c="dimmed">{TIER[t.host_tier] ?? `tier ${t.host_tier}`}</Text>}
        </div>
        <div>
          <Text size="xs" ff="monospace">{t.opened.slice(5, 16).replace("T", " ")}</Text>
          <Text size="xs" c="dimmed">{age(t.opened, now)} ago</Text>
        </div>
        <Text size="xs" fw={700} tt="uppercase" c="orange" style={{ whiteSpace: "nowrap" }}>
          {open_} open{row.items.length > open_ ? <Text span size="xs" c="dimmed" tt="none" fw={400}>{` · ${row.items.length - open_} other`}</Text> : null}
        </Text>
      </div>
      {open && row.items.map((i) => <QueueRow key={i.case_id} item={i} now={now} child onOpen={() => onOpen(i.case_id)} />)}
    </>
  );
}

export default function Live() {
  const { session } = useAuth();
  const qc = useQueryClient();
  const navigate = useNavigate();
  const status = useLive();
  const queue = useQuery({ queryKey: ["queue"], queryFn: () => api<QueueItem[]>("/queue?limit=500"), refetchInterval: 3000 });
  const activity = useQuery({ queryKey: ["activity"], queryFn: () => api<{ hours: HourBucket[] }>("/live/activity?hours=24"), refetchInterval: 5000 });
  const control = useMutation({
    mutationFn: (op: { path: string; body?: unknown }) => api<LiveStatus>(op.path, { method: "POST", body: op.body }),
    onSuccess: (s) => qc.setQueryData(["live"], s),
  });
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("all");
  const [kind, setKind] = useState("all");
  const [grouped, setGrouped] = useState(true);

  const s = status.data;
  const lead = canControl(session?.role);
  const follow = s?.mode === "follow";
  const items = useMemo(() => queue.data ?? [], [queue.data]);
  const hours = activity.data?.hours ?? [];
  const now = s?.stream_time ?? new Date().toISOString();

  const rows = useMemo(() => {
    const q = search.trim().toLowerCase();
    const filtered = items.filter((i) =>
      (statusFilter === "all" || i.review_status === statusFilter) &&
      (kind === "all" || i.kind === kind) &&
      (!q || i.title.toLowerCase().includes(q) || (i.host ?? "").toLowerCase().includes(q)));
    const by = new Map<string, QueueItem[]>();
    for (const i of filtered) {
      const k = grouped ? i.group ?? i.case_id : i.case_id;
      by.set(k, [...(by.get(k) ?? []), i]);
    }
    return [...by.entries()]
      .map(([key, its]) => ({ key, items: its, top: its[0] }))
      .sort((a, b) => b.top.priority - a.top.priority || a.top.opened.localeCompare(b.top.opened));
  }, [items, search, statusFilter, kind, grouped]);

  const hosts = useMemo(() => {
    const m = new Map<string, { host: string; n: number; max: number; tier: number | null | undefined }>();
    for (const i of items) {
      const h = i.host ?? "—";
      const e = m.get(h) ?? { host: h, n: 0, max: 0, tier: i.host_tier };
      e.n += 1;
      e.max = Math.max(e.max, i.priority);
      m.set(h, e);
    }
    return [...m.values()].sort((a, b) => b.max - a.max || b.n - a.n).slice(0, 8);
  }, [items]);

  const counts: Record<string, number> = { open: 0, claimed: 0, needs_info: 0 };
  for (const i of items) counts[i.review_status] = (counts[i.review_status] ?? 0) + 1;

  return (
    <Stack gap="lg">
      <Group justify="space-between" align="flex-end">
        <div>
          <Title order={2}>SOC overview</Title>
          <Text size="sm" c="dimmed" maw={760}>
            {follow ? "Following live log files as they grow."
              : s?.dataset && s.dataset !== "DEDALE" ? `Replaying the ${s.dataset} dataset.` : "A day in the SOC during the DEDALE attack."} Activity the
            Knowledge Store has learned as routine stays silent; new patterns become cases, triaged by the pipeline and
            ordered for review.
          </Text>
        </div>
        {lead && s && (
          <Group gap="sm">
            {s.state === "running" ? (
              <Button color="yellow" variant="light" onClick={() => control.mutate({ path: "/live/pause" })}>Pause</Button>
            ) : (
              <Button color="green" onClick={() => control.mutate({ path: "/live/start" })} disabled={s.state === "finished"}>
                {s.state === "finished" ? "Finished" : "Start"}
              </Button>
            )}
            {!follow && (
              <SegmentedControl size="xs" value={String(s.speed)} data={SPEEDS.map((v) => ({ value: v, label: `×${v}` }))}
                onChange={(v) => control.mutate({ path: "/live/speed", body: { speed: Number(v) } })} />
            )}
          </Group>
        )}
      </Group>
      {control.error && <Alert color="red">{String(control.error)}</Alert>}

      {s && (
        <Grid gap="md">
          <Grid.Col span={{ base: 6, md: 4, lg: 2.4 }}>
            <Tile label="Stream time" value={new Date(s.stream_time).toISOString().slice(11, 16)}
              hint={`${new Date(s.stream_time).toLocaleDateString("en-GB", { weekday: "short", day: "numeric", month: "short", timeZone: "UTC" })} UTC · ${s.state}`} />
          </Grid.Col>
          <Grid.Col span={{ base: 6, md: 4, lg: 2.4 }}>
            <Tile label="Events processed" value={s.events_processed.toLocaleString("en-US")}
              hint={`incl. ${((s.counts.events_training ?? 0) / 1e6).toFixed(1)} M in the training weeks`} />
          </Grid.Col>
          <Grid.Col span={{ base: 6, md: 4, lg: 2.4 }}>
            <Tile label="Alerts (new patterns)" value={(s.alerts_test ?? s.counts.alerts ?? 0).toLocaleString("en-US")}
              hint="after the training weeks" />
          </Grid.Col>
          <Grid.Col span={{ base: 6, md: 6, lg: 2.4 }}>
            <Tile label="Cases" value={(s.counts.cases_test ?? 0).toLocaleString("en-US")} hint="opened per hour, last 24 h">
              <Sparkline label="cases opened" values={hours.map((h) => h.closed_automatically + h.sent_to_analyst)} />
            </Tile>
          </Grid.Col>
          <Grid.Col span={{ base: 12, md: 6, lg: 2.4 }}>
            <Tile label="Waiting for an analyst" value={items.length}
              hint={`${counts.open} open · ${counts.claimed} claimed · ${counts.needs_info} need info`}>
              <Sparkline label="sent to an analyst" color="#d95926" values={hours.map((h) => h.sent_to_analyst)} />
            </Tile>
          </Grid.Col>
        </Grid>
      )}

      <Grid gap="md">
        <Grid.Col span={{ base: 12, lg: 8 }}>
          <div className="soc-card" style={{ padding: 16, height: "100%" }}>
            <Text className="soc-card-title">Triage, last 24 hours of stream time</Text>
            <Text size="xs" c="dimmed" mb={4}>Cases opened per hour: closed by the pipeline, or sent to an analyst</Text>
            <ActivityChart hours={hours} />
          </div>
        </Grid.Col>
        <Grid.Col span={{ base: 12, lg: 4 }}>
          <div className="soc-card" style={{ padding: 16, height: "100%" }}>
            <Text className="soc-card-title" mb="xs">Hosts with cases waiting</Text>
            <Stack gap={6}>
              {hosts.map((h) => (
                <Group key={h.host} justify="space-between" wrap="nowrap" style={{ cursor: "pointer" }}
                  onClick={() => setSearch(h.host === "—" ? "" : h.host)}>
                  <Group gap={8} wrap="nowrap" style={{ minWidth: 0 }}>
                    <SeverityStripe priority={h.max} />
                    <div style={{ minWidth: 0 }}>
                      <Text size="sm" fw={500} truncate="end">{h.host}</Text>
                      <Text size="xs" c="dimmed">{h.tier != null ? TIER[h.tier] ?? `tier ${h.tier}` : "—"}</Text>
                    </div>
                  </Group>
                  <Group gap={8} wrap="nowrap">
                    <Text size="xs" c="dimmed">{h.n} {h.n === 1 ? "case" : "cases"}</Text>
                    <SeverityPill priority={h.max} />
                    {h.host !== "—" && (
                      <Anchor component={Link} to={`/hosts/${encodeURIComponent(h.host)}`} size="xs" onClick={(e) => e.stopPropagation()}>
                        timeline
                      </Anchor>
                    )}
                  </Group>
                </Group>
              ))}
              {!hosts.length && <Text size="sm" c="dimmed">Nothing waiting.</Text>}
            </Stack>
            <Text size="xs" c="dimmed" mt="sm">Click a host to filter the queue, or open its timeline.</Text>
          </div>
        </Grid.Col>
      </Grid>

      <div className="soc-card" style={{ overflow: "hidden" }}>
        <Group justify="space-between" p="md" pb="sm" wrap="wrap" gap="sm">
          <div>
            <Text className="soc-card-title">Review queue</Text>
            <Text size="xs" c="dimmed">Highest priority first; hover a score for its reasons</Text>
          </div>
          <Group gap="sm" wrap="wrap">
            <TextInput size="xs" placeholder="Search pattern or host" leftSection={<IconSearch size={14} />}
              value={search} onChange={(e) => setSearch(e.currentTarget.value)} w={220} />
            <SegmentedControl size="xs" value={statusFilter} onChange={setStatusFilter}
              data={[{ value: "all", label: "All" }, { value: "open", label: "Open" }, { value: "claimed", label: "Claimed" }, { value: "needs_info", label: "Needs info" }]} />
            <SegmentedControl size="xs" value={kind} onChange={setKind}
              data={[{ value: "all", label: "All" }, { value: "host", label: "Host" }, { value: "network", label: "Network" }]} />
            <Switch size="xs" label="Group similar" checked={grouped} onChange={(e) => setGrouped(e.currentTarget.checked)} />
          </Group>
        </Group>
        <div className="soc-queue-head">
          <span />
          <span>Priority</span>
          <span>Case</span>
          <span>Host</span>
          <span>Opened (stream)</span>
          <span>Status</span>
        </div>
        {rows.map((r) =>
          r.items.length > 1 ? (
            <GroupRow key={r.key} row={r} now={now} onOpen={(id) => navigate(`/cases/${id}`)} />
          ) : (
            <QueueRow key={r.key} item={r.top} now={now} onOpen={() => navigate(`/cases/${r.top.case_id}`)} />
          ),
        )}
        {!rows.length && (
          <Text c="dimmed" ta="center" py="xl">{items.length ? "No case matches the filters." : "Nothing waiting for review."}</Text>
        )}
      </div>
    </Stack>
  );
}
