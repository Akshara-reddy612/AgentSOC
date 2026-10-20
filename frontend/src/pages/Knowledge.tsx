import { Grid, Group, Loader, Select, SimpleGrid, Stack, Table, Text, Title } from "@mantine/core";
import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { api, type GraphData, type KnowledgeSummary, type Pattern, type Retraction } from "../api";
import Graph from "../components/Graph";
import { PROVENANCE_COLOR, PROVENANCE_LABEL, when } from "../format";

const PROVENANCES = ["training", "closed_benign", "analyst", "ungated", "telemetry", "config"];

function Tile({ label, value, hint, tone }: { label: string; value: string | number; hint?: string; tone?: string }) {
  return (
    <div className="soc-card" style={{ padding: "12px 14px" }}>
      <Text size="xs" c="dimmed" fw={600}>{label}</Text>
      <div className="soc-kpi-value" style={{ marginTop: 4, color: tone }}>{value}</div>
      {hint && <Text size="xs" c="dimmed" mt={2}>{hint}</Text>}
    </div>
  );
}

function Swatch({ p }: { p: string }) {
  return <span style={{ display: "inline-block", width: 10, height: 10, borderRadius: 2, background: PROVENANCE_COLOR[p], flexShrink: 0 }} />;
}

export function ProvenanceLegend({ only }: { only?: string[] }) {
  return (
    <Group gap="md">
      {(only ?? Object.keys(PROVENANCE_COLOR)).map((k) => (
        <Group key={k} gap={6} wrap="nowrap">
          <Swatch p={k} />
          <Text size="xs" c="dimmed">{PROVENANCE_LABEL[k] ?? k}</Text>
        </Group>
      ))}
    </Group>
  );
}

const short = (node: string) => node.split(":").slice(1).join(":").split("\\").pop();

export default function Knowledge() {
  const hostnames = useQuery({ queryKey: ["ks-hostnames"], queryFn: () => api<string[]>("/knowledge/hostnames"), staleTime: 60_000 });
  const [picked, setHost] = useState<string | null>(null);
  const host = picked ?? (hostnames.data?.includes("CLIENT2") ? "CLIENT2" : hostnames.data?.[0] ?? "CLIENT2");
  const summary = useQuery({ queryKey: ["ks-summary"], queryFn: () => api<KnowledgeSummary>("/knowledge/summary"), refetchInterval: 5000 });
  const graph = useQuery({ queryKey: ["ks-graph", host], queryFn: () => api<GraphData>(`/knowledge/graph/${encodeURIComponent(host)}?limit=80`) });
  const patterns = useQuery({ queryKey: ["ks-host", host], queryFn: () => api<Pattern[]>(`/knowledge/hosts/${encodeURIComponent(host)}?limit=300`), refetchInterval: 5000 });
  const retractions = useQuery({ queryKey: ["ks-retractions"], queryFn: () => api<Retraction[]>("/knowledge/retractions?limit=50"), refetchInterval: 5000 });
  const s = summary.data;
  const totalEdges = s ? Object.values(s.edges).flatMap((e) => Object.values(e)).reduce((a, b) => a + b, 0) : 0;
  const byProv: Record<string, number> = {};
  if (s) for (const t of Object.values(s.edges)) for (const [p, n] of Object.entries(t)) byProv[p] = (byProv[p] ?? 0) + n;

  return (
    <Stack gap="lg">
      <div>
        <Title order={2}>Knowledge Store</Title>
        <Text size="sm" c="dimmed" maw={820}>
          What the SOC has learned as routine, and from where: the benign training weeks, cases closed benign behind the
          learning gate, or analysts. Learned activity stops raising alerts. Free text is never stored; script text only as a
          fingerprint. Every write is in the audit log.
        </Text>
      </div>

      {s && (
        <SimpleGrid cols={{ base: 2, md: 4 }}>
          <Tile label="Nodes" value={Object.values(s.nodes).reduce((a, b) => a + b, 0).toLocaleString("en-US")} hint="hosts, programs, accounts, addresses" />
          <Tile label="Learned patterns" value={totalEdges.toLocaleString("en-US")} hint="activity that no longer alerts" />
          <Tile label="Audit log entries" value={s.log_entries.toLocaleString("en-US")} hint="append-only" />
          <Tile label="Retracted (unlearned)" value={s.retractions} tone={s.retractions ? "var(--soc-critical)" : undefined}
            hint="after a confirmed compromise" />
        </SimpleGrid>
      )}

      {s && (
        <div className="soc-card" style={{ padding: 16 }}>
          <Group justify="space-between" mb="sm" wrap="wrap">
            <div>
              <Text className="soc-card-title">Where the learning came from</Text>
              <Text size="xs" c="dimmed">Patterns by provenance; the learning gate decides what may be learned after training</Text>
            </div>
            <ProvenanceLegend only={PROVENANCES} />
          </Group>
          <div style={{ display: "flex", height: 14, borderRadius: 3, overflow: "hidden", gap: 2, background: "var(--soc-surface-2)" }}
            role="img" aria-label="Share of learned patterns by provenance">
            {PROVENANCES.filter((p) => byProv[p]).map((p) => (
              <div key={p} title={`${PROVENANCE_LABEL[p] ?? p}: ${byProv[p].toLocaleString("en-US")}`}
                style={{ flex: byProv[p], background: PROVENANCE_COLOR[p], minWidth: 3 }} />
            ))}
          </div>
          <Table.ScrollContainer minWidth={760} type="native" mt="sm">
          <Table fz="xs" verticalSpacing={4} style={{ fontVariantNumeric: "tabular-nums" }}>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Pattern type</Table.Th>
                {PROVENANCES.map((p) => <Table.Th key={p} ta="right">{PROVENANCE_LABEL[p] ?? p}</Table.Th>)}
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {Object.entries(s.edges).map(([t, row]) => (
                <Table.Tr key={t}>
                  <Table.Td>{t}</Table.Td>
                  {PROVENANCES.map((p) => <Table.Td key={p} ta="right">{row[p] ? row[p].toLocaleString("en-US") : "—"}</Table.Td>)}
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
          </Table.ScrollContainer>
        </div>
      )}

      <Grid gap="lg">
        <Grid.Col span={{ base: 12, lg: 7 }}>
          <div className="soc-card" style={{ padding: 16 }}>
            <Group justify="space-between" mb="xs">
              <div>
                <Text className="soc-card-title">Around a host</Text>
                <Text size="xs" c="dimmed">Latest 80 patterns; edges coloured by provenance. Hover a node for its name, scroll to zoom.</Text>
              </div>
              <Select size="xs" w={180} data={hostnames.data ?? [host]} value={host} onChange={(v) => v && setHost(v)} searchable aria-label="Host" />
            </Group>
            {graph.isLoading ? <Loader /> : graph.data && graph.data.edges.length ? <Graph data={graph.data} /> : <Text c="dimmed" size="sm">Nothing learned on this host.</Text>}
            <Group justify="space-between" mt="xs" wrap="wrap" gap="xs">
              <ProvenanceLegend only={["training", "closed_benign", "analyst", "ungated"]} />
              <Text size="xs" c="dimmed">■ host · ◆ program · ● account · ▲ script</Text>
            </Group>
          </div>
        </Grid.Col>
        <Grid.Col span={{ base: 12, lg: 5 }}>
          <div className="soc-card" style={{ padding: 16, maxHeight: 590, overflow: "auto" }}>
            <Text className="soc-card-title" mb="xs">Latest patterns learned on {host}</Text>
            <Table fz="xs" verticalSpacing={3}>
              <Table.Tbody>
                {(patterns.data ?? []).slice(0, 120).map((p, i) => (
                  <Table.Tr key={i}>
                    <Table.Td style={{ whiteSpace: "nowrap" }}>
                      <Group gap={6} wrap="nowrap"><Swatch p={p.learned_from} /><Text size="xs">{PROVENANCE_LABEL[p.learned_from] ?? p.learned_from}</Text></Group>
                    </Table.Td>
                    <Table.Td c="dimmed">{p.type}</Table.Td>
                    <Table.Td><Text size="xs" ff="monospace" style={{ overflowWrap: "anywhere" }}>{short(p.src)} → {short(p.dst)}</Text></Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
            {patterns.data && !patterns.data.length && <Text size="sm" c="dimmed">Nothing learned on this host.</Text>}
          </div>
        </Grid.Col>
      </Grid>

      <div className="soc-card" style={{ padding: 16 }}>
        <Text className="soc-card-title">Retracted after a confirmed compromise</Text>
        <Text size="xs" c="dimmed" mb="sm">
          Confirming a host compromised retracts what was learned on it in the 7 days before: that activity alerts again.
        </Text>
        {retractions.data?.length ? (
          <Table fz="xs" verticalSpacing={3}>
            <Table.Thead>
              <Table.Tr><Table.Th>When (stream)</Table.Th><Table.Th>By</Table.Th><Table.Th>Pattern</Table.Th><Table.Th>Why</Table.Th></Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {retractions.data.map((r) => (
                <Table.Tr key={r.seq}>
                  <Table.Td style={{ whiteSpace: "nowrap" }}>{when(r.at).slice(0, 16)}</Table.Td>
                  <Table.Td>{r.writer}</Table.Td>
                  <Table.Td><Text size="xs" ff="monospace" style={{ overflowWrap: "anywhere" }}>{short(r.src)} → {short(r.dst)}</Text></Table.Td>
                  <Table.Td>{r.reason}</Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        ) : (
          <Text size="sm" c="dimmed">Nothing retracted yet.</Text>
        )}
      </div>
    </Stack>
  );
}
