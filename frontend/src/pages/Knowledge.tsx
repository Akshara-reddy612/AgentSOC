import { Card, Grid, Group, Loader, Select, SimpleGrid, Stack, Table, Text, Title } from "@mantine/core";
import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { api, type GraphData, type KnowledgeSummary, type Pattern, type Retraction } from "../api";
import Graph from "../components/Graph";
import { PROVENANCE_COLOR, when } from "../format";

const HOSTS = [...Array.from({ length: 30 }, (_, i) => `CLIENT${i + 1}`), "internalserver", "logserver", "dmzserver", "webserver", "vpnserver"];

function Legend() {
  return (
    <Group gap="sm">
      {Object.entries(PROVENANCE_COLOR).map(([k, c]) => (
        <Group key={k} gap={4}>
          <div style={{ width: 12, height: 3, background: c }} />
          <Text size="xs" c="dimmed">{k}</Text>
        </Group>
      ))}
    </Group>
  );
}

export default function Knowledge() {
  const [host, setHost] = useState<string>("CLIENT2");
  const summary = useQuery({ queryKey: ["ks-summary"], queryFn: () => api<KnowledgeSummary>("/knowledge/summary"), refetchInterval: 5000 });
  const graph = useQuery({ queryKey: ["ks-graph", host], queryFn: () => api<GraphData>(`/knowledge/graph/${encodeURIComponent(host)}?limit=80`) });
  const patterns = useQuery({ queryKey: ["ks-host", host], queryFn: () => api<Pattern[]>(`/knowledge/hosts/${encodeURIComponent(host)}?limit=300`), refetchInterval: 5000 });
  const retractions = useQuery({ queryKey: ["ks-retractions"], queryFn: () => api<Retraction[]>("/knowledge/retractions?limit=50"), refetchInterval: 5000 });
  const s = summary.data;

  return (
    <Stack>
      <div>
        <Title order={3}>Knowledge Store</Title>
        <Text size="sm" c="dimmed">
          What the SOC has learned as routine, and from where: the benign training weeks, cases closed benign behind the
          learning gate, or analysts. Free text is never stored; script text only as a fingerprint.
        </Text>
      </div>

      {s && (
        <SimpleGrid cols={{ base: 2, md: 4 }}>
          <Card withBorder p="sm">
            <Text size="xs" c="dimmed">Nodes</Text>
            <Text size="xl" fw={600}>{Object.values(s.nodes).reduce((a, b) => a + b, 0).toLocaleString()}</Text>
          </Card>
          <Card withBorder p="sm">
            <Text size="xs" c="dimmed">Learned patterns (edges)</Text>
            <Text size="xl" fw={600}>
              {Object.values(s.edges).flatMap((e) => Object.values(e)).reduce((a, b) => a + b, 0).toLocaleString()}
            </Text>
          </Card>
          <Card withBorder p="sm">
            <Text size="xs" c="dimmed">Audit log entries</Text>
            <Text size="xl" fw={600}>{s.log_entries.toLocaleString()}</Text>
          </Card>
          <Card withBorder p="sm">
            <Text size="xs" c="dimmed">Retracted (unlearned)</Text>
            <Text size="xl" fw={600} c={s.retractions ? "red" : undefined}>{s.retractions}</Text>
          </Card>
        </SimpleGrid>
      )}

      {s && (
        <Card withBorder>
          <Title order={6} mb="xs">Patterns by type and provenance</Title>
          <Table fz="xs" verticalSpacing={2}>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Type</Table.Th>
                {["config", "telemetry", "training", "closed_benign", "analyst", "ungated"].map((p) => <Table.Th key={p}>{p}</Table.Th>)}
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {Object.entries(s.edges).map(([t, byProv]) => (
                <Table.Tr key={t}>
                  <Table.Td>{t}</Table.Td>
                  {["config", "telemetry", "training", "closed_benign", "analyst", "ungated"].map((p) => <Table.Td key={p}>{byProv[p] ?? ""}</Table.Td>)}
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </Card>
      )}

      <Grid>
        <Grid.Col span={{ base: 12, lg: 7 }}>
          <Card withBorder>
            <Group justify="space-between" mb="xs">
              <div>
                <Title order={6}>Around a host</Title>
                <Text size="xs" c="dimmed">latest 80 patterns; hover a node for its name, scroll to zoom</Text>
              </div>
              <Select size="xs" w={180} data={HOSTS} value={host} onChange={(v) => v && setHost(v)} searchable />
            </Group>
            {graph.isLoading ? <Loader /> : graph.data && graph.data.edges.length ? <Graph data={graph.data} /> : <Text c="dimmed" size="sm">Nothing learned on this host.</Text>}
            <Group mt="xs"><Legend /></Group>
          </Card>
        </Grid.Col>
        <Grid.Col span={{ base: 12, lg: 5 }}>
          <Card withBorder style={{ maxHeight: 560, overflow: "auto" }}>
            <Title order={6} mb="xs">Latest patterns learned on {host}</Title>
            <Table fz="xs" verticalSpacing={2}>
              <Table.Tbody>
                {(patterns.data ?? []).slice(0, 120).map((p, i) => (
                  <Table.Tr key={i}>
                    <Table.Td>
                      <Group gap={6} wrap="nowrap">
                        <div style={{ width: 8, height: 8, borderRadius: 4, background: PROVENANCE_COLOR[p.learned_from], flexShrink: 0 }} />
                        <Text size="xs">{p.learned_from}</Text>
                      </Group>
                    </Table.Td>
                    <Table.Td>{p.type}</Table.Td>
                    <Table.Td>
                      <Text size="xs" ff="monospace" style={{ wordBreak: "break-all" }}>
                        {p.src.split(":").slice(1).join(":").split("\\").pop()} → {p.dst.split(":").slice(1).join(":").split("\\").pop()}
                      </Text>
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </Card>
        </Grid.Col>
      </Grid>

      <Card withBorder>
        <Title order={6} mb="xs">Retracted after a confirmed compromise (unlearning)</Title>
        {retractions.data?.length ? (
          <Table fz="xs">
            <Table.Thead>
              <Table.Tr><Table.Th>When</Table.Th><Table.Th>By</Table.Th><Table.Th>Pattern</Table.Th><Table.Th>Why</Table.Th></Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {retractions.data.map((r) => (
                <Table.Tr key={r.seq}>
                  <Table.Td>{when(r.at).slice(0, 16)}</Table.Td>
                  <Table.Td>{r.writer}</Table.Td>
                  <Table.Td><Text size="xs" ff="monospace">{r.src} → {r.dst}</Text></Table.Td>
                  <Table.Td>{r.reason}</Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        ) : (
          <Text size="sm" c="dimmed">Nothing retracted yet. Confirming a host compromised retracts what was learned on it in the 7 days before.</Text>
        )}
      </Card>
    </Stack>
  );
}
