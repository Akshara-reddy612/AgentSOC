import { Alert, Badge, Button, Card, Group, Paper, SegmentedControl, SimpleGrid, Stack, Table, Text, Title, Tooltip } from "@mantine/core";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { api, type LiveStatus, type QueueItem } from "../api";
import { canControl, useAuth } from "../auth";
import { STATUS_COLOR, when } from "../format";

const SPEEDS = ["60", "600", "3600", "7200"];

function Stat({ label, value, hint }: { label: string; value: string | number; hint?: string }) {
  return (
    <Paper withBorder p="sm">
      <Text size="xs" c="dimmed" tt="uppercase">
        {label}
      </Text>
      <Text size="xl" fw={600}>
        {value}
      </Text>
      {hint && (
        <Text size="xs" c="dimmed">
          {hint}
        </Text>
      )}
    </Paper>
  );
}

export default function Live() {
  const { session } = useAuth();
  const qc = useQueryClient();
  const navigate = useNavigate();
  const status = useQuery({ queryKey: ["live"], queryFn: () => api<LiveStatus>("/live/status"), refetchInterval: 2000 });
  const queue = useQuery({ queryKey: ["queue"], queryFn: () => api<QueueItem[]>("/queue?limit=100"), refetchInterval: 3000 });
  const control = useMutation({
    mutationFn: (op: { path: string; body?: unknown }) => api<LiveStatus>(op.path, { method: "POST", body: op.body }),
    onSuccess: (s) => qc.setQueryData(["live"], s),
  });
  const s = status.data;
  const lead = canControl(session?.role);

  return (
    <Stack>
      <Group justify="space-between">
        <div>
          <Title order={3}>Live</Title>
          <Text size="sm" c="dimmed">
            A day in the SOC during the DEDALE attack. Activity the Knowledge Store has learned as routine stays silent; new
            patterns become cases, triaged by the pipeline and ordered for review.
          </Text>
        </div>
        {lead && s && (
          <Group>
            {s.state === "running" ? (
              <Button color="yellow" onClick={() => control.mutate({ path: "/live/pause" })}>
                Pause
              </Button>
            ) : (
              <Button color="green" onClick={() => control.mutate({ path: "/live/start" })} disabled={s.state === "finished"}>
                {s.state === "finished" ? "Finished" : "Start"}
              </Button>
            )}
            <SegmentedControl
              value={String(s.speed)}
              data={SPEEDS.map((v) => ({ value: v, label: `×${v}` }))}
              onChange={(v) => control.mutate({ path: "/live/speed", body: { speed: Number(v) } })}
            />
          </Group>
        )}
      </Group>
      {control.error && <Alert color="red">{String(control.error)}</Alert>}

      {s && (
        <SimpleGrid cols={{ base: 2, md: 5 }}>
          <Stat label="Stream time" value={when(s.stream_time).slice(0, 16)} hint={s.state} />
          <Stat label="Events processed" value={s.events_processed.toLocaleString()} hint={`${(s.counts.events_training ?? 0).toLocaleString()} in training`} />
          <Stat label="Alerts (new patterns)" value={s.counts.alerts ?? 0} />
          <Stat label="Cases" value={s.counts.cases_test ?? 0} />
          <Stat label="Waiting for an analyst" value={queue.data?.length ?? "…"} />
        </SimpleGrid>
      )}

      <Card withBorder>
        <Group justify="space-between" mb="xs">
          <Title order={5}>Review queue</Title>
          <Text size="xs" c="dimmed">
            Highest priority first; hover the score for its reasons
          </Text>
        </Group>
        <Table highlightOnHover verticalSpacing="xs">
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Priority</Table.Th>
              <Table.Th>Pattern</Table.Th>
              <Table.Th>Host</Table.Th>
              <Table.Th>Opened (stream time)</Table.Th>
              <Table.Th>Alerts</Table.Th>
              <Table.Th>Status</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {(queue.data ?? []).map((q) => (
              <Table.Tr key={q.case_id} style={{ cursor: "pointer" }} onClick={() => navigate(`/cases/${q.case_id}`)}>
                <Table.Td>
                  <Tooltip
                    multiline
                    w={420}
                    label={q.priority_reasons.length ? q.priority_reasons.join("\n") : "no priority factors"}
                    style={{ whiteSpace: "pre-line" }}
                  >
                    <Badge color={q.priority >= 60 ? "red" : q.priority >= 30 ? "orange" : "gray"} variant="filled">
                      {q.priority}
                    </Badge>
                  </Tooltip>
                </Table.Td>
                <Table.Td>
                  <Text size="sm">{q.title}</Text>
                </Table.Td>
                <Table.Td>{q.host}</Table.Td>
                <Table.Td>
                  <Text size="xs" ff="monospace">
                    {when(q.opened).slice(0, 16)}
                  </Text>
                </Table.Td>
                <Table.Td>{q.alert_count}</Table.Td>
                <Table.Td>
                  <Badge color={STATUS_COLOR[q.review_status] ?? "gray"} variant="light">
                    {q.review_status}
                    {q.claimed_by ? ` · ${q.claimed_by}` : ""}
                  </Badge>
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
        {queue.data?.length === 0 && (
          <Text c="dimmed" ta="center" py="lg">
            Nothing waiting for review.
          </Text>
        )}
      </Card>
    </Stack>
  );
}
