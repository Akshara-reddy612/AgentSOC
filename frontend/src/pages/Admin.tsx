import { Alert, Badge, Button, Card, Group, PasswordInput, Select, Stack, Table, Text, TextInput, Title } from "@mantine/core";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { api, type Role, type User } from "../api";
import { useAuth } from "../auth";
import { when } from "../format";

export default function Admin() {
  const { session } = useAuth();
  const qc = useQueryClient();
  const users = useQuery({ queryKey: ["users"], queryFn: () => api<User[]>("/admin/users") });
  const [form, setForm] = useState<{ username: string; password: string; role: Role }>({ username: "", password: "", role: "analyst" });
  const create = useMutation({
    mutationFn: () => api("/admin/users", { method: "POST", body: form }),
    onSuccess: () => {
      setForm({ username: "", password: "", role: "analyst" });
      void qc.invalidateQueries({ queryKey: ["users"] });
    },
  });
  const disable = useMutation({
    mutationFn: (u: string) => api(`/admin/users/${encodeURIComponent(u)}/disable`, { method: "POST" }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["users"] }),
  });

  function submit(e: FormEvent) {
    e.preventDefault();
    create.mutate();
  }

  return (
    <Stack>
      <div>
        <Title order={3}>Accounts</Title>
        <Text size="sm" c="dimmed">
          Analysts review and approve; leads also control the replay; admins also manage accounts. Containment of a critical
          host needs two different analysts.
        </Text>
      </div>
      <Card withBorder>
        <Table>
          <Table.Thead>
            <Table.Tr><Table.Th>User</Table.Th><Table.Th>Role</Table.Th><Table.Th>Created</Table.Th><Table.Th /></Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {(users.data ?? []).map((u) => (
              <Table.Tr key={u.username}>
                <Table.Td>{u.username}</Table.Td>
                <Table.Td><Badge variant="light">{u.role}</Badge></Table.Td>
                <Table.Td><Text size="xs">{when(u.created).slice(0, 16)}</Text></Table.Td>
                <Table.Td>
                  {u.disabled ? (
                    <Badge color="gray">disabled</Badge>
                  ) : u.username !== session?.username ? (
                    <Button size="xs" variant="subtle" color="red" onClick={() => disable.mutate(u.username)}>Disable</Button>
                  ) : null}
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      </Card>
      <Card withBorder>
        <Title order={6} mb="xs">New account</Title>
        <form onSubmit={submit}>
          <Group align="flex-end">
            <TextInput label="Username" value={form.username} onChange={(e) => setForm({ ...form, username: e.currentTarget.value })} required />
            <PasswordInput label="Password (12+ characters)" value={form.password} onChange={(e) => setForm({ ...form, password: e.currentTarget.value })} required />
            <Select label="Role" data={["analyst", "lead", "admin"]} value={form.role} onChange={(v) => v && setForm({ ...form, role: v as Role })} />
            <Button type="submit" loading={create.isPending}>Create</Button>
          </Group>
        </form>
        {create.error && <Alert color="red" mt="xs">{(create.error as Error).message}</Alert>}
      </Card>
    </Stack>
  );
}
