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
  const op = useMutation({
    mutationFn: (p: { user: string; what: string; body?: unknown }) =>
      api(`/admin/users/${encodeURIComponent(p.user)}/${p.what}`, { method: "POST", body: p.body }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["users"] }),
  });
  const [reset, setReset] = useState<{ user: string | null; password: string }>({ user: null, password: "" });
  const resetPw = useMutation({
    mutationFn: () => api(`/admin/users/${encodeURIComponent(reset.user ?? "")}/password`, { method: "POST", body: { password: reset.password } }),
    onSuccess: () => setReset({ user: null, password: "" }),
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
                <Table.Td>
                  {u.username === session?.username ? (
                    <Badge variant="light">{u.role} (you)</Badge>
                  ) : (
                    <Select
                      size="xs"
                      w={120}
                      data={["analyst", "lead", "admin"]}
                      value={u.role}
                      allowDeselect={false}
                      onChange={(v) => v && v !== u.role && op.mutate({ user: u.username, what: "role", body: { role: v } })}
                    />
                  )}
                </Table.Td>
                <Table.Td><Text size="xs">{when(u.created).slice(0, 16)}</Text></Table.Td>
                <Table.Td>
                  {u.username === session?.username ? null : u.disabled ? (
                    <Group gap="xs">
                      <Badge color="gray">disabled</Badge>
                      <Button size="xs" variant="subtle" onClick={() => op.mutate({ user: u.username, what: "enable" })}>Enable</Button>
                    </Group>
                  ) : (
                    <Button size="xs" variant="subtle" color="red" onClick={() => op.mutate({ user: u.username, what: "disable" })}>Disable</Button>
                  )}
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
        {op.error && <Alert color="red" mt="xs">{(op.error as Error).message}</Alert>}
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
      <Card withBorder>
        <Title order={6} mb="xs">Reset a password</Title>
        <Text size="xs" c="dimmed" mb="xs">Sets a new password and signs the user out everywhere. Users change their own on My account.</Text>
        <Group align="flex-end">
          <Select
            label="User"
            data={(users.data ?? []).filter((u) => u.username !== session?.username).map((u) => u.username)}
            value={reset.user}
            onChange={(v) => setReset({ ...reset, user: v })}
          />
          <PasswordInput label="New password (12+ characters)" value={reset.password} onChange={(e) => setReset({ ...reset, password: e.currentTarget.value })} />
          <Button disabled={!reset.user || !reset.password} loading={resetPw.isPending} onClick={() => resetPw.mutate()}>Reset</Button>
        </Group>
        {resetPw.isSuccess && <Alert color="green" mt="xs" p="xs">Password reset.</Alert>}
        {resetPw.error && <Alert color="red" mt="xs">{(resetPw.error as Error).message}</Alert>}
      </Card>
    </Stack>
  );
}
