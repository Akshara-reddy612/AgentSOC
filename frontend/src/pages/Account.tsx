import { Alert, Badge, Button, Card, Group, PasswordInput, Stack, Text, Title } from "@mantine/core";
import { useState, type FormEvent } from "react";
import { ApiError, api } from "../api";
import { useAuth } from "../auth";

const ROLE_TEXT: Record<string, string> = {
  analyst: "reviews cases, gives verdicts and approves containment",
  lead: "also controls the replay and can withdraw a wrong malicious verdict",
  admin: "also manages accounts",
};

/** The signed-in user's own account: role and password. */
export default function Account() {
  const { session, login } = useAuth();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setMsg(null);
    if (next !== confirm) {
      setMsg({ ok: false, text: "The two new passwords differ." });
      return;
    }
    setBusy(true);
    try {
      await api("/auth/password", { method: "POST", body: { current_password: current, new_password: next } });
      await login(session!.username, next); // the change ended every session: sign in again with the new one
      setCurrent("");
      setNext("");
      setConfirm("");
      setMsg({ ok: true, text: "Password changed. Your other sessions were signed out." });
    } catch (err) {
      setMsg({ ok: false, text: err instanceof ApiError ? err.message : String(err) });
    } finally {
      setBusy(false);
    }
  }

  return (
    <Stack maw={520}>
      <Title order={2}>My account</Title>
      <Card withBorder>
        <Group gap="xs">
          <Text fw={600}>{session?.username}</Text>
          <Badge variant="light">{session?.role}</Badge>
        </Group>
        <Text size="sm" c="dimmed" mt={4}>
          {session ? `This role ${ROLE_TEXT[session.role]}.` : ""} Roles are set by an admin.
        </Text>
      </Card>
      <Card withBorder>
        <Title order={6} mb="xs">Change password</Title>
        <form onSubmit={submit}>
          <Stack gap="xs">
            <PasswordInput label="Current password" value={current} onChange={(e) => setCurrent(e.currentTarget.value)} required />
            <PasswordInput label="New password (12+ characters)" value={next} onChange={(e) => setNext(e.currentTarget.value)} required />
            <PasswordInput label="New password again" value={confirm} onChange={(e) => setConfirm(e.currentTarget.value)} required />
            <Button type="submit" loading={busy} w="fit-content">Change password</Button>
          </Stack>
        </form>
        {msg && <Alert color={msg.ok ? "green" : "red"} mt="xs" p="xs">{msg.text}</Alert>}
      </Card>
    </Stack>
  );
}
