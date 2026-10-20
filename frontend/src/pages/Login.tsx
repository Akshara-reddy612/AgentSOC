import { Alert, Button, Card, Center, Group, Loader, PasswordInput, Stack, Text, TextInput, Title } from "@mantine/core";
import { useEffect, useState, type FormEvent } from "react";
import { ApiError, api } from "../api";
import { useAuth } from "../auth";
import { IconLogo } from "../components/Icons";

/** Sign-in; on a server with no accounts yet, first-run setup of the first admin instead. */
export default function Login() {
  const { login, setup } = useAuth();
  const [needsSetup, setNeedsSetup] = useState<boolean | null>(null);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api<{ needed: boolean }>("/auth/setup")
      .then((r) => setNeedsSetup(r.needed))
      .catch(() => setNeedsSetup(false));
  }, []);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    if (needsSetup && password !== confirm) {
      setError("The two passwords differ.");
      return;
    }
    setBusy(true);
    try {
      if (needsSetup) await setup(username, password);
      else await login(username, password);
    } catch (err) {
      if (err instanceof ApiError && err.status === 429) setError("Too many failed sign-ins. Wait a few minutes and try again.");
      else if (needsSetup && err instanceof ApiError && err.status === 409) {
        setNeedsSetup(false);
        setError("An account was created meanwhile: sign in.");
      } else if (needsSetup && err instanceof ApiError) setError(err.message);
      else setError("Wrong username or password.");
    } finally {
      setBusy(false);
    }
  }

  if (needsSetup === null)
    return (
      <Center h="100vh">
        <Loader />
      </Center>
    );

  return (
    <Center h="100vh">
      <Card w={400} withBorder padding="xl">
        <form onSubmit={submit}>
          <Stack>
            <div>
              <Group gap={8} mb={2}>
                <span style={{ color: "var(--soc-brand)", display: "flex" }}><IconLogo size={26} /></span>
                <Title order={3}>AgentSOC</Title>
              </Group>
              <Text size="sm" c="dimmed">
                {needsSetup ? "First run — create the admin account" : "Analyst console — sign in"}
              </Text>
            </div>
            {needsSetup && (
              <Alert variant="light" p="xs">
                <Text size="xs">
                  No accounts exist yet. This first account is an admin; create the analysts' and leads' accounts on the
                  Accounts page afterwards. Passwords have at least 12 characters.
                </Text>
              </Alert>
            )}
            <TextInput label="Username" value={username} onChange={(e) => setUsername(e.currentTarget.value)} autoFocus required />
            <PasswordInput label="Password" value={password} onChange={(e) => setPassword(e.currentTarget.value)} required />
            {needsSetup && (
              <PasswordInput label="Password again" value={confirm} onChange={(e) => setConfirm(e.currentTarget.value)} required />
            )}
            {error && (
              <Alert color="red" variant="light">
                {error}
              </Alert>
            )}
            <Button type="submit" loading={busy}>
              {needsSetup ? "Create admin account" : "Sign in"}
            </Button>
          </Stack>
        </form>
      </Card>
    </Center>
  );
}
