import { Alert, Button, Card, Center, PasswordInput, Stack, Text, TextInput, Title } from "@mantine/core";
import { useState, type FormEvent } from "react";
import { ApiError } from "../api";
import { useAuth } from "../auth";

export default function Login() {
  const { login } = useAuth();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await login(username, password);
    } catch (err) {
      setError(
        err instanceof ApiError && err.status === 429
          ? "Too many failed sign-ins. Wait a few minutes and try again."
          : "Wrong username or password.",
      );
    } finally {
      setBusy(false);
    }
  }

  return (
    <Center h="100vh">
      <Card w={380} withBorder padding="xl">
        <form onSubmit={submit}>
          <Stack>
            <div>
              <Title order={3}>AgentSOC</Title>
              <Text size="sm" c="dimmed">
                Analyst console — sign in
              </Text>
            </div>
            <TextInput label="Username" value={username} onChange={(e) => setUsername(e.currentTarget.value)} autoFocus required />
            <PasswordInput label="Password" value={password} onChange={(e) => setPassword(e.currentTarget.value)} required />
            {error && (
              <Alert color="red" variant="light">
                {error}
              </Alert>
            )}
            <Button type="submit" loading={busy}>
              Sign in
            </Button>
          </Stack>
        </form>
      </Card>
    </Center>
  );
}
