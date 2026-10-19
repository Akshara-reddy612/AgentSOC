import { AppShell, Badge, Button, Center, Group, Loader, NavLink, Stack, Text, Title } from "@mantine/core";
import { useQuery } from "@tanstack/react-query";
import { lazy, Suspense } from "react";
import { NavLink as RouterLink, Navigate, Route, Routes, useLocation } from "react-router-dom";
import { api, type LiveStatus } from "./api";
import { useAuth } from "./auth";
import { when } from "./format";
import CasePage from "./pages/Case";
import Live from "./pages/Live";
import Login from "./pages/Login";

// Pages with the heavy graph / chart libraries load on demand.
const Admin = lazy(() => import("./pages/Admin"));
const Knowledge = lazy(() => import("./pages/Knowledge"));
const MetricsPage = lazy(() => import("./pages/Metrics"));

const NAV = [
  { to: "/", label: "Live", hint: "stream and review queue" },
  { to: "/knowledge", label: "Knowledge Store", hint: "what has been learned" },
  { to: "/metrics", label: "Metrics", hint: "workload and learning" },
];

function StreamClock() {
  const { data } = useQuery({ queryKey: ["live"], queryFn: () => api<LiveStatus>("/live/status"), refetchInterval: 2000 });
  if (!data) return null;
  const color = data.state === "running" ? "green" : data.state === "finished" ? "gray" : "yellow";
  return (
    <Group gap="xs">
      <Badge color={color} variant="light">
        {data.state}
      </Badge>
      <Text size="sm" ff="monospace">
        {when(data.stream_time)}
      </Text>
      <Text size="xs" c="dimmed">
        ×{data.speed}
      </Text>
    </Group>
  );
}

export default function App() {
  const { session, loading, logout } = useAuth();
  const location = useLocation();

  if (loading)
    return (
      <Center h="100vh">
        <Loader />
      </Center>
    );
  if (!session) return <Login />;

  return (
    <AppShell header={{ height: 56 }} navbar={{ width: 220, breakpoint: "sm" }} padding="md">
      <AppShell.Header>
        <Group h="100%" px="md" justify="space-between">
          <Group gap="sm">
            <Title order={4}>AgentSOC</Title>
            <Text size="xs" c="dimmed">
              DEDALE replay
            </Text>
          </Group>
          <StreamClock />
          <Group gap="xs">
            <Text size="sm">{session.username}</Text>
            <Badge variant="outline">{session.role}</Badge>
            <Button size="xs" variant="subtle" onClick={() => void logout()}>
              Sign out
            </Button>
          </Group>
        </Group>
      </AppShell.Header>
      <AppShell.Navbar p="sm">
        <Stack gap={4}>
          {NAV.map((n) => (
            <NavLink
              key={n.to}
              component={RouterLink}
              to={n.to}
              label={n.label}
              description={n.hint}
              active={n.to === "/" ? location.pathname === "/" || location.pathname.startsWith("/cases") : location.pathname.startsWith(n.to)}
            />
          ))}
          {session.role === "admin" && (
            <NavLink component={RouterLink} to="/admin" label="Accounts" description="users and roles" active={location.pathname === "/admin"} />
          )}
        </Stack>
      </AppShell.Navbar>
      <AppShell.Main>
        <Suspense fallback={<Loader />}>
        <Routes>
          <Route path="/" element={<Live />} />
          <Route path="/cases/:caseId" element={<CasePage />} />
          <Route path="/knowledge" element={<Knowledge />} />
          <Route path="/metrics" element={<MetricsPage />} />
          <Route path="/admin" element={session.role === "admin" ? <Admin /> : <Navigate to="/" />} />
          <Route path="*" element={<Navigate to="/" />} />
        </Routes>
        </Suspense>
      </AppShell.Main>
    </AppShell>
  );
}
