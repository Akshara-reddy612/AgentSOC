import { AppShell, Avatar, Center, Group, Loader, Menu, NavLink, Stack, Text, UnstyledButton } from "@mantine/core";
import { lazy, Suspense, type ReactNode } from "react";
import { NavLink as RouterLink, Navigate, Route, Routes, useLocation, useNavigate } from "react-router-dom";
import { useAuth } from "./auth";
import { useLive } from "./hooks";
import { IconKnowledge, IconLive, IconLogo, IconMetrics, IconUser, IconUsers } from "./components/Icons";
import CasePage from "./pages/Case";
import Live from "./pages/Live";
import Login from "./pages/Login";

// Pages with the heavy graph / chart libraries load on demand.
const Admin = lazy(() => import("./pages/Admin"));
const Account = lazy(() => import("./pages/Account"));
const Knowledge = lazy(() => import("./pages/Knowledge"));
const MetricsPage = lazy(() => import("./pages/Metrics"));

const NAV: { to: string; label: string; hint: string; icon: ReactNode }[] = [
  { to: "/", label: "Live", hint: "stream and review queue", icon: <IconLive /> },
  { to: "/knowledge", label: "Knowledge Store", hint: "what has been learned", icon: <IconKnowledge /> },
  { to: "/metrics", label: "Metrics", hint: "workload and learning", icon: <IconMetrics /> },
];

function StreamClock() {
  const { data } = useLive();
  if (!data) return null;
  const t = new Date(data.stream_time);
  const date = t.toLocaleDateString("en-GB", { weekday: "short", day: "numeric", month: "short", year: "numeric", timeZone: "UTC" });
  const time = t.toISOString().slice(11, 19);
  return (
    <div className="soc-clock" title={`${data.state}; stream time (UTC)`}>
      <span className="soc-dot" data-state={data.state} />
      <Text size="xs" c="dimmed" fw={600}>{data.state}</Text>
      <Text size="sm" ff="monospace" fw={600}>{time}</Text>
      <Text size="xs" c="dimmed">{date} UTC</Text>
      {data.mode !== "follow" && <Text size="xs" c="dimmed">×{data.speed}</Text>}
    </div>
  );
}

export default function App() {
  const { session, loading, logout } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();
  const live = useLive(!!session);

  if (loading)
    return (
      <Center h="100vh">
        <Loader />
      </Center>
    );
  if (!session) return <Login />;

  const active = (to: string) =>
    to === "/" ? location.pathname === "/" || location.pathname.startsWith("/cases") : location.pathname.startsWith(to);

  return (
    <AppShell header={{ height: 60 }} navbar={{ width: 232, breakpoint: "sm" }} padding="lg">
      <AppShell.Header className="soc-header">
        <Group h="100%" px="lg" justify="space-between" wrap="nowrap">
          <Group gap={10} wrap="nowrap">
            <span style={{ color: "var(--soc-brand)", display: "flex" }}><IconLogo size={24} /></span>
            <div>
              <Text fw={700} size="lg" lh={1.1}>AgentSOC</Text>
              <Text size="xs" c="dimmed" lh={1.1}>{live.data?.mode === "follow" ? "live logs" : "DEDALE replay"}</Text>
            </div>
          </Group>
          <StreamClock />
          <Menu position="bottom-end" width={200} withArrow>
            <Menu.Target>
              <UnstyledButton>
                <Group gap={8} wrap="nowrap">
                  <Avatar size={30} radius="sm" color="gray" variant="filled">{session.username.slice(0, 2).toUpperCase()}</Avatar>
                  <div>
                    <Text size="sm" fw={600} lh={1.1}>{session.username}</Text>
                    <Text size="xs" c="dimmed" lh={1.1}>{session.role}</Text>
                  </div>
                </Group>
              </UnstyledButton>
            </Menu.Target>
            <Menu.Dropdown>
              <Menu.Item onClick={() => navigate("/account")}>My account</Menu.Item>
              {session.role === "admin" && <Menu.Item onClick={() => navigate("/admin")}>Accounts</Menu.Item>}
              <Menu.Divider />
              <Menu.Item color="red" onClick={() => void logout()}>Sign out</Menu.Item>
            </Menu.Dropdown>
          </Menu>
        </Group>
      </AppShell.Header>
      <AppShell.Navbar p="sm" className="soc-navbar">
        <Stack gap={4}>
          {NAV.map((n) => (
            <NavLink key={n.to} className="soc-nav-item" component={RouterLink} to={n.to} label={n.label}
              description={n.hint} leftSection={n.icon} active={active(n.to)} />
          ))}
          <Text size="xs" c="dimmed" fw={600} mt="md" mb={2} px="sm">Account</Text>
          {session.role === "admin" && (
            <NavLink className="soc-nav-item" component={RouterLink} to="/admin" label="Accounts" description="users and roles"
              leftSection={<IconUsers />} active={active("/admin")} />
          )}
          <NavLink className="soc-nav-item" component={RouterLink} to="/account" label="My account" description="role and password"
            leftSection={<IconUser />} active={active("/account")} />
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
            <Route path="/account" element={<Account />} />
            <Route path="*" element={<Navigate to="/" />} />
          </Routes>
        </Suspense>
      </AppShell.Main>
    </AppShell>
  );
}
