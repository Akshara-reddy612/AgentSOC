import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { api, getToken, setToken, type Role } from "./api";

interface Session {
  username: string;
  role: Role;
}

interface AuthState {
  session: Session | null;
  loading: boolean;
  login: (username: string, password: string) => Promise<void>;
  setup: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<Session | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!getToken()) {
      setLoading(false);
      return;
    }
    api<{ analyst: string; role: Role }>("/me")
      .then((me) => setSession({ username: me.analyst, role: me.role }))
      .catch(() => setToken(null))
      .finally(() => setLoading(false));
  }, []);

  async function begin(path: string, username: string, password: string) {
    const r = await api<{ token: string; username: string; role: Role }>(path, {
      method: "POST",
      body: { username, password },
    });
    setToken(r.token);
    setSession({ username: r.username, role: r.role });
  }

  const login = (username: string, password: string) => begin("/auth/login", username, password);
  /** First run only: creates the first (admin) account and signs it in. */
  const setup = (username: string, password: string) => begin("/auth/setup", username, password);

  async function logout() {
    try {
      await api("/auth/logout", { method: "POST" });
    } finally {
      setToken(null);
      setSession(null);
    }
  }

  return <AuthContext.Provider value={{ session, loading, login, setup, logout }}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth outside AuthProvider");
  return ctx;
}

export function canControl(role: Role | undefined): boolean {
  return role === "lead" || role === "admin";
}
