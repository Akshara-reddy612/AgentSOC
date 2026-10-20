// Queries several pages share (one cache entry each).
import { useQuery } from "@tanstack/react-query";
import { api, type LiveStatus } from "./api";

/** The runner's status; `enabled` false until someone is signed in (it needs a session). */
export function useLive(enabled = true) {
  return useQuery({ queryKey: ["live"], queryFn: () => api<LiveStatus>("/live/status"), refetchInterval: 2000, enabled });
}

export type Techniques = Record<string, { name: string; detail: string }>;

/** ATT&CK technique names the pipeline reasons about (static: fetched once). */
export function useTechniques() {
  return useQuery({ queryKey: ["techniques"], queryFn: () => api<Techniques>("/techniques"), staleTime: Infinity });
}
