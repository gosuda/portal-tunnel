import { useEffect, useState } from "react";
import { apiClient, APIClientError } from "@/lib/apiClient";
import { RELAY_API_PATHS } from "@/lib/apiPaths";
import type { ServiceDiscoveryResponse } from "@/types/api";

// Mounted by the public-list page. Card rendering alone never starts a lookup.
export function useServiceDiscovery(address: string, name?: string, enabled = true) {
  const query = new URLSearchParams({ address });
  if (name !== undefined) query.set("name", name);
  const key = query.toString();
  const valid = /^0x[0-9a-f]{40}$/i.test(address);
  const [state, setState] = useState<{ key: string; response?: ServiceDiscoveryResponse; error?: string }>({ key: "" });
  useEffect(() => {
    if (!enabled || !valid) return;
    let cancelled = false;
    apiClient.get<ServiceDiscoveryResponse>(`${RELAY_API_PATHS.public.services}?${key}`)
      .then((response) => { if (!cancelled) setState({ key, response }); })
      .catch((error: unknown) => {
        if (cancelled) return;
        const unsupported = error instanceof APIClientError && error.status === 404;
        setState({ key, error: unsupported
          ? "This relay does not support service lookup. The local directory is still available."
          : "Other relay locations could not be checked. The local directory is still available." });
      });
    return () => { cancelled = true; };
  }, [key, enabled, valid]);
  const current = state.key === key;
  return {
    response: current ? state.response : undefined,
    error: current ? state.error : undefined,
    loading: enabled && valid && !current,
  };
}
