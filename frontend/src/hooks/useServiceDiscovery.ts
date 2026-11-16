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
  const [request, setRequest] = useState(0);
  const [state, setState] = useState<{ key: string; request: number; response?: ServiceDiscoveryResponse; error?: string }>({ key: "", request: -1 });
  useEffect(() => {
    if (!enabled || !valid) return;
    let cancelled = false;
    apiClient.get<ServiceDiscoveryResponse>(`${RELAY_API_PATHS.public.services}?${key}`)
      .then((response) => { if (!cancelled) setState({ key, request, response }); })
      .catch((error: unknown) => {
        if (cancelled) return;
        const unsupported = error instanceof APIClientError && error.status === 404;
        setState({ key, request, error: unsupported
          ? "This relay does not support service lookup. The local directory is still available."
          : "Other relay locations could not be checked. The local directory is still available." });
      });
    return () => { cancelled = true; };
  }, [key, request, enabled, valid]);
  const current = state.key === key;
  return {
    response: current ? state.response : undefined,
    error: current && state.request === request ? state.error : undefined,
    loading: enabled && valid && (!current || state.request !== request),
    checkMore: () => setRequest((previous) => previous + 1),
  };
}
