import { useEffect, useState } from "react";
import { apiClient } from "@/lib/apiClient";
import { RELAY_API_PATHS } from "@/lib/apiPaths";
import { isIdentityAddress, type BaseServer } from "@/lib/server";
import type { FederatedCommentsResponse } from "@/types/api";

// Leave enough time for the backend to return partial results at its deadline.
const COMMENTS_REQUEST_TIMEOUT_MS = 24_000;

type LoadedSample = {
  key: string;
  generation: number;
  response?: FederatedCommentsResponse;
  error?: string;
};

// Called only by the open comments panel; only the current relay fans out.
// Each load is one complete bounded sample that replaces the previous one, so
// deleted or removed comments do not linger and no rows are appended twice.
export function useFederatedComments(server: BaseServer): { response: FederatedCommentsResponse | undefined; loading: boolean; error: string | undefined; refresh: () => void } {
  const address = server.address?.trim() ?? "";
  const valid = isIdentityAddress(address);
  const key = new URLSearchParams({ address, name: server.serviceName ?? "" }).toString();
  const [generation, setGeneration] = useState(0);
  const [sample, setSample] = useState<LoadedSample>();

  useEffect(() => {
    if (!valid) return;
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), COMMENTS_REQUEST_TIMEOUT_MS);
    let cancelled = false;
    void apiClient.get<FederatedCommentsResponse>(`${RELAY_API_PATHS.public.federatedComments}?${key}`, controller.signal)
      .then((response) => {
        if (!cancelled) setSample({ key, generation, response });
      })
      .catch(() => {
        if (!cancelled) setSample({ key, generation, error: "Other relay comments could not be checked." });
      })
      .finally(() => window.clearTimeout(timeout));
    return () => {
      cancelled = true;
      window.clearTimeout(timeout);
      controller.abort();
    };
  }, [key, generation, valid]);

  const current = sample?.key === key && sample.generation === generation ? sample : undefined;
  const loading = valid && !current;
  return {
    response: current?.response,
    loading,
    error: current?.error,
    refresh: () => { if (valid) setGeneration((value) => value + 1); },
  };
}
