import { useEffect, useState } from "react";
import { apiClient, APIClientError } from "@/lib/apiClient";
import { RELAY_API_PATHS } from "@/lib/apiPaths";
import { isIdentityAddress, mergeLocations } from "@/lib/server";
import type { DiscoveredService, ServiceDiscoveryResponse } from "@/types/api";

const REFRESH_MS = 25_000;
const REQUEST_TIMEOUT_MS = 7_000;
const MAX_TIMER_MS = 2 ** 31 - 1;

// Earliest future expires_at in a snapshot, or Infinity when none is left.
function nextLocationExpiry(response: ServiceDiscoveryResponse, now: number): number {
  let next = Infinity;
  for (const service of response.services) {
    for (const location of service.locations) {
      const expires = Date.parse(location.expires_at);
      if (Number.isFinite(expires) && expires > now) next = Math.min(next, expires);
    }
  }
  return next;
}

// Keep every location seen for this filter. expires_at decides only whether a
// location is available, never whether it is listed. The newest snapshot owns
// service metadata.
function mergeDiscoveryResponses(
  previous: ServiceDiscoveryResponse | undefined,
  incoming: ServiceDiscoveryResponse,
): ServiceDiscoveryResponse {
  if (!previous) return incoming;
  const identity = (service: DiscoveredService) =>
    `${service.name.toLowerCase()}:${service.address.toLowerCase()}`;
  const services = new Map(previous.services.map((service) => [identity(service), service]));
  for (const service of incoming.services) {
    const existing = services.get(identity(service));
    services.set(identity(service), existing
      ? { ...service, locations: mergeLocations(existing.locations, service.locations) }
      : service);
  }
  return { services: [...services.values()] };
}

// Mounted by the public-list page. Card rendering alone never starts a lookup.
export function useServiceDiscovery(address: string | undefined, name?: string, enabled = true, refresh = false) {
  const query = new URLSearchParams();
  if (address !== undefined) query.set("address", address);
  if (name !== undefined) query.set("name", name);
  const key = query.toString();
  const valid = address === undefined ? name === undefined : isIdentityAddress(address);
  const [state, setState] = useState<{ key: string; response?: ServiceDiscoveryResponse; error?: string } | undefined>();
  useEffect(() => {
    if (!enabled || !valid) return;
    let cancelled = false;
    let timer: number | undefined;
    let deadline: number | undefined;
    let controller: AbortController | undefined;
    const path = key ? `${RELAY_API_PATHS.public.services}?${key}` : RELAY_API_PATHS.public.services;
    async function load() {
      let refreshDelay = REFRESH_MS;
      if (refresh) {
        controller = new AbortController();
        deadline = window.setTimeout(() => controller?.abort(), REQUEST_TIMEOUT_MS);
      }
      try {
        const incoming = refresh && controller
          ? await apiClient.get<ServiceDiscoveryResponse>(path, controller.signal)
          : await apiClient.get<ServiceDiscoveryResponse>(path);
        // A poll can return a cached observation about to expire. Recheck just
        // after expiry so the backend can fetch it again instead of waiting
        // another full polling interval with no locations.
        refreshDelay = Math.min(REFRESH_MS, Math.max(1, nextLocationExpiry(incoming, Date.now()) - Date.now() + 1));
        if (!cancelled) {
          setState((previous) => ({
            key,
            response: mergeDiscoveryResponses(previous?.key === key ? previous.response : undefined, incoming),
          }));
        }
      } catch (error) {
        if (cancelled) return;
        const unsupported = error instanceof APIClientError && error.status === 404;
        setState((previous) => ({
          key,
          response: previous?.key === key ? previous.response : undefined,
          error: unsupported
            ? "This relay does not support service discovery. The local directory is still available."
            : "Other relay locations could not be checked. The local directory is still available.",
        }));
      } finally {
        window.clearTimeout(deadline);
        if (refresh && !cancelled) timer = window.setTimeout(() => void load(), refreshDelay);
      }
    }
    void load();
    return () => {
      cancelled = true;
      controller?.abort();
      window.clearTimeout(deadline);
      window.clearTimeout(timer);
    };
  }, [key, enabled, refresh, valid]);

  // Locations stay listed after expiry. Publish a new services array when one
  // expires so memoized consumers derive availability again.
  useEffect(() => {
    if (!state?.response) return;
    const { key: snapshotKey, response: snapshot } = state;
    const now = Date.now();
    const next = nextLocationExpiry(snapshot, now);
    if (!Number.isFinite(next)) return;
    const timer = window.setTimeout(() => {
      setState((current) =>
        current?.key === snapshotKey && current.response
          ? { ...current, response: { ...current.response, services: [...current.response.services] } }
          : current,
      );
    }, Math.min(next - now, MAX_TIMER_MS));
    return () => window.clearTimeout(timer);
  }, [state]);

  const current = enabled && valid && state?.key === key ? state : undefined;
  return {
    response: current?.response,
    error: current?.error,
    loading: enabled && valid && !current,
  };
}
