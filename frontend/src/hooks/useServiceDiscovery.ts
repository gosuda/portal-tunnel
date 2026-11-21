import { useEffect, useState } from "react";
import { apiClient, APIClientError } from "@/lib/apiClient";
import { RELAY_API_PATHS } from "@/lib/apiPaths";
import { mergeLocations } from "@/lib/server";
import type { DiscoveredService, ServiceDiscoveryResponse } from "@/types/api";

const REFRESH_MS = 25_000;
const REQUEST_TIMEOUT_MS = 7_000;

function pruneExpiredLocations(response: ServiceDiscoveryResponse, now: number) {
  let nextExpiry = Infinity;
  let stale = false;
  const services = response.services.flatMap((service) => {
    const locations = service.locations.filter((location) => {
      const expires = Date.parse(location.expires_at);
      if (!Number.isFinite(expires) || expires <= now) {
        stale = true;
        return false;
      }
      nextExpiry = Math.min(nextExpiry, expires);
      return true;
    });
    return locations.length ? [{ ...service, locations }] : [];
  });
  return {
    response: stale ? { ...response, services, partial: true } : response,
    nextExpiry,
  };
}

// Keep locations from earlier polls until they expire.
export function mergeDiscoveryResponses(
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
  return {
    ...incoming,
    services: [...services.values()],
    relays_checked: Math.max(previous.relays_checked, incoming.relays_checked),
    relays_skipped: Math.min(previous.relays_skipped, incoming.relays_skipped),
  };
}

// Mounted by the public-list page. Card rendering alone never starts a lookup.
export function useServiceDiscovery(address: string | undefined, name?: string, enabled = true, refresh = false) {
  const query = new URLSearchParams();
  if (address !== undefined) query.set("address", address);
  if (name !== undefined) query.set("name", name);
  const key = query.toString();
  const valid = address === undefined ? name === undefined : /^0x[0-9a-f]{40}$/i.test(address);
  const [request, setRequest] = useState(0);
  const [state, setState] = useState<{ key: string; request: number; response?: ServiceDiscoveryResponse; error?: string } | undefined>();
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
        const { nextExpiry } = pruneExpiredLocations(incoming, Date.now());
        refreshDelay = Math.min(REFRESH_MS, Math.max(1, nextExpiry - Date.now() + 1));
        if (!cancelled) {
          setState((previous) => ({
            key,
            request,
            response: mergeDiscoveryResponses(previous?.key === key ? previous.response : undefined, incoming),
          }));
        }
      } catch (error) {
        if (cancelled) return;
        const unsupported = error instanceof APIClientError && error.status === 404;
        const now = Date.now();
        setState((previous) => ({
          key,
          request,
          response: previous?.key === key && previous.response
            ? pruneExpiredLocations(previous.response, now).response
            : undefined,
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
  }, [key, request, enabled, refresh, valid]);

  useEffect(() => {
    if (!state?.response) return;
    const { key: snapshotKey, response: snapshot } = state;
    const now = Date.now();
    const { response, nextExpiry } = pruneExpiredLocations(snapshot, now);
    if (snapshot === response && !Number.isFinite(nextExpiry)) return;
    const delay = Math.max(0, nextExpiry - now);
    const timer = window.setTimeout(() => {
      const currentTime = Date.now();
      setState((current) =>
        current?.key === snapshotKey && current.response
          ? { ...current, response: pruneExpiredLocations(current.response, currentTime).response }
          : current,
      );
    }, delay);
    return () => window.clearTimeout(timer);
  }, [state]);

  const current = enabled && valid && state?.key === key ? state : undefined;
  return {
    response: current?.response,
    error: current?.request === request ? current.error : undefined,
    loading: enabled && valid && (!current || current.request !== request),
    checkMore: () => setRequest((previous) => previous + 1),
  };
}
