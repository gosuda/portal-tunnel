import { useEffect, useState } from "react";
import { apiClient, APIClientError } from "@/lib/apiClient";
import { RELAY_API_PATHS } from "@/lib/apiPaths";
import type { DiscoveredService, ServiceDiscoveryResponse, ServiceLocation } from "@/types/api";

const REFRESH_MS = 30_000;
const REQUEST_TIMEOUT_MS = 7_000;

export type DiscoveredLocationEvent = {
  serviceName: string;
  serviceAddress: string;
  location: ServiceLocation;
};

export function mergeDiscoveryResponses(
  previous?: ServiceDiscoveryResponse,
  incoming?: ServiceDiscoveryResponse,
): { response: ServiceDiscoveryResponse; newLocations: DiscoveredLocationEvent[] } {
  if (!previous) {
    const newLocations: DiscoveredLocationEvent[] = [];
    for (const service of incoming?.services ?? []) {
      for (const location of service.locations) {
        newLocations.push({
          serviceName: service.name,
          serviceAddress: service.address,
          location,
        });
      }
    }
    return {
      response: incoming ?? { services: [], partial: false, relays_checked: 0, relays_skipped: 0 },
      newLocations,
    };
  }
  if (!incoming) {
    return { response: previous, newLocations: [] };
  }

  const newLocations: DiscoveredLocationEvent[] = [];
  const servicesMap = new Map<string, DiscoveredService>();

  for (const s of previous.services) {
    const key = `${s.name.toLowerCase()}:${s.address.toLowerCase()}`;
    servicesMap.set(key, { ...s, locations: [...s.locations] });
  }

  for (const s of incoming.services) {
    const key = `${s.name.toLowerCase()}:${s.address.toLowerCase()}`;
    const existing = servicesMap.get(key);
    if (!existing) {
      servicesMap.set(key, s);
      for (const loc of s.locations) {
        newLocations.push({
          serviceName: s.name,
          serviceAddress: s.address,
          location: loc,
        });
      }
    } else {
      const locMap = new Map<string, ServiceLocation>();
      for (const l of existing.locations) {
        locMap.set(l.relay_url, l);
      }
      for (const l of s.locations) {
        if (!locMap.has(l.relay_url)) {
          locMap.set(l.relay_url, l);
          newLocations.push({
            serviceName: s.name,
            serviceAddress: s.address,
            location: l,
          });
        } else {
          const prev = locMap.get(l.relay_url)!;
          locMap.set(l.relay_url, {
            ...prev,
            ...l,
            url: l.url || prev.url,
            reported_ready: l.reported_ready ?? prev.reported_ready,
            reputation: l.reputation ?? prev.reputation,
          });
        }
      }
      existing.locations = Array.from(locMap.values());
    }
  }

  return {
    response: {
      ...incoming,
      services: Array.from(servicesMap.values()),
      relays_checked: Math.max(previous.relays_checked, incoming.relays_checked),
      relays_skipped: Math.min(previous.relays_skipped, incoming.relays_skipped),
    },
    newLocations,
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
      if (refresh) {
        controller = new AbortController();
        deadline = window.setTimeout(() => controller?.abort(), REQUEST_TIMEOUT_MS);
      }
      try {
        const incoming = refresh && controller
          ? await apiClient.get<ServiceDiscoveryResponse>(path, controller.signal)
          : await apiClient.get<ServiceDiscoveryResponse>(path);
        if (!cancelled) {
          setState((previous) => {
            const prevResponse = previous?.key === key ? previous.response : undefined;
            const { response: merged, newLocations } = mergeDiscoveryResponses(prevResponse, incoming);
            if (newLocations.length > 0 && typeof window !== "undefined") {
              window.dispatchEvent(
                new CustomEvent("portal:relay-discovered", { detail: { newLocations } }),
              );
            }
            return { key, request, response: merged };
          });
        }
      } catch (error) {
        if (cancelled) return;
        const unsupported = error instanceof APIClientError && error.status === 404;
        setState((previous) => ({
          key,
          request,
          response: previous?.key === key ? previous.response : undefined,
          error: unsupported
            ? "This relay does not support service discovery. The local directory is still available."
            : "Other relay locations could not be checked. The local directory is still available.",
        }));
      } finally {
        window.clearTimeout(deadline);
        if (refresh && !cancelled) timer = window.setTimeout(() => void load(), REFRESH_MS);
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

  const current = enabled && valid && state?.key === key ? state : undefined;
  return {
    response: current?.response,
    error: current?.request === request ? current.error : undefined,
    loading: enabled && valid && (!current || current.request !== request),
    checkMore: () => setRequest((previous) => previous + 1),
  };
}
