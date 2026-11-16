import { useEffect, useState } from "react";
import { apiClient, APIClientError } from "@/lib/apiClient";
import { RELAY_API_PATHS } from "@/lib/apiPaths";
import type { ServiceDiscoveryResponse } from "@/types/api";

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
        const response = refresh && controller
          ? await apiClient.get<ServiceDiscoveryResponse>(path, controller.signal)
          : await apiClient.get<ServiceDiscoveryResponse>(path);
        if (!cancelled) setState({ key, request, response: pruneExpiredLocations(response, Date.now()).response });
      } catch (error) {
        if (cancelled) return;
        const unsupported = error instanceof APIClientError && error.status === 404;
        setState({
          key,
          request,
          error: unsupported
            ? "This relay does not support service discovery. The local directory is still available."
            : "Other relay locations could not be checked. The local directory is still available.",
        });
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
  // Keep expiry independent of fetching and scope changes. A new HTTP response
  // can still contain cached locations with only a few seconds left to live.
  useEffect(() => {
    const snapshot = state?.response;
    if (!snapshot) return;
    const now = Date.now();
    const { response, nextExpiry } = pruneExpiredLocations(snapshot, now);
    if (snapshot === response && !Number.isFinite(nextExpiry)) return;
    const timer = window.setTimeout(() => {
      const next = pruneExpiredLocations(snapshot, Date.now()).response;
      setState((current) => current && current === state
        ? { ...current, response: next }
        : current);
    }, snapshot === response ? nextExpiry - now : 0);
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
