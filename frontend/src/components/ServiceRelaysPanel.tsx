import type { JSX } from "react";
import * as Dialog from "@radix-ui/react-dialog";
import clsx from "clsx";
import { ExternalLink, X } from "lucide-react";
import { useCopy } from "@/hooks/useCopy";
import { isLocationAvailable, isLocationLive, type BaseServer } from "@/lib/server";
import type { ServiceDiscoveryResponse, ServiceLocation } from "@/types/api";

export function ServiceRelaysPanel({ server, response, loading, error, onClose }: {
  server: BaseServer;
  response?: ServiceDiscoveryResponse;
  loading: boolean;
  error?: string;
  onClose: () => void;
}): JSX.Element {
  const discoveredLocations = server.locations?.length ? server.locations
    : response?.services.find((service) => service.name === (server.serviceName ?? "") && service.address.toLowerCase() === server.address?.toLowerCase())?.locations;

  const { copiedKey, copy } = useCopy(1500);
  const currentOrigin = typeof window !== "undefined" && window.location.origin ? window.location.origin : "https://localhost";
  const defaultLocalLocation: ServiceLocation = {
    relay_url: currentOrigin,
    url: server.link || (server.dns ? `https://${server.dns}/` : ""),
    tcp_addr: server.remoteOnly ? undefined : server.tcpAddr,
    udp_addr: server.remoteOnly ? undefined : server.udpAddr,
    current_relay: true,
    reported_ready: server.online,
    observed_at: "",
    expires_at: "",
    verification: "relay-reported",
  };

  const resolvedLocations = (() => {
    if (discoveredLocations && discoveredLocations.length > 0) {
      if (server.remoteOnly) return discoveredLocations;
      const hasCurrent = discoveredLocations.some((loc) => loc.current_relay);
      return hasCurrent ? discoveredLocations : [defaultLocalLocation, ...discoveredLocations];
    }
    return !server.remoteOnly ? [defaultLocalLocation] : [];
  })();

  return (
    <Dialog.Root open onOpenChange={(open) => { if (!open) onClose(); }}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-50 bg-black/50 backdrop-blur-sm" />
        <Dialog.Content aria-describedby={undefined} className="fixed inset-x-0 bottom-0 z-50 max-h-[85vh] overflow-y-auto rounded-t-2xl border border-border bg-background p-6 shadow-xl sm:inset-x-auto sm:bottom-auto sm:left-1/2 sm:top-1/2 sm:w-[min(90vw,32rem)] sm:-translate-x-1/2 sm:-translate-y-1/2 sm:rounded-2xl">
          <div className="flex items-center justify-between">
            <Dialog.Title className="text-base font-semibold">
              Relays
            </Dialog.Title>
            <Dialog.Close aria-label="Close" className="rounded p-1 text-muted-foreground hover:bg-secondary hover:text-foreground">
              <X className="size-4" />
            </Dialog.Close>
          </div>

          {loading && <p role="status" className="mt-4 text-sm text-muted-foreground">Checking relays…</p>}
          {error && <p role="alert" className="mt-4 text-sm text-destructive">{error}</p>}

          <div className="mt-4 space-y-2">
            {resolvedLocations.map((loc) => {
              // Each row uses its own relay's endpoints. Transport rows name the
              // relay and copy its addresses; HTTP rows name and link the service URL.
              // This relay's own row comes from the local lease; remote rows must be live.
              const endpoints = [
                ...(loc.tcp_addr ? [{ protocol: "TCP", address: loc.tcp_addr }] : []),
                ...(loc.udp_addr ? [{ protocol: "UDP", address: loc.udp_addr }] : []),
              ];
              const transport = endpoints.length > 0;
              const live = transport
                ? (loc.current_relay ? server.online : isLocationLive(loc))
                : Boolean(loc.url) && (loc.current_relay || isLocationAvailable(loc));
              const href = !transport && live ? loc.url : "";
              const label = (transport ? loc.relay_url : loc.url || loc.relay_url).replace(/^https?:\/\//, "").replace(/\/$/, "");
              const Row = href ? "a" : "div";
              return (
                <Row
                  key={loc.relay_url}
                  {...(href ? { href, target: "_blank", rel: "noopener noreferrer" } : {})}
                  className={clsx(
                    "flex items-center justify-between gap-3 rounded-lg border p-3 text-sm font-medium",
                    href && "border-border transition-colors hover:bg-secondary hover:text-primary",
                    !href && live && "border-border bg-card text-foreground",
                    !live && "border-border/60 bg-secondary/30 text-muted-foreground",
                  )}
                >
                  <div className="flex min-w-0 items-center gap-2">
                    <span className="truncate font-mono">{label}</span>
                    {loc.current_relay && (
                      <span className="shrink-0 rounded bg-primary/10 px-1.5 py-0.5 text-[10px] font-semibold text-primary">
                        Current
                      </span>
                    )}
                  </div>
                  {!live ? (
                    <span className="shrink-0 text-xs text-muted-foreground">Unavailable</span>
                  ) : href ? (
                    <ExternalLink className="size-4 shrink-0 text-muted-foreground" />
                  ) : (
                    <div className="flex shrink-0 flex-col items-end gap-1">
                      {endpoints.map((endpoint) => {
                        const key = `${loc.relay_url}|${endpoint.protocol}`;
                        return (
                          <button
                            key={endpoint.protocol}
                            type="button"
                            onClick={() => void copy(endpoint.address, key)}
                            title={endpoint.address}
                            aria-label={`Copy ${endpoint.protocol} ${endpoint.address}`}
                            className="inline-flex items-center gap-1.5 rounded bg-secondary px-2 py-0.5 text-xs font-mono font-medium text-muted-foreground transition-colors hover:bg-primary hover:text-primary-foreground cursor-pointer"
                          >
                            <span className="font-semibold">{endpoint.protocol}</span>
                            <span>{copiedKey === key ? "Copied!" : endpoint.address}</span>
                          </button>
                        );
                      })}
                    </div>
                  )}
                </Row>
              );
            })}

            {!loading && !resolvedLocations.length && (
              <p className="py-4 text-center text-sm text-muted-foreground">
                No relays found.
              </p>
            )}
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
