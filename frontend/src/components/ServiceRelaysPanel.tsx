import type { JSX } from "react";
import * as Dialog from "@radix-ui/react-dialog";
import { ExternalLink, X } from "lucide-react";
import type { BaseServer } from "@/lib/server";
import type { ObservedReputation, ServiceDiscoveryResponse, ServiceLocation } from "@/types/api";

export function ServiceRelaysPanel({ server, response, loading, error, onCheckMore, onClose }: {
  server: BaseServer;
  response?: ServiceDiscoveryResponse;
  loading: boolean;
  error?: string;
  localReputation?: ObservedReputation;
  onCheckMore: () => void;
  onClose: () => void;
}): JSX.Element {
  const discoveredLocations = server.locations?.length ? server.locations
    : response?.services.find((service) => service.name === (server.serviceName ?? "") && service.address.toLowerCase() === server.address?.toLowerCase())?.locations;

  const currentOrigin = typeof window !== "undefined" && window.location.origin ? window.location.origin : "https://localhost";
  const defaultLocalLocation: ServiceLocation = {
    relay_url: currentOrigin,
    url: server.link || (server.dns ? `https://${server.dns}/` : ""),
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
              const targetUrl = loc.url || loc.relay_url;
              const displayText = (loc.url || loc.relay_url).replace(/^https?:\/\//, "").replace(/\/$/, "");
              return (
                <a
                  key={loc.relay_url}
                  href={targetUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center justify-between gap-3 rounded-lg border border-border p-3 text-sm font-medium transition-colors hover:bg-secondary hover:text-primary"
                >
                  <div className="flex min-w-0 items-center gap-2">
                    <span className="truncate font-mono">{displayText}</span>
                    {loc.current_relay && (
                      <span className="shrink-0 rounded bg-primary/10 px-1.5 py-0.5 text-[10px] font-semibold text-primary">
                        Current
                      </span>
                    )}
                  </div>
                  <ExternalLink className="size-4 shrink-0 text-muted-foreground" />
                </a>
              );
            })}

            {!loading && !resolvedLocations.length && (
              <p className="py-4 text-center text-sm text-muted-foreground">
                No relays connected.
              </p>
            )}
          </div>

          {(response?.partial || error) && (
            <button
              type="button"
              disabled={loading}
              onClick={onCheckMore}
              className="mt-4 w-full rounded-lg bg-secondary py-2 text-sm font-medium hover:bg-secondary/80 disabled:opacity-50"
            >
              Check more relays
            </button>
          )}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
