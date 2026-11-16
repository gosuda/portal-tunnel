import type { JSX } from "react";
import * as Dialog from "@radix-ui/react-dialog";
import { X } from "lucide-react";
import type { BaseServer } from "@/lib/server";
import type { ObservedReputation, ServiceDiscoveryResponse } from "@/types/api";

function acceptedCounts(reputation?: ObservedReputation): ObservedReputation | undefined {
  if (!reputation || ![reputation.up, reputation.down].every((count) =>
    Number.isSafeInteger(count) && count >= 0 && count <= 0xffffffff)) {
    return undefined;
  }
  return reputation;
}

function countsLabel(reputation: ObservedReputation): string {
  return `${reputation.up.toLocaleString()} up · ${reputation.down.toLocaleString()} down`;
}

export function ServiceRelaysPanel({ server, response, loading, error, localReputation, onCheckMore, onClose }: {
  server: BaseServer;
  response?: ServiceDiscoveryResponse;
  loading: boolean;
  error?: string;
  localReputation?: ObservedReputation;
  onCheckMore: () => void;
  onClose: () => void;
}): JSX.Element {
  const locations = server.locations?.length ? server.locations
    : response?.services.find((service) => service.name === (server.serviceName ?? "") && service.address.toLowerCase() === server.address?.toLowerCase())?.locations;
  const ownCounts = acceptedCounts(localReputation);
  const sources = (locations ?? []).map((location) => ({
    location,
    counts: location.current_relay ? ownCounts : acceptedCounts(location.reputation),
  }));
  const showSeparateLocal = !server.remoteOnly && !sources.some(({ location }) => location.current_relay);
  const reports = sources.map(({ counts }) => counts);
  if (showSeparateLocal) reports.push(ownCounts);
  const totals = { up: 0, down: 0, count: 0 };
  for (const report of reports) {
    if (!report) continue;
    totals.up += report.up;
    totals.down += report.down;
    totals.count++;
  }

  return (
    <Dialog.Root open onOpenChange={(open) => { if (!open) onClose(); }}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-50 bg-black/50 backdrop-blur-sm" />
        <Dialog.Content className="fixed inset-x-0 bottom-0 z-50 max-h-[85vh] overflow-y-auto rounded-t-2xl border border-border bg-background p-6 shadow-xl sm:inset-x-auto sm:bottom-auto sm:left-1/2 sm:top-1/2 sm:w-[min(90vw,36rem)] sm:-translate-x-1/2 sm:-translate-y-1/2 sm:rounded-2xl">
          <Dialog.Title className="pr-8 text-lg font-semibold">Also available via — {server.name}</Dialog.Title>
          <Dialog.Description className="mt-2 text-sm text-muted-foreground">
            Choose an HTTP service URL. Each opens a separate origin; sign-in sessions are not transferred. Candidates are relay-reported, without independent proof of identity or live reachability. TCP/UDP endpoints cannot be opened from this selector.
          </Dialog.Description>
          <Dialog.Close aria-label="Close relay locations" className="absolute right-5 top-5 rounded p-1 hover:bg-secondary"><X className="size-4" /></Dialog.Close>
          {server.link && <a className="mt-4 block break-all text-sm text-primary underline" href={server.link} target="_blank" rel="noopener noreferrer">Open current relay: {server.link}</a>}
          {loading && <p role="status" className="mt-5 text-sm">Checking known relays…</p>}
          {error && <p role="alert" className="mt-5 text-sm">{error}</p>}
          <section aria-label="Observed reputation" className="mt-4 space-y-1 rounded-md border border-border p-3 text-sm">
            <h3 className="font-medium">Observed reputation</h3>
            <p>{totals.count ? `${countsLabel(totals)} across ${totals.count} of ${reports.length} shown relays` : "No reputation counts were observed."}</p>
            <p className="text-xs text-muted-foreground">These are relay-reported counts, not unique voters or a global score. Votes on different relays may be counted more than once.</p>
            {showSeparateLocal && <p className="text-xs">This relay: {ownCounts ? countsLabel(ownCounts) : "reputation not reported"}</p>}
          </section>
          {response && <>
            <p className="mt-4 text-xs text-muted-foreground">{response.relays_checked} directories observed; {response.relays_skipped} unavailable or skipped. {response.partial ? "Partial lookup. " : ""}Other relay locations may exist.</p>
            <ul className="mt-4 space-y-4">
              {sources.map(({ location, counts }) => <li key={location.relay_url} className="space-y-1 border-t border-border pt-3 text-sm">
                <p className="break-all font-medium">{location.relay_url}{location.current_relay ? " · Current relay" : ""}</p>
                <p className="text-xs text-muted-foreground">Relay-reported · {location.reported_ready ? "Reported ready" : "Not reported ready"} · Observed {new Date(location.observed_at).toLocaleString()}</p>
                <p className="text-xs text-muted-foreground">Reputation: {counts ? countsLabel(counts) : "not reported"}</p>
                <p className="text-xs text-muted-foreground">Observation expires {new Date(location.expires_at).toLocaleString()}</p>
                {location.url ? <a className="block break-all text-primary underline" href={location.url} target="_blank" rel="noopener noreferrer">{location.url}</a> : <p className="text-xs text-muted-foreground">No available HTTP URL reported. This selector provides HTTP links only.</p>}
              </li>)}
            </ul>
            {!locations?.length && <p className="mt-4 text-sm">No additional public locations were observed.</p>}
          </>}
          {(response?.partial || error) && <button type="button" disabled={loading} onClick={onCheckMore} className="mt-4 rounded-lg bg-secondary px-4 py-2 text-sm disabled:opacity-50">Check more relays</button>}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
