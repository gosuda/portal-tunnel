import { useState } from "react";
import { Check, Copy, ExternalLink, Globe, Search } from "lucide-react";
import { Badge } from "@/components/ui/chip";
import { IconButton } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { relayReleaseLabel, type KnownRelay, type RelayReleases } from "@/lib/relays";

const OFFICIAL_REGISTRY_SOURCE_URL =
  "https://raw.githubusercontent.com/gosuda/portal-tunnel/main/registry.json";

interface PublicRelaysSectionProps {
  knownRelays: KnownRelay[];
  relayReleases: RelayReleases;
  loading: boolean;
  copiedURL: string | null;
  onCopyURL: (key: string, text: string) => void | Promise<void>;
}

export function PublicRelaysSection({
  knownRelays,
  relayReleases,
  loading,
  copiedURL,
  onCopyURL,
}: PublicRelaysSectionProps) {
  const [searchQuery, setSearchQuery] = useState("");
  const { versions, discovery } = relayReleases;
  const latest = discovery?.release_version?.trim() ?? "";

  const q = searchQuery.trim().toLowerCase();
  const rows = knownRelays
    .map((relay) => ({ relay, label: relayReleaseLabel(versions, relay, discovery) }))
    .filter(
      ({ relay, label }) =>
        !q || relay.relayURL.toLowerCase().includes(q) || (label ?? "").toLowerCase().includes(q)
    );

  return (
    <section id="public-relays" aria-labelledby="public-relays-title" className="py-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 id="public-relays-title" className="text-xl font-bold text-content-emphasis">
            Public relays
          </h1>
          <p className="mt-1 text-sm text-content-muted">Explore other relays and the apps they host.</p>
        </div>
        <a
          href={OFFICIAL_REGISTRY_SOURCE_URL}
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex items-center gap-1 text-sm font-semibold text-content-emphasis hover:underline"
        >
          Registry
          <ExternalLink className="size-4" />
        </a>
      </div>

      <div className="relative mt-4 max-w-xl">
        <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-content-muted" />
        <Input
          type="search"
          aria-label="Search relays"
          placeholder="Search by URL or version"
          value={searchQuery}
          onChange={(event) => setSearchQuery(event.target.value)}
          className="pl-9"
        />
      </div>

      {loading ? (
        <div role="status" aria-label="Loading relays" className="mt-4 divide-y divide-stroke border-y border-stroke">
          {[0, 1, 2, 3].map((i) => (
            <div key={i} className="flex h-14 items-center gap-3">
              <div className="size-8 rounded-md bg-surface-200 motion-safe:animate-pulse" />
              <div className="h-4 w-1/2 rounded-sm bg-surface-200 motion-safe:animate-pulse" />
            </div>
          ))}
        </div>
      ) : rows.length === 0 ? (
        <div className="flex flex-col items-center gap-2 py-16 text-center">
          <Globe className="size-10 text-content-muted" />
          <p className="font-semibold text-content-emphasis">No relays found</p>
          <p className="text-sm text-content-muted">Try a different URL or version.</p>
        </div>
      ) : (
        <ul className="mt-4 divide-y divide-stroke border-y border-stroke">
          {rows.map(({ relay, label }) => {
            const isCopied = copiedURL === relay.relayURL;
            const incompatible = relay.protocolVersion !== undefined;
            return (
              <li key={relay.relayURL} className="flex min-h-14 items-center gap-3 py-2">
                <Globe className="size-5 shrink-0 text-content-muted" />
                <div className="min-w-0 flex-1">
                  <a
                    href={relay.relayURL}
                    target="_blank"
                    rel="noopener noreferrer"
                    title={relay.relayURL}
                    className="block truncate text-sm font-semibold text-content-emphasis hover:underline"
                  >
                    {relay.relayURL}
                  </a>
                  <p className="text-xs text-content-muted">{relay.isCurrent ? "Current relay" : "Public relay"}</p>
                </div>
                {incompatible && <Badge tone="danger">Incompatible</Badge>}
                {label && <Badge tone={latest !== "" && label === latest ? "success" : "neutral"}>{label}</Badge>}
                <IconButton
                  aria-label={isCopied ? `Copied ${relay.relayURL}` : `Copy ${relay.relayURL}`}
                  onClick={() => void onCopyURL(relay.relayURL, relay.relayURL)}
                >
                  {isCopied ? <Check className="size-4 text-success" /> : <Copy className="size-4" />}
                </IconButton>
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}
