import { useMemo, useState } from "react";
import { Check, Copy, ExternalLink, Globe, Search } from "lucide-react";
import { relayReleaseLabel, type KnownRelay, type RelayReleases } from "@/lib/relays";

const OFFICIAL_REGISTRY_SOURCE_URL =
  "https://raw.githubusercontent.com/gosuda/portal-tunnel/main/registry.json";

export interface PublicRelaysSectionProps {
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

  const filteredRelays = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    if (!q) {
      return knownRelays;
    }
    return knownRelays.filter((relay) => {
      const label =
        relayReleaseLabel(
          relayReleases.versions,
          relay,
          relayReleases.discovery
        ) ?? "";
      return (
        relay.relayURL.toLowerCase().includes(q) ||
        label.toLowerCase().includes(q)
      );
    });
  }, [knownRelays, relayReleases, searchQuery]);

  return (
    <section id="public-relays" aria-labelledby="public-relays-title" className="px-4 py-6 lg:px-8">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 id="public-relays-title" className="text-2xl font-bold">Public relays</h1>
          <p className="mt-2 text-sm text-muted-foreground">Explore other relays and the apps they host.</p>
        </div>
        <a
          href={OFFICIAL_REGISTRY_SOURCE_URL}
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex items-center gap-2 rounded-full bg-secondary px-4 py-2 text-sm font-medium"
        >
          Registry
          <ExternalLink className="size-4" />
        </a>
      </div>
      <label className="mt-6 flex h-11 max-w-xl items-center gap-3 rounded-full border border-border px-4">
        <Search className="size-4 shrink-0 text-muted-foreground" />
        <input
          type="search"
          aria-label="Search relays"
          placeholder="Search by URL or version"
          value={searchQuery}
          onChange={(event) => setSearchQuery(event.target.value)}
          className="min-w-0 flex-1 bg-transparent text-sm outline-none"
        />
      </label>
      {loading ? (
        <p role="status" className="py-12 text-sm text-muted-foreground">Loading relays...</p>
      ) : filteredRelays.length === 0 ? (
        <p className="py-12 text-sm text-muted-foreground">No relays found.</p>
      ) : (
        <div className="mt-6 grid gap-4 min-[700px]:grid-cols-2 min-[1300px]:grid-cols-3">
          {filteredRelays.map((relay) => {
            const releaseLabel = relayReleaseLabel(relayReleases.versions, relay, relayReleases.discovery);
            const isCopied = copiedURL === relay.relayURL;
            return (
              <article key={relay.relayURL} className="min-w-0 rounded-xl border border-border bg-card/85 p-5 backdrop-blur-sm">
                <Globe className="mb-4 size-8 text-muted-foreground" />
                <a
                  href={relay.relayURL}
                  target="_blank"
                  rel="noopener noreferrer"
                  title={relay.relayURL}
                  className="block truncate text-sm font-semibold hover:underline"
                >
                  {relay.relayURL}
                </a>
                <div className="mt-3 flex items-center justify-between gap-2 text-xs text-muted-foreground">
                  <span>
                    {relay.isCurrent ? "Current relay" : "Public relay"}
                    {releaseLabel ? ` / ${releaseLabel}` : ""}
                  </span>
                  <button
                    type="button"
                    onClick={() => void onCopyURL(relay.relayURL, relay.relayURL)}
                    aria-label={isCopied ? `Copied ${relay.relayURL}` : `Copy ${relay.relayURL}`}
                    className="flex size-8 shrink-0 items-center justify-center rounded-full hover:bg-secondary"
                  >
                    {isCopied ? <Check className="size-4 text-primary" /> : <Copy className="size-4" />}
                  </button>
                </div>
              </article>
            );
          })}
        </div>
      )}
    </section>
  );
}
