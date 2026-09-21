import { useEffect, useMemo, useState } from "react";
import { Header } from "@/components/Header";
import { LandingHero } from "@/components/LandingHero";
import { SearchBar } from "@/components/SearchBar";
import { ServerCard } from "@/components/ServerCard";
import { TunnelCommandModal } from "@/components/TunnelCommandModal";
import type { BaseServer } from "@/hooks/useList";
import type { SortOption, StatusFilter } from "@/types/filters";
import { readCurrentOrigin } from "@/hooks/useTunnelCommand";
import { apiClient } from "@/lib/apiClient";
import { BROWSER_API_PATHS, ROUTE_PATHS } from "@/lib/apiPaths";
import type { ReputationVote, DiscoveryResponse, RelayDescriptor, IncompatibleRelayEntry } from "@/types/api";

export interface KnownRelay {
  relayURL: string;
  isCurrent: boolean;
  protocolVersion?: string;
}

const OFFICIAL_REGISTRY_SOURCE_URL =
  "https://raw.githubusercontent.com/gosuda/portal-tunnel/main/registry.json";
const REPOSITORY_URL = "https://github.com/gosuda/portal-tunnel";

function normalizeRelayURL(relayURL: string | undefined): string {
  return typeof relayURL === "string" ? relayURL.trim() : "";
}

function normalizeKnownRelays(
  relays: RelayDescriptor[] | undefined,
  currentRelayURL: string
): KnownRelay[] {
  const seen = new Set<string>();
  const knownRelays: KnownRelay[] = [];

  relays?.forEach((relay) => {
    const relayURL = normalizeRelayURL(relay.api_https_addr);
    if (relayURL === "" || seen.has(relayURL)) {
      return;
    }

    seen.add(relayURL);
    knownRelays.push({
      relayURL,
      isCurrent: relayURL === currentRelayURL,
    });
  });

  if (currentRelayURL !== "" && !seen.has(currentRelayURL)) {
    knownRelays.push({
      relayURL: currentRelayURL,
      isCurrent: true,
    });
  }

  knownRelays.sort((a, b) => {
    if (a.isCurrent !== b.isCurrent) {
      return a.isCurrent ? -1 : 1;
    }
    return a.relayURL.localeCompare(b.relayURL);
  });

  return knownRelays;
}

export function mergeIncompatibleRelays(
  knownRelays: KnownRelay[],
  incompatible: IncompatibleRelayEntry[] | undefined,
  currentRelayURL: string
): KnownRelay[] {
  if (!incompatible?.length) {
    return knownRelays;
  }

  const seen = new Set(knownRelays.map((relay) => relay.relayURL));
  const merged = [...knownRelays];

  incompatible.forEach((entry) => {
    const relayURL = normalizeRelayURL(entry.url);
    if (relayURL === "" || seen.has(relayURL)) {
      return;
    }
    seen.add(relayURL);
    merged.push({
      relayURL,
      isCurrent: relayURL === currentRelayURL,
      protocolVersion: entry.protocol_version?.trim() || undefined,
    });
  });

  return merged;
}

// Locally observed release metadata: peer versions collected from the serving
// relay's own discovery response, plus the response envelope itself.
export function relayReleaseLabel(
  versions: Record<string, string>,
  relay: KnownRelay,
  discovery?: DiscoveryResponse
): string | null {
  const observed =
    versions[normalizeRelayURL(relay.relayURL)]?.trim() ?? "";
  if (observed !== "") {
    return observed;
  }

  if (relay.isCurrent) {
    const selfRelease =
      typeof discovery?.release_version === "string"
        ? discovery.release_version.trim()
        : "";
    if (selfRelease !== "") {
      return selfRelease;
    }
  }

  const protocolVersion =
    relay.protocolVersion?.trim() ||
    (relay.isCurrent && typeof discovery?.protocol_version === "string"
      ? discovery.protocol_version.trim()
      : "");
  if (protocolVersion !== "") {
    return `discovery ${protocolVersion}`;
  }

  return null;
}

interface ServerListViewProps {
  title?: string;
  searchQuery: string;
  status: StatusFilter;
  sortBy: SortOption;
  selectedTags: string[];
  availableTags: string[];
  filteredServers: BaseServer[];
  favorites: string[];
  onSearchChange: (value: string) => void;
  onStatusChange: (value: StatusFilter) => void;
  onSortByChange: (value: SortOption) => void;
  onTagToggle: (tag: string) => void;
  onToggleFavorite: (serverId: string) => void;
  onVote?: (hostname: string, vote: ReputationVote) => void | Promise<void>;
  landingPageEnabled?: boolean;
}

export function ServerListView({
  title = "PORTAL",
  searchQuery,
  status,
  sortBy,
  selectedTags,
  availableTags,
  filteredServers,
  favorites,
  onSearchChange,
  onStatusChange,
  onSortByChange,
  onTagToggle,
  onToggleFavorite,
  onVote,
  landingPageEnabled = false,
}: ServerListViewProps) {
  const [relayReleases, setRelayReleases] = useState<{
    versions: Record<string, string>;
    discovery?: DiscoveryResponse;
  }>({ versions: {} });
  const [knownRelays, setKnownRelays] = useState<KnownRelay[]>([]);
  const [relayDiscoveryLoading, setRelayDiscoveryLoading] = useState(true);
  const currentRelayURL = useMemo(() => readCurrentOrigin(), []);

  useEffect(() => {
    let cancelled = false;
    setRelayDiscoveryLoading(true);
    setRelayReleases({ versions: {} });
    setKnownRelays([]);

    void (async () => {
      let nextKnownRelays = normalizeKnownRelays(undefined, currentRelayURL);
      let nextReleases: {
        versions: Record<string, string>;
        discovery?: DiscoveryResponse;
      } = { versions: {} };

      try {
        const discovery =
          await apiClient.get<DiscoveryResponse>(BROWSER_API_PATHS.discovery);
        nextKnownRelays = mergeIncompatibleRelays(
          normalizeKnownRelays(discovery?.relays, currentRelayURL),
          discovery?.incompatible_relays,
          currentRelayURL
        );

        const versions: Record<string, string> = {};
        Object.entries(discovery?.relay_release_versions ?? {}).forEach(
          ([url, releaseVersion]) => {
            const relayURL = normalizeRelayURL(url);
            const trimmedVersion = releaseVersion.trim();
            if (relayURL !== "" && trimmedVersion !== "") {
              versions[relayURL] = trimmedVersion;
            }
          }
        );
        nextReleases = {
          versions,
          discovery: {
            release_version: discovery?.release_version,
            protocol_version: discovery?.protocol_version,
          },
        };
      } catch {
        // Keep the current relay fallback when discovery is unavailable.
      }

      if (cancelled) {
        return;
      }

      setKnownRelays(nextKnownRelays);
      setRelayReleases(nextReleases);
      setRelayDiscoveryLoading(false);
    })();

    return () => {
      cancelled = true;
    };
  }, [currentRelayURL]);

  const favoriteIds = useMemo(() => new Set(favorites), [favorites]);
  const paymentAppCount = filteredServers.filter((server) => server.paymentEnabled).length;
  const serverGrid = filteredServers.length > 0 ? (
    <div className="grid grid-cols-1 gap-6 py-4 min-[500px]:py-6 min-[500px]:grid-cols-2 md:grid-cols-3">
      {filteredServers.map((server) => (
        <ServerCard
          key={server.id}
          server={server}
          isFavorite={favoriteIds.has(server.id)}
          onToggleFavorite={onToggleFavorite}
          onVote={onVote}
        />
      ))}
    </div>
  ) : null;
  const noMatchingServersMessage = (
    <p className="text-lg text-text-muted">No servers match these filters</p>
  );

  const searchBar = (
    <SearchBar
      searchQuery={searchQuery}
      onSearchChange={onSearchChange}
      status={status}
      onStatusChange={onStatusChange}
      sortBy={sortBy}
      onSortByChange={onSortByChange}
      availableTags={availableTags}
      selectedTags={selectedTags}
      onAddTag={onTagToggle}
      onRemoveTag={onTagToggle}
    />
  );
  const publicFooter = (
    <footer className="w-full bg-secondary/35">
      <div className="flex w-full flex-col gap-6 px-6 py-8 sm:px-8 md:flex-row md:items-end md:justify-between lg:px-10">
        <div className="space-y-1.5">
          <a
            href={ROUTE_PATHS.home}
            className="inline-block text-lg font-bold tracking-normal text-foreground transition-colors hover:text-primary"
          >
            PORTAL
          </a>
          <p className="text-sm text-text-muted">
            Public relay index and localhost tunnel launcher.
          </p>
        </div>

        <nav
          aria-label="Footer"
          className="flex flex-wrap items-center gap-x-6 gap-y-2 text-sm text-text-muted md:justify-end"
        >
          <a href={ROUTE_PATHS.admin} className="transition-colors hover:text-foreground">
            Admin
          </a>
          <a
            href={REPOSITORY_URL}
            target="_blank"
            rel="noopener noreferrer"
            className="transition-colors hover:text-foreground"
          >
            Source
          </a>
        </nav>
      </div>
    </footer>
  );

  return (
    <div className="relative flex h-auto min-h-screen w-full flex-col">
      <div className="flex h-full grow flex-col">
        <div className="sticky top-0 z-20 w-full bg-background/95 py-5 backdrop-blur supports-backdrop-filter:bg-background/80">
          <div className="flex w-full flex-col px-6 sm:px-8 lg:px-10">
            <Header
              title={title}
              showQuickStartLink={landingPageEnabled}
            />
          </div>
        </div>
        <div className="mx-auto flex w-full max-w-6xl flex-1 flex-col border-x border-border/80">
          <main className="z-0 flex-1 pb-14">
            {landingPageEnabled && (
              <section className="border-b border-border/80 px-4 pt-6 pb-8 sm:px-6 sm:pb-10 md:px-8">
                <LandingHero />
              </section>
            )}
            <section
              id="live-servers"
              aria-labelledby="live-servers-title"
              className="scroll-mt-24 min-h-136 border-b border-border/80 px-4 py-8 sm:min-h-144 sm:px-6 md:px-8"
            >
              <div className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
                <div className="space-y-2">
                  <p className="text-sm font-semibold uppercase tracking-normal text-primary">
                    Live apps
                  </p>
                  <h2
                    id="live-servers-title"
                    className="text-3xl font-semibold tracking-normal text-foreground"
                  >
                    Browse live apps
                  </h2>
                </div>
                <TunnelCommandModal />
              </div>

              {filteredServers.length > 0 ? (
                <div className="mt-6">
                  {searchBar}
                  <div className="px-1 pt-3 text-sm text-text-muted">
                    {filteredServers.length.toLocaleString()} services visible
                    {paymentAppCount > 0 &&
                      `, including ${paymentAppCount.toLocaleString()} paid app${paymentAppCount === 1 ? "" : "s"
                      }`}
                  </div>
                  {serverGrid}
                </div>
              ) : (
                <div className="mt-6 flex min-h-88 flex-col">
                  {searchBar}
                  <div className="px-1 pt-3 text-sm text-text-muted">
                    0 services visible
                  </div>
                  <div className="flex flex-1 items-center justify-center py-12 text-center">
                    {noMatchingServersMessage}
                  </div>
                </div>
              )}
            </section>

            <section
              id="public-relays"
              aria-labelledby="public-relays-title"
              className="scroll-mt-24 px-4 py-8 sm:px-6 md:px-8"
            >
              <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
                <div className="space-y-2">
                  <p className="text-sm font-semibold uppercase tracking-normal text-primary">
                    Relays
                  </p>
                  <h2
                    id="public-relays-title"
                    className="text-3xl font-semibold tracking-normal text-foreground"
                  >
                    Public relays
                  </h2>
                </div>
                <a
                  href={OFFICIAL_REGISTRY_SOURCE_URL}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex h-10 items-center justify-center rounded-md bg-primary/10 px-4 text-sm font-semibold text-primary transition-colors hover:bg-primary/16"
                >
                  Open registry.json
                </a>
              </div>

              <div className="mt-6 rounded-lg border border-border/80 bg-secondary/25 p-5 sm:p-6">
                {relayDiscoveryLoading ? (
                  <div className="rounded-md border border-border/70 bg-background px-4 py-3 text-sm text-text-muted">
                    Loading known relays...
                  </div>
                ) : knownRelays.length === 0 ? (
                  <div className="rounded-md border border-border/70 bg-background px-4 py-3 text-sm text-text-muted">
                    No known relays discovered from this relay.
                  </div>
                ) : (
                  <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3">
                    {knownRelays.map((relay) => {
                      const releaseLabel = relayReleaseLabel(
                        relayReleases.versions,
                        relay,
                        relayReleases.discovery
                      );

                      return (
                        <div
                          key={relay.relayURL}
                          className="flex min-w-0 items-center justify-between gap-3 rounded-md border border-border/70 bg-background px-4 py-3"
                        >
                          <a
                            href={relay.relayURL}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="min-w-0 flex-1 overflow-hidden text-ellipsis whitespace-nowrap font-mono text-[13px] text-foreground underline-offset-4 hover:underline sm:text-sm"
                          >
                            {relay.relayURL}
                          </a>
                          {releaseLabel && (
                            <span className="shrink-0 rounded-sm bg-secondary/70 px-2.5 py-1 font-mono text-[11px] font-medium text-text-muted ring-1 ring-border">
                              {releaseLabel}
                            </span>
                          )}
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            </section>
          </main>
        </div>
        {publicFooter}
      </div>
    </div>
  );
}
