import { useEffect, useId, useMemo, useRef, useState, type ReactNode } from "react";
import { flushSync } from "react-dom";
import { ArrowRight, Check, Copy, ExternalLink, Globe, Search } from "lucide-react";
import { Header } from "@/components/Header";
import { HeroBackdropGraphic, LandingHero } from "@/components/LandingHero";
import { SearchBar } from "@/components/SearchBar";
import { ServerCard } from "@/components/ServerCard";
import { TunnelCommandModal } from "@/components/TunnelCommandModal";
import { useCopy } from "@/hooks/useCopy";
import type { BaseServer } from "@/hooks/useList";
import type { SortOption, StatusFilter } from "@/types/filters";
import { readCurrentOrigin } from "@/hooks/useTunnelCommand";
import { apiClient } from "@/lib/apiClient";
import { RELAY_API_PATHS, ROUTE_PATHS } from "@/lib/apiPaths";
import type { Lease, ReputationVote, DiscoveryResponse, RelayDescriptor, IncompatibleRelayEntry } from "@/types/api";

export interface KnownRelay {
  relayURL: string;
  isCurrent: boolean;
  protocolVersion?: string;
}

const OFFICIAL_REGISTRY_SOURCE_URL =
  "https://raw.githubusercontent.com/gosuda/portal-tunnel/main/registry.json";
const REPOSITORY_URL = "https://github.com/gosuda/portal-tunnel";

// A card fades up the first time it comes into view on this page load; cards
// that return through filters or a remount appear in place.
const revealedServerIds = new Set<string>();
const REVEAL_STAGGER_MS = 70;
const REVEAL_STAGGER_MAX_STEPS = 7;
const REVEAL_KEYFRAMES: Keyframe[] = [
  { opacity: 0, translate: "0 14px" },
  { opacity: 1, translate: "0 0" },
];
// Every named card becomes its own snapshot during a reorder, so an update that
// could render more cards than this happens instantly.
const REORDER_ANIMATION_MAX_CARDS = 60;

function animateReorder(update: () => void, maxCards: number): void {
  if (
    typeof document.startViewTransition !== "function" ||
    maxCards > REORDER_ANIMATION_MAX_CARDS ||
    window.matchMedia("(prefers-reduced-motion: reduce)").matches
  ) {
    update();
    return;
  }
  document.startViewTransition(() => flushSync(update));
}

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

interface LiveAppCardProps {
  serverId: string;
  children: ReactNode;
}

function LiveAppCard({ serverId, children }: LiveAppCardProps) {
  const viewTransitionName = useId();
  // The set changes outside React, so the card reads it once when it mounts.
  const [revealOnView] = useState(() => !revealedServerIds.has(serverId));

  // Off-screen cards skip layout and paint but stay mounted; 174.5px is the
  // card's height until the browser remembers its rendered size.
  return (
    <div
      data-reveal={revealOnView ? serverId : undefined}
      className="[view-transition-class:live-app] [content-visibility:auto] [contain-intrinsic-size:auto_174.5px] print:[content-visibility:visible]"
      style={{ viewTransitionName }}
    >
      {children}
    </div>
  );
}

interface ServerListViewProps {
  title?: string;
  searchQuery: string;
  status: StatusFilter;
  sortBy: SortOption;
  selectedTags: string[];
  availableTags: string[];
  filteredServers: BaseServer[];
  leases: Lease[] | null;
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
  leases,
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
  const [relaySearchQuery, setRelaySearchQuery] = useState("");
  const [showAllLiveApps, setShowAllLiveApps] = useState(false);
  const { copiedKey: copiedRelayURL, copy: copyRelayURL } = useCopy(1500);
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
          await apiClient.get<DiscoveryResponse>(RELAY_API_PATHS.discovery);
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

  const gridRef = useRef<HTMLDivElement>(null);
  const hasActiveFilters =
    searchQuery.trim() !== "" || status !== "all" || selectedTags.length > 0;
  // leases is null before the relay first answers and after a failed poll; an
  // active filter explains an empty list either way.
  const showConnecting = leases === null && !hasActiveFilters;
  const renderedServerIds = filteredServers.map((server) => server.id).join("\n");

  useEffect(() => {
    const pending = gridRef.current?.querySelectorAll<HTMLElement>(
      "[data-reveal]:not([data-revealed])"
    );
    if (!pending?.length) {
      return;
    }

    const animateEntrance = window.matchMedia(
      "(prefers-reduced-motion: no-preference)"
    ).matches;

    const observer = new IntersectionObserver(
      (entries) => {
        entries
          .filter((entry) => entry.isIntersecting)
          .sort(
            (a, b) =>
              a.boundingClientRect.top - b.boundingClientRect.top ||
              a.boundingClientRect.left - b.boundingClientRect.left
          )
          .forEach((entry, order) => {
            const card = entry.target as HTMLElement;
            observer.unobserve(card);
            card.setAttribute("data-revealed", "");
            if (card.dataset.reveal) {
              revealedServerIds.add(card.dataset.reveal);
            }
            if (animateEntrance) {
              card.animate(REVEAL_KEYFRAMES, {
                duration: 460,
                delay: Math.min(order, REVEAL_STAGGER_MAX_STEPS) * REVEAL_STAGGER_MS,
                easing: "cubic-bezier(0.22, 1, 0.36, 1)",
                fill: "backwards",
              });
            }
          });
      },
      { threshold: 0.15 }
    );
    pending.forEach((card) => observer.observe(card));
    return () => observer.disconnect();
  }, [renderedServerIds]);

  const handleToggleFavorite = (serverId: string) =>
    animateReorder(() => onToggleFavorite(serverId), filteredServers.length);
  const handleSortByChange = (value: SortOption) =>
    animateReorder(() => onSortByChange(value), filteredServers.length);
  const handleStatusChange = (value: StatusFilter) =>
    animateReorder(() => onStatusChange(value), leases?.length ?? Infinity);
  const handleTagToggle = (tag: string) =>
    animateReorder(() => onTagToggle(tag), leases?.length ?? Infinity);

  const favoriteIds = useMemo(() => new Set(favorites), [favorites]);
  const paymentAppCount = filteredServers.filter((server) => server.paymentEnabled).length;
  const featuredServers = filteredServers.slice(0, 2);

  const filteredRelays = useMemo(() => {
    const q = relaySearchQuery.trim().toLowerCase();
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
  }, [knownRelays, relayReleases, relaySearchQuery]);

  const searchBar = (
    <SearchBar
      allowRecommendationSort
      searchQuery={searchQuery}
      onSearchChange={onSearchChange}
      status={status}
      onStatusChange={handleStatusChange}
      sortBy={sortBy}
      onSortByChange={handleSortByChange}
      availableTags={availableTags}
      selectedTags={selectedTags}
      onAddTag={handleTagToggle}
      onRemoveTag={handleTagToggle}
    />
  );

  const publicFooter = (
    <footer className="relative w-full bg-background">
      <div
        aria-hidden="true"
        className="pointer-events-none absolute inset-0"
        style={{
          background:
            "radial-gradient(ellipse 340px 48px at 58% 0%, rgb(var(--stage-accent) / calc(0.22 * var(--stage-glow))), transparent 100%)",
        }}
      />
      <div className="relative mx-auto flex w-full max-w-[1437px] flex-col items-center justify-between gap-3 px-4 py-4 sm:flex-row sm:px-6 lg:h-[52px] lg:px-[32px] lg:py-0">
        <div className="flex flex-wrap items-center gap-[15px]">
          <a
            href={ROUTE_PATHS.home}
            className="inline-flex items-center gap-[15px] text-[15.5px] font-extrabold tracking-[0.02em] text-foreground transition-colors hover:text-primary"
          >
            <svg
              xmlns="http://www.w3.org/2000/svg"
              width="17"
              height="26"
              viewBox="0 0 906.26 1457.543"
              className="h-[25px] w-[17px] text-primary drop-shadow-[0_0_6px_rgb(var(--stage-accent)/0.4)]"
            >
              <path
                fill="currentColor"
                d="M254.854 137.158c-34.46 84.407-88.363 149.39-110.934 245.675 90.926-187.569 308.397-483.654 554.729-348.685 135.487 74.216 194.878 270.78 206.058 467.566 21.924 385.996-190.977 853.604-467.585 943.057-174.879 56.543-307.375-86.447-364.527-198.115-176.498-344.82 2.041-910.077 182.259-1109.498zm198.13 7.918C202.61 280.257 4.622 968.542 207.322 1270.414c51.713 77.029 194.535 160.648 285.294 71.318-209.061 31.529-288.389-176.143-301.145-340.765 31.411 147.743 139.396 326.12 309.075 253.588 251.957-107.723 376.778-648.46 269.433-966.817 22.394 134.616 15.572 317.711-47.551 412.087 86.655-230.615 7.903-704.478-269.444-554.749z"
              />
            </svg>
            <span>PORTAL</span>
          </a>
        </div>

        <nav
          aria-label="Footer"
          className="flex flex-wrap items-center gap-x-[32px] gap-y-2 text-[12.5px] font-medium text-foreground/80"
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

  const relayNotice = (message: string) => (
    <div className="mt-[14px] rounded-[8px] border border-border bg-card/90 px-[16px] py-[12px] text-[13px] text-muted-foreground">
      {message}
    </div>
  );

  return (
    <div className="relative flex min-h-screen w-full flex-col overflow-x-hidden bg-background text-foreground">
      <div className="flex h-full grow flex-col">
        <div
          className={`relative w-full border-b border-border bg-linear-to-b from-[rgb(var(--stage-bg))] to-[rgb(var(--stage-bg-edge))] ${
            landingPageEnabled ? "xl:h-[360px]" : "pb-[12px]"
          }`}
        >
          {landingPageEnabled && <HeroBackdropGraphic />}

          <div className="relative z-10 mx-auto w-full max-w-[1437px] px-4 pt-[12px] sm:px-6 lg:px-[32px]">
            <Header title={title} />
          </div>

          {landingPageEnabled && (
            <div className="relative z-10 mx-auto w-full max-w-[1437px] px-4 pt-[24px] pb-8 sm:px-6 lg:px-[32px] xl:pt-[70px] xl:pb-0">
              <LandingHero />
            </div>
          )}
        </div>

        <main className="z-0 flex-1">
          <section
            id="live-servers"
            aria-labelledby="live-servers-title"
            className="scroll-mt-24 border-b border-border bg-muted/40"
          >
            <div className="mx-auto w-full max-w-[1437px] px-4 py-6 sm:px-6 lg:px-[32px] lg:pt-[21px] lg:pb-[19px]">
              <div className="flex flex-col gap-5 xl:flex-row xl:items-start xl:gap-[19px]">
                <div className="flex items-center justify-between gap-4 xl:w-[307px] xl:shrink-0 xl:flex-col xl:items-start">
                  <h2
                    id="live-servers-title"
                    className="text-[30px] font-extrabold leading-none tracking-[-0.01em] text-foreground"
                  >
                    Live apps
                  </h2>
                  {!landingPageEnabled && <TunnelCommandModal />}
                </div>

                {featuredServers.length > 0 ? (
                  <div
                    ref={gridRef}
                    className="grid min-w-0 flex-1 grid-cols-1 gap-[19px] md:grid-cols-2"
                  >
                    {featuredServers.map((server, idx) => (
                      <LiveAppCard key={server.id} serverId={server.id}>
                        <ServerCard
                          server={server}
                          isFavorite={favoriteIds.has(server.id)}
                          onToggleFavorite={handleToggleFavorite}
                          onVote={onVote}
                          action={
                            idx === featuredServers.length - 1 ? (
                              <button
                                type="button"
                                aria-expanded={showAllLiveApps}
                                onClick={(event) => {
                                  event.preventDefault();
                                  event.stopPropagation();
                                  setShowAllLiveApps((prev) => !prev);
                                }}
                                className="pointer-events-auto relative z-30 inline-flex h-[36px] cursor-pointer items-center gap-[8px] rounded-[8px] border border-white/25 bg-black/45 px-[14px] text-[12.5px] font-semibold text-white backdrop-blur-md transition-colors hover:border-white/55"
                              >
                                <span>View all live apps</span>
                                <ArrowRight className="size-[14px]" />
                              </button>
                            ) : undefined
                          }
                        />
                      </LiveAppCard>
                    ))}
                  </div>
                ) : (
                  <div className="flex min-h-[165px] min-w-0 flex-1 items-center justify-center rounded-[12px] border border-dashed border-border px-6 text-center text-[14px] text-muted-foreground">
                    {showConnecting
                      ? "Connecting to relay…"
                      : hasActiveFilters
                        ? "No servers match these filters"
                        : "No apps are live on this relay yet"}
                  </div>
                )}
              </div>

              {(showAllLiveApps || hasActiveFilters) && (
                <div className="mt-6 border-t border-border pt-4">
                  {searchBar}
                  <div className="px-1 pt-3 text-sm text-muted-foreground">
                    {filteredServers.length.toLocaleString()} services visible
                    {paymentAppCount > 0 &&
                      `, including ${paymentAppCount.toLocaleString()} paid app${paymentAppCount === 1 ? "" : "s"}`}
                  </div>
                  {filteredServers.length > 2 && (
                    <div className="mt-4 grid grid-cols-1 gap-5 md:grid-cols-2 lg:grid-cols-3">
                      {filteredServers.slice(2).map((server) => (
                        <LiveAppCard key={server.id} serverId={server.id}>
                          <ServerCard
                            server={server}
                            isFavorite={favoriteIds.has(server.id)}
                            onToggleFavorite={handleToggleFavorite}
                            onVote={onVote}
                          />
                        </LiveAppCard>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          </section>

          <section
            id="public-relays"
            aria-labelledby="public-relays-title"
            className="scroll-mt-24 border-b border-border bg-background"
          >
            <div className="mx-auto w-full max-w-[1437px] px-4 py-6 sm:px-6 lg:px-[32px] lg:pt-[20px] lg:pb-[20px]">
              <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
                <h2
                  id="public-relays-title"
                  className="text-[30px] font-extrabold leading-none tracking-[-0.01em] text-foreground"
                >
                  Public relays
                </h2>

                <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:gap-[18px]">
                  <label className="relative flex h-[44px] w-full items-center rounded-[8px] border border-border bg-card/90 px-[14px] focus-within:border-primary/50 sm:w-[520px]">
                    <Search className="h-[16px] w-[16px] shrink-0 text-muted-foreground" />
                    <input
                      type="text"
                      value={relaySearchQuery}
                      onChange={(event) => setRelaySearchQuery(event.target.value)}
                      placeholder="Search relays by URL or version"
                      aria-label="Search relays"
                      className="h-full w-full bg-transparent pl-[11px] text-[13px] text-foreground placeholder:text-muted-foreground outline-none"
                    />
                  </label>

                  <a
                    href={OFFICIAL_REGISTRY_SOURCE_URL}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex h-[44px] w-full shrink-0 items-center justify-center gap-[8px] whitespace-nowrap rounded-[8px] border border-border bg-card/90 px-[14px] text-[12.5px] font-semibold text-primary transition-colors hover:border-primary/55 sm:w-[158px]"
                  >
                    <span>Open registry.json</span>
                    <ExternalLink className="h-[14px] w-[14px] shrink-0" />
                  </a>
                </div>
              </div>

              {relayDiscoveryLoading ? (
                relayNotice("Loading known relays...")
              ) : knownRelays.length === 0 ? (
                relayNotice("No known relays discovered from this relay.")
              ) : filteredRelays.length === 0 ? (
                relayNotice("No relays match this search.")
              ) : (
                <div className="mt-[14px] grid grid-cols-1 gap-x-[17px] gap-y-[9px] md:grid-cols-2 lg:grid-cols-3">
                  {filteredRelays.map((relay) => {
                    const releaseLabel = relayReleaseLabel(
                      relayReleases.versions,
                      relay,
                      relayReleases.discovery
                    );
                    const isCopied = copiedRelayURL === relay.relayURL;

                    return (
                      <div
                        key={relay.relayURL}
                        className="flex h-[43px] min-w-0 items-center justify-between gap-3 rounded-[8px] border border-border bg-card/90 px-[16px] transition-colors hover:border-primary/40"
                      >
                        <div className="flex min-w-0 flex-1 items-center gap-[14px]">
                          <Globe className="size-[18px] shrink-0 text-muted-foreground" />
                          <a
                            href={relay.relayURL}
                            target="_blank"
                            rel="noopener noreferrer"
                            title={relay.relayURL}
                            className="min-w-0 flex-1 truncate font-mono text-[13px] font-medium text-foreground underline-offset-4 hover:underline"
                          >
                            {relay.relayURL}
                          </a>
                        </div>

                        <div className="flex shrink-0 items-center gap-[18px]">
                          {releaseLabel && (
                            <span className="shrink-0 rounded-[5px] border border-primary/25 bg-primary/10 px-[10px] py-[3px] font-mono text-[11px] font-semibold text-primary">
                              {releaseLabel}
                            </span>
                          )}
                          <button
                            type="button"
                            onClick={() => void copyRelayURL(relay.relayURL, relay.relayURL)}
                            aria-label={`Copy ${relay.relayURL}`}
                            title={isCopied ? "Copied!" : "Copy relay URL"}
                            className="inline-flex cursor-pointer items-center justify-center text-muted-foreground transition-colors hover:text-foreground"
                          >
                            {isCopied ? (
                              <Check className="size-[15px] text-primary" />
                            ) : (
                              <Copy className="size-[15px]" />
                            )}
                          </button>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          </section>
        </main>

        {publicFooter}
      </div>
    </div>
  );
}
