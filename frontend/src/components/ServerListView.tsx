import { useEffect, useId, useMemo, useRef, useState, type ReactNode } from "react";
import { flushSync } from "react-dom";
import { Check, Copy, ExternalLink, Github, Globe, Search, ShieldCheck, X, Home, ThumbsUp, Menu, BookOpen, Terminal, Plus } from "lucide-react";
import { ThemeToggleButton } from "@/components/ThemeToggleButton";
import { HeroBackdropSVG } from "@/components/DirectoryBackdrop";
import { ServerCard } from "@/components/ServerCard";
import { TunnelCommandModal } from "@/components/TunnelCommandModal";
import { useCopy } from "@/hooks/useCopy";
import type { BaseServer } from "@/hooks/useList";
import type { BrowseView, SortOption, StatusFilter } from "@/types/filters";
import { readCurrentOrigin } from "@/hooks/useTunnelCommand";
import { apiClient } from "@/lib/apiClient";
import { RELAY_API_PATHS, ROUTE_PATHS } from "@/lib/apiPaths";
import type { Lease, DiscoveryResponse, DomainResponse, RelayDescriptor, IncompatibleRelayEntry } from "@/types/api";

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
    (typeof window !== "undefined" && typeof window.matchMedia === "function" && window.matchMedia("(prefers-reduced-motion: reduce)").matches)
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

  // Off-screen cards skip layout and paint but stay mounted; 320px estimates the
  // card's height until the browser remembers its rendered size.
  return (
    <div
      data-reveal={revealOnView ? serverId : undefined}
      className="relative [view-transition-class:live-app] [content-visibility:auto] [contain-intrinsic-size:auto_320px] has-[details[open]]:z-40 has-[details[open]]:[content-visibility:visible] print:[content-visibility:visible]"
      style={{ viewTransitionName }}
    >
      {children}
    </div>
  );
}

interface ServerListViewProps {
  browseView: BrowseView;
  sidebarOpen: boolean;
  onSidebarOpenChange: (open: boolean) => void;
  onBrowseViewChange: (view: BrowseView) => void;
  title?: string;
  searchQuery: string;
  status: StatusFilter;
  sortBy: SortOption;
  selectedTags: string[];
  availableTags: string[];
  filteredServers: BaseServer[];
  leases: Lease[] | null;
  favorites: number;
  showHidden: boolean;
  onShowHiddenChange: (show: boolean) => void;
  hiddenCount: number;
  onSearchChange: (value: string) => void;
  onSortByChange: (value: SortOption) => void;
  onTagToggle: (tag: string) => void;
  onOpenComments: (server: BaseServer) => void;
}

export function ServerListView({
  browseView,
  sidebarOpen,
  onSidebarOpenChange,
  onBrowseViewChange,
  title = "PORTAL",
  searchQuery,
  status,
  sortBy,
  selectedTags,
  availableTags,
  filteredServers,
  leases,
  favorites,
  showHidden,
  onShowHiddenChange,
  hiddenCount,
  onSearchChange,
  onSortByChange,
  onTagToggle,
  onOpenComments,
}: ServerListViewProps) {
  const [relayReleases, setRelayReleases] = useState<{
    versions: Record<string, string>;
    discovery?: DiscoveryResponse;
  }>({ versions: {} });
  const [knownRelays, setKnownRelays] = useState<KnownRelay[]>([]);
  const [releaseVersion, setReleaseVersion] = useState("");
  const [relayDiscoveryLoading, setRelayDiscoveryLoading] = useState(true);
  const [relaySearchQuery, setRelaySearchQuery] = useState("");

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
        const domainPromise = apiClient.get<DomainResponse>(RELAY_API_PATHS.sdk.domain).catch(() => null);
        const discoveryPromise = apiClient.get<DiscoveryResponse>(RELAY_API_PATHS.discovery).catch(() => null);
        const [domain, discovery] = await Promise.all([domainPromise, discoveryPromise]);

        const fetchedVersion =
          (typeof domain?.release_version === "string" && domain.release_version.trim()) ||
          (typeof discovery?.release_version === "string" && discovery.release_version.trim()) ||
          "";
        if (!cancelled && fetchedVersion) {
          setReleaseVersion(fetchedVersion);
        }

        nextKnownRelays = mergeIncompatibleRelays(
          normalizeKnownRelays(discovery?.relays, currentRelayURL),
          discovery?.incompatible_relays,
          currentRelayURL
        );

        const versions: Record<string, string> = {};
        Object.entries(discovery?.relay_release_versions ?? {}).forEach(
          ([url, ver]) => {
            const relayURL = normalizeRelayURL(url);
            const trimmedVersion = ver.trim();
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

    const animateEntrance = typeof window !== "undefined" && typeof window.matchMedia === "function" && window.matchMedia("(prefers-reduced-motion: no-preference)").matches;

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
  }, [renderedServerIds, browseView]);

  const handleTagToggle = (tag: string) =>
    animateReorder(() => onTagToggle(tag), leases?.length ?? Infinity);

  const paymentAppCount = filteredServers.filter((server) => server.paymentEnabled).length;

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

  const isAppView = browseView === "home" || browseView === "favorites";

  return (
    <div className="portal-browser relative isolate min-h-screen text-foreground" onKeyDown={(event) => { if (event.key === "Escape") onSidebarOpenChange(false); }}>
      <div aria-hidden="true" className="pointer-events-none absolute inset-x-0 top-0 -z-10 h-[520px] overflow-hidden [mask-image:linear-gradient(to_bottom,black_50%,transparent)]">
        <div className="absolute inset-x-0 top-0 flex justify-center"><HeroBackdropSVG /></div>
      </div>
      <a href="#portal-content" className="sr-only focus:not-sr-only focus:fixed focus:top-2 focus:left-2 focus:z-[70] focus:rounded-md focus:bg-foreground focus:px-4 focus:py-2 focus:text-background">Skip to content</a>
      <header className="sticky top-0 z-50 grid h-[116px] grid-cols-[1fr_auto] items-center gap-x-4 gap-y-2 border-b border-border bg-background/80 px-4 py-2 backdrop-blur-xl md:h-16 md:grid-cols-[auto_minmax(0,1fr)_auto] md:gap-x-6 lg:px-6">
        <div className="flex items-center gap-3">
          <button type="button" aria-label={sidebarOpen ? "Close navigation" : "Open navigation"} aria-expanded={sidebarOpen} aria-controls="portal-navigation" onClick={() => onSidebarOpenChange(!sidebarOpen)} className="flex size-10 shrink-0 items-center justify-center rounded-full hover:bg-secondary">
            <Menu className="size-5" />
          </button>
          <div className="flex items-center gap-2.5">
            <a href={ROUTE_PATHS.home} aria-label="Portal home" className="inline-flex items-center gap-2 text-xl font-extrabold tracking-tight">
              <svg viewBox="0 0 906.26 1457.543" className="h-8 w-6 text-primary" aria-hidden="true"><path fill="currentColor" d="M254.854 137.158c-34.46 84.407-88.363 149.39-110.934 245.675 90.926-187.569 308.397-483.654 554.729-348.685 135.487 74.216 194.878 270.78 206.058 467.566 21.924 385.996-190.977 853.604-467.585 943.057-174.879 56.543-307.375-86.447-364.527-198.115-176.498-344.82 2.041-910.077 182.259-1109.498zm198.13 7.918C202.61 280.257 4.622 968.542 207.322 1270.414c51.713 77.029 194.535 160.648 285.294 71.318-209.061 31.529-288.389-176.143-301.145-340.765 31.411 147.743 139.396 326.12 309.075 253.588 251.957-107.723 376.778-648.46 269.433-966.817 22.394 134.616 15.572 317.711-47.551 412.087 86.655-230.615 7.903-704.478-269.444-554.749z" /></svg>
              {title}
            </a>
            {releaseVersion && (
              <span className="inline-flex h-6 items-center rounded-md border border-border bg-secondary/85 px-2 font-mono text-[11px] font-semibold text-foreground/80">
                {releaseVersion}
              </span>
            )}
          </div>
        </div>
        <form role="search" onSubmit={(event) => event.preventDefault()} className="order-3 col-span-2 mx-auto flex h-10 w-full max-w-[640px] overflow-hidden rounded-full border border-border focus-within:border-primary md:order-none md:col-span-1">
          <input type="search" aria-label="Search apps" placeholder="Search" value={searchQuery} onChange={(event) => {
            if (!isAppView) onBrowseViewChange("home");
            onSearchChange(event.target.value);
          }} className="min-w-0 flex-1 bg-background pl-5 pr-2 text-base outline-none placeholder:text-muted-foreground" />
          {searchQuery && <button type="button" aria-label="Clear search" onClick={() => onSearchChange("")} className="px-2 hover:bg-secondary"><X className="size-5" /></button>}
          <button type="submit" aria-label="Search" className="flex w-16 shrink-0 items-center justify-center border-l border-border bg-secondary/60 hover:bg-secondary"><Search className="size-5" /></button>
        </form>
        <div className="flex items-center justify-end gap-2 md:col-start-3 md:row-start-1">
          <TunnelCommandModal trigger={<button type="button" className="inline-flex h-9 items-center gap-2 rounded-full bg-secondary px-3 text-sm font-semibold hover:bg-accent"><Plus className="size-5" /><span className="hidden sm:inline">Launch App</span></button>} />
          <ThemeToggleButton className="rounded-full border-0 bg-transparent shadow-none hover:bg-secondary" />
        </div>
      </header>

      {sidebarOpen && <button type="button" aria-label="Close navigation" onClick={() => onSidebarOpenChange(false)} className="fixed inset-x-0 top-[116px] bottom-0 z-40 bg-black/40 md:top-16 lg:hidden" />}
      <aside id="portal-navigation" aria-label="Navigation" className={`fixed top-[116px] bottom-0 left-0 z-40 flex w-[min(240px,calc(100vw-3rem))] flex-col overflow-y-auto border-r border-border bg-background/85 px-3 backdrop-blur-xl pb-6 pt-3 md:top-16 ${sidebarOpen ? "translate-x-0 visible" : "-translate-x-full invisible"}`}>
        <nav aria-label="Browse apps" className="shrink-0 space-y-1">
          <button type="button" aria-current={browseView === "home" && status === "all" && sortBy === "default" ? "page" : undefined} onClick={() => onBrowseViewChange("home")} className="portal-nav-item"><Home className="size-5" /><span>Home</span></button>
          <button type="button" aria-current={browseView === "home" && sortBy === "recommended" ? "page" : undefined} onClick={() => { onBrowseViewChange("home"); onSortByChange("recommended"); }} className="portal-nav-item"><ThumbsUp className="size-5" /><span>Most recommended</span></button>
          <button type="button" aria-current={browseView === "favorites" ? "page" : undefined} onClick={() => onBrowseViewChange("favorites")} className="portal-nav-item"><ThumbsUp className="size-5" /><span>Favorites</span><span className="ml-auto text-xs text-muted-foreground">{favorites}</span></button>
        </nav>
        <nav aria-label="Your apps" className="mt-3 shrink-0 border-t border-border pt-3">
          <p className="px-3 py-2 text-base font-semibold">You</p>
          <TunnelCommandModal trigger={
            <button type="button" aria-label="Launch App" className="portal-nav-item"><Terminal className="size-5" /><span>Launch App</span></button>
          } />
        </nav>
        <nav aria-label="Portal resources" className="mt-3 shrink-0 space-y-1 border-t border-border pt-3">
          <p className="px-3 py-2 text-base font-semibold">Explore Portal</p>
          <button type="button" aria-current={browseView === "relays" ? "page" : undefined} onClick={() => onBrowseViewChange("relays")} className="portal-nav-item"><Globe className="size-5" /><span>Public relays</span></button>
          <a href="https://gosuda.github.io/portal-tunnel" target="_blank" rel="noopener noreferrer" className="portal-nav-item"><BookOpen className="size-5" /><span>Documentation</span></a>
        </nav>
        <div className="mt-auto shrink-0 pt-4">
          <div className="flex items-center gap-4 border-t border-border px-3 pt-5 text-xs text-muted-foreground">
            <a href={REPOSITORY_URL} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1.5 hover:text-foreground"><Github className="size-4" aria-hidden="true" />GitHub</a>
            <a href={ROUTE_PATHS.admin} className="inline-flex items-center gap-1.5 hover:text-foreground"><ShieldCheck className="size-4" aria-hidden="true" />Admin</a>
          </div>
        </div>
      </aside>

      <main id="portal-content" tabIndex={-1} className={`min-w-0 pb-12 outline-none ${sidebarOpen ? "lg:pl-[240px]" : ""}`}>
        {isAppView && (
          <section id="live-servers" aria-label={browseView === "favorites" ? "Favorite apps" : "Discover apps"}>
            <div className="sticky top-[116px] z-30 bg-background/80 px-4 pb-3 pt-2 backdrop-blur-xl md:top-16 lg:px-8">
              <div aria-label="Filter by category" className="flex gap-3 overflow-x-auto [scrollbar-width:none] [&::-webkit-scrollbar]:hidden">
                <button type="button" aria-pressed={selectedTags.length === 0} onClick={() => selectedTags.forEach(onTagToggle)} className={`portal-category ${selectedTags.length === 0 ? "bg-foreground text-background" : "bg-secondary text-foreground"}`}>All</button>
                {availableTags.map((tag) => <button key={tag} type="button" aria-pressed={selectedTags.includes(tag)} onClick={() => handleTagToggle(tag)} className={`portal-category ${selectedTags.includes(tag) ? "bg-foreground text-background" : "bg-secondary text-foreground"}`}>{tag}</button>)}
              </div>
            </div>
            <div className="px-4 lg:px-8">
              <div className="flex flex-wrap items-center justify-between gap-3 py-3">
                <h1 className="text-xl font-bold">
                  {browseView === "favorites" ? "Favorites" : searchQuery.trim() ? `Results for ${searchQuery}` : sortBy === "recommended" ? "Most recommended" : status === "online" ? "Live now" : browseView === "home" ? "Home" : "Discover apps"}
                </h1>
                <p role="status" className="text-xs text-muted-foreground">{showConnecting ? "Connecting to relay..." : `${filteredServers.length.toLocaleString()} apps${paymentAppCount ? ` / ${paymentAppCount} paid` : ""}`}</p>
                {(hiddenCount > 0 || showHidden) && <button type="button" aria-pressed={showHidden} onClick={() => onShowHiddenChange(!showHidden)} className="ml-auto rounded-md px-2 py-1 text-xs text-muted-foreground hover:bg-secondary hover:text-foreground">{showHidden ? "Hide downvoted apps" : `Show hidden apps (${hiddenCount})`}</button>}
              </div>
              {filteredServers.length > 0 ? (
                <div ref={gridRef} className="grid grid-cols-1 gap-x-4 gap-y-10 min-[600px]:grid-cols-2 min-[1150px]:grid-cols-3 min-[1600px]:grid-cols-4 min-[2000px]:grid-cols-5">
                  {filteredServers.map((server) => <LiveAppCard key={server.id} serverId={server.id}><ServerCard server={server} onOpenComments={onOpenComments} /></LiveAppCard>)}
                </div>
              ) : (
                <div className="mx-auto flex min-h-[55vh] max-w-md flex-col items-center justify-center gap-3 px-4 text-center">
                  {browseView === "favorites" ? <ThumbsUp className="mb-2 size-12 text-muted-foreground" /> : <Search className="mb-2 size-12 text-muted-foreground" />}
                  <h2 className="text-xl font-semibold">{showConnecting ? "Finding live apps" : hasActiveFilters ? "No results found" : browseView === "favorites" ? "Keep your favorite apps here" : "No apps are live yet"}</h2>
                  <p className="text-sm leading-6 text-muted-foreground">{showConnecting ? "Waiting for this relay to respond." : hasActiveFilters ? "Try another search or change your filters." : browseView === "favorites" ? "Recommend an app to find it here later." : "Create a tunnel to share your first app."}</p>
                </div>
              )}
            </div>
          </section>
        )}

        {browseView === "relays" && (
          <section id="public-relays" aria-labelledby="public-relays-title" className="px-4 py-6 lg:px-8">
            <div className="flex flex-wrap items-center justify-between gap-4">
              <div><h1 id="public-relays-title" className="text-2xl font-bold">Public relays</h1><p className="mt-2 text-sm text-muted-foreground">Explore other relays and the apps they host.</p></div>
              <a href={OFFICIAL_REGISTRY_SOURCE_URL} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-2 rounded-full bg-secondary px-4 py-2 text-sm font-medium">Registry<ExternalLink className="size-4" /></a>
            </div>
            <label className="mt-6 flex h-11 max-w-xl items-center gap-3 rounded-full border border-border px-4"><Search className="size-4 shrink-0 text-muted-foreground" /><input type="search" aria-label="Search relays" placeholder="Search by URL or version" value={relaySearchQuery} onChange={(event) => setRelaySearchQuery(event.target.value)} className="min-w-0 flex-1 bg-transparent text-sm outline-none" /></label>
            {relayDiscoveryLoading ? <p role="status" className="py-12 text-sm text-muted-foreground">Loading relays...</p> : filteredRelays.length === 0 ? <p className="py-12 text-sm text-muted-foreground">No relays found.</p> : (
              <div className="mt-6 grid gap-4 min-[700px]:grid-cols-2 min-[1300px]:grid-cols-3">
                {filteredRelays.map((relay) => {
                  const releaseLabel = relayReleaseLabel(relayReleases.versions, relay, relayReleases.discovery);
                  const isCopied = copiedRelayURL === relay.relayURL;
                  return (
                    <article key={relay.relayURL} className="min-w-0 rounded-xl border border-border bg-card/85 p-5 backdrop-blur-sm">
                      <Globe className="mb-4 size-8 text-muted-foreground" />
                      <a href={relay.relayURL} target="_blank" rel="noopener noreferrer" title={relay.relayURL} className="block truncate text-sm font-semibold hover:underline">{relay.relayURL}</a>
                      <div className="mt-3 flex items-center justify-between gap-2 text-xs text-muted-foreground"><span>{relay.isCurrent ? "Current relay" : "Public relay"}{releaseLabel ? ` / ${releaseLabel}` : ""}</span><button type="button" onClick={() => void copyRelayURL(relay.relayURL, relay.relayURL)} aria-label={isCopied ? `Copied ${relay.relayURL}` : `Copy ${relay.relayURL}`} className="flex size-8 shrink-0 items-center justify-center rounded-full hover:bg-secondary">{isCopied ? <Check className="size-4 text-primary" /> : <Copy className="size-4" />}</button></div>
                    </article>
                  );
                })}
              </div>
            )}
          </section>
        )}

      </main>
    </div>
  );
}
