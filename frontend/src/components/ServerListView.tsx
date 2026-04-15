import { useEffect, useMemo, useState } from "react";
import { Header } from "@/components/Header";
import { LandingHero } from "@/components/LandingHero";
import { SearchBar } from "@/components/SearchBar";
import { ServerCard } from "@/components/ServerCard";
import { TagCombobox } from "@/components/TagCombobox";
import { TunnelCommandModal } from "@/components/TunnelCommandModal";
import type { ClientServer } from "@/hooks/useServerList";
import type { AdminServer, ApprovalMode, UDPSettings, TCPPortSettings } from "@/hooks/useAdmin";
import type { SortOption, StatusFilter } from "@/types/filters";
import { StatusSelect } from "@/components/select/StatusSelect";
import { BanStatusButtons } from "@/components/button/BanStatusButtons";
import { SortbySelect } from "@/components/select/SortbySelect";
import { ApprovalModeToggle } from "@/components/button/ApprovalModeToggle";
import { FloatingActionBar } from "@/components/FloatingActionBar";
import { readCurrentOrigin } from "@/hooks/useTunnelCommand";
import { apiClient } from "@/lib/apiClient";
import { API_PATHS, ROUTE_PATHS } from "@/lib/apiPaths";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";

export type BanFilter = "all" | "banned" | "active";
type ListServer = ClientServer | AdminServer;

interface RelayDomainResponse {
  release_version?: string;
}

interface RelayDiscoveryDescriptor {
  api_https_addr?: string;
}

interface RelayDiscoveryResponse {
  relays?: RelayDiscoveryDescriptor[];
}

interface KnownRelay {
  relayURL: string;
  isCurrent: boolean;
}

const OFFICIAL_REGISTRY_SOURCE_URL =
  "https://raw.githubusercontent.com/gosuda/portal-tunnel/main/registry.json";
const REPOSITORY_URL = "https://github.com/gosuda/portal-tunnel";

async function loadRelayReleaseVersion(
  relayURL: string,
  timeoutMs: number = 5000
): Promise<string> {
  const domainURL = new URL(API_PATHS.sdk.domain, relayURL).toString();

  const timeoutPromise = new Promise<never>((_, reject) => {
    setTimeout(() => reject(new Error("timeout")), timeoutMs);
  });

  try {
    const domain = await Promise.race([
      apiClient.get<RelayDomainResponse>(domainURL),
      timeoutPromise,
    ]);
    return typeof domain?.release_version === "string"
      ? domain.release_version.trim()
      : "";
  } catch {
    return "";
  }
}

function normalizeRelayURL(relayURL: string | undefined): string {
  return typeof relayURL === "string" ? relayURL.trim() : "";
}

function normalizeKnownRelays(
  relays: RelayDiscoveryDescriptor[] | undefined,
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

interface ServerListViewProps {
  title?: string;
  searchQuery: string;
  status: StatusFilter;
  sortBy: SortOption;
  selectedTags: string[];
  availableTags: string[];
  filteredServers: ClientServer[] | AdminServer[];
  favorites: string[];
  onSearchChange: (value: string) => void;
  onStatusChange: (value: StatusFilter) => void;
  onSortByChange: (value: SortOption) => void;
  onTagToggle: (tag: string) => void;
  onToggleFavorite: (serverId: string) => void;
  isAdmin?: boolean;
  banFilter?: BanFilter;
  approvalMode?: ApprovalMode;
  landingPageEnabled?: boolean;
  onBanFilterChange?: (value: BanFilter) => void;
  onBanStatusChange?: (
    identityKey: string,
    isBan: boolean
  ) => void | Promise<void>;
  onBPSChange?: (identityKey: string, bps: number) => void | Promise<void>;
  onApprovalModeChange?: (mode: ApprovalMode) => void;
  onLandingPageEnabledChange?: (enabled: boolean) => void | Promise<void>;
  udpSettings?: UDPSettings;
  onUDPSettingsChange?: (settings: UDPSettings) => void | Promise<void>;
  tcpPortSettings?: TCPPortSettings;
  onTCPPortSettingsChange?: (settings: TCPPortSettings) => void | Promise<void>;
  onApproveStatusChange?: (
    identityKey: string,
    approve: boolean
  ) => void | Promise<void>;
  onDenyStatusChange?: (
    identityKey: string,
    deny: boolean
  ) => void | Promise<void>;
  onIPBanStatusChange?: (ip: string, isBan: boolean) => void | Promise<void>;
  onBulkApprove?: (identityKeys: string[]) => void | Promise<void>;
  onBulkDeny?: (identityKeys: string[]) => void | Promise<void>;
  onBulkBan?: (identityKeys: string[]) => void | Promise<void>;
  onLogout?: () => void;
}

function isAdminServer(server: ListServer): server is AdminServer {
  return "address" in server;
}

function toAdminServer(server: ListServer): AdminServer | undefined {
  return isAdminServer(server) ? server : undefined;
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
  isAdmin = false,
  banFilter = "all",
  approvalMode = "auto",
  landingPageEnabled = true,
  onBanFilterChange,
  onBanStatusChange,
  onBPSChange,
  onApprovalModeChange,
  onLandingPageEnabledChange,
  udpSettings,
  onUDPSettingsChange,
  tcpPortSettings,
  onTCPPortSettingsChange,
  onApproveStatusChange,
  onDenyStatusChange,
  onIPBanStatusChange,
  onBulkApprove,
  onBulkDeny,
  onBulkBan,
  onLogout,
}: ServerListViewProps) {
  const [showFilterModal, setShowFilterModal] = useState(false);
  const [relayReleaseVersions, setRelayReleaseVersions] = useState<
    Record<string, string>
  >({});
  const [knownRelays, setKnownRelays] = useState<KnownRelay[]>([]);
  const [relayDiscoveryLoading, setRelayDiscoveryLoading] = useState(
    () => !isAdmin
  );
  const [relayDiscoveryMessage, setRelayDiscoveryMessage] = useState("");
  const [selectedIdentityKeys, setSelectedIdentityKeys] = useState<Set<string>>(
    new Set()
  );
  const serverItems = filteredServers as ListServer[];
  const favoriteIds = useMemo(() => new Set(favorites), [favorites]);
  const showLandingHero = !isAdmin && landingPageEnabled;
  const currentRelayURL = useMemo(() => readCurrentOrigin(), []);

  const handleToggleSelect = (identityKey: string) => {
    setSelectedIdentityKeys((prev) => {
      const next = new Set(prev);
      if (next.has(identityKey)) {
        next.delete(identityKey);
      } else {
        next.add(identityKey);
      }
      return next;
    });
  };

  const handleClearSelection = () => {
    setSelectedIdentityKeys(new Set());
  };

  const serverRows = useMemo(
    () =>
      serverItems.map((server) => ({
        server,
        adminServer: toAdminServer(server),
      })),
    [serverItems]
  );

  const allIdentityKeys = useMemo(
    () => [
      ...new Set(
        serverRows
          .map(({ adminServer }) => adminServer?.identityKey)
          .filter(
            (identityKey): identityKey is string =>
              typeof identityKey === "string" && identityKey.trim().length > 0
          )
      ),
    ],
    [serverRows]
  );

  useEffect(() => {
    const validIdentityKeys = new Set(allIdentityKeys);
    setSelectedIdentityKeys((prev) => {
      if (prev.size === 0) {
        return prev;
      }

      const next = new Set<string>();
      prev.forEach((identityKey) => {
        if (validIdentityKeys.has(identityKey)) {
          next.add(identityKey);
        }
      });

      if (next.size === prev.size) {
        return prev;
      }

      return next;
    });
  }, [allIdentityKeys]);

  useEffect(() => {
    if (isAdmin) {
      return;
    }
    setSelectedIdentityKeys((prev) => (prev.size === 0 ? prev : new Set()));
  }, [isAdmin]);

  useEffect(() => {
    if (isAdmin) {
      return;
    }
    let cancelled = false;
    setRelayDiscoveryLoading(true);
    setRelayReleaseVersions({});
    setKnownRelays([]);
    setRelayDiscoveryMessage("");

    void (async () => {
      let discoveryMessage = "";
      let nextKnownRelays = normalizeKnownRelays(undefined, currentRelayURL);

      try {
        const discovery =
          await apiClient.get<RelayDiscoveryResponse>(API_PATHS.discovery);
        nextKnownRelays = normalizeKnownRelays(
          discovery?.relays,
          currentRelayURL
        );
      } catch {
        discoveryMessage = "Known relay data is unavailable on this relay.";
      }

      const relayURLs = nextKnownRelays.map((relay) => relay.relayURL);
      const uniqueRelayURLs = [...new Set(relayURLs)];
      const versions = await Promise.all(
        uniqueRelayURLs.map(async (relayURL) => [
          relayURL,
          await loadRelayReleaseVersion(relayURL),
        ] as const)
      );

      if (cancelled) {
        return;
      }

      setRelayReleaseVersions(Object.fromEntries(versions));
      setKnownRelays(nextKnownRelays);
      setRelayDiscoveryLoading(false);
      setRelayDiscoveryMessage(discoveryMessage);
    })();

    return () => {
      cancelled = true;
    };
  }, [currentRelayURL, isAdmin]);
  const isAllSelected =
    allIdentityKeys.length > 0 &&
    allIdentityKeys.every((identityKey) => selectedIdentityKeys.has(identityKey));

  const handleSelectAll = () => {
    if (isAllSelected) {
      setSelectedIdentityKeys(new Set());
    } else {
      setSelectedIdentityKeys(new Set(allIdentityKeys));
    }
  };

  const runBulkAction = async (
    handler?: (identityKeys: string[]) => void | Promise<void>
  ) => {
    if (!handler || selectedIdentityKeys.size === 0) {
      return;
    }

    try {
      await handler(Array.from(selectedIdentityKeys));
      handleClearSelection();
    } catch (err) {
      console.error("Failed bulk admin action", err);
    }
  };

  const handleBulkApprove = () => {
    void runBulkAction(onBulkApprove);
  };
  const handleBulkDeny = () => {
    void runBulkAction(onBulkDeny);
  };
  const handleBulkBan = () => {
    void runBulkAction(onBulkBan);
  };

  const [maxLeasesInput, setMaxLeasesInput] = useState(
    String(udpSettings?.maxLeases ?? 0)
  );
  const [tcpPortMaxLeasesInput, setTCPPortMaxLeasesInput] = useState(
    String(tcpPortSettings?.maxLeases ?? 0)
  );

  useEffect(() => {
    setMaxLeasesInput(String(udpSettings?.maxLeases ?? 0));
  }, [udpSettings?.maxLeases]);

  useEffect(() => {
    setTCPPortMaxLeasesInput(String(tcpPortSettings?.maxLeases ?? 0));
  }, [tcpPortSettings?.maxLeases]);

  const handleUDPToggle = (enabled: boolean) => {
    if (onUDPSettingsChange && udpSettings) {
      void onUDPSettingsChange({ ...udpSettings, enabled });
    }
  };

  const handleTCPPortToggle = (enabled: boolean) => {
    if (onTCPPortSettingsChange && tcpPortSettings) {
      void onTCPPortSettingsChange({ ...tcpPortSettings, enabled });
    }
  };

  const handleLandingPageToggle = (enabled: boolean) => {
    if (onLandingPageEnabledChange) {
      void onLandingPageEnabledChange(enabled);
    }
  };

  const handleMaxLeasesSave = () => {
    if (onUDPSettingsChange && udpSettings) {
      const value = Math.max(0, parseInt(maxLeasesInput, 10) || 0);
      setMaxLeasesInput(String(value));
      void onUDPSettingsChange({ ...udpSettings, maxLeases: value });
    }
  };

  const handleTCPPortMaxLeasesSave = () => {
    if (onTCPPortSettingsChange && tcpPortSettings) {
      const value = Math.max(0, parseInt(tcpPortMaxLeasesInput, 10) || 0);
      setTCPPortMaxLeasesInput(String(value));
      void onTCPPortSettingsChange({ ...tcpPortSettings, maxLeases: value });
    }
  };

  const adminFilterControls = (
    <>
      {onBanFilterChange && (
        <div className="flex items-center gap-3">
          <span className="text-sm font-medium text-text-muted">
            Ban Status
          </span>
          <BanStatusButtons
            banFilter={banFilter}
            onBanFilterChange={onBanFilterChange}
          />
        </div>
      )}
      {onApprovalModeChange && (
        <div className="flex items-center gap-3">
          <span className="text-sm font-medium text-text-muted">Approval</span>
          <ApprovalModeToggle
            approvalMode={approvalMode}
            onApprovalModeChange={onApprovalModeChange}
          />
        </div>
      )}
      {onLandingPageEnabledChange && (
        <div className="flex items-center gap-3">
          <span className="text-sm font-medium text-text-muted">Landing</span>
          <div className="flex overflow-hidden rounded-lg border border-foreground/20">
            <button
              onClick={() => handleLandingPageToggle(true)}
              className={`cursor-pointer px-4 h-10 text-sm font-medium transition-colors ${
                landingPageEnabled
                  ? "bg-primary text-primary-foreground"
                  : "bg-secondary text-secondary-foreground hover:bg-secondary/80"
              }`}
            >
              Shown
            </button>
            <button
              onClick={() => handleLandingPageToggle(false)}
              className={`cursor-pointer border-l border-foreground/20 px-4 h-10 text-sm font-medium transition-colors ${
                !landingPageEnabled
                  ? "bg-primary text-primary-foreground"
                  : "bg-secondary text-secondary-foreground hover:bg-secondary/80"
              }`}
            >
              Hidden
            </button>
          </div>
        </div>
      )}
      {onUDPSettingsChange && udpSettings && (
        <>
          <div className="flex items-center gap-3">
            <span className="text-sm font-medium text-text-muted">UDP</span>
            <div className="flex rounded-lg overflow-hidden border border-foreground/20">
              <button
                onClick={() => handleUDPToggle(false)}
                className={`cursor-pointer px-4 h-10 text-sm font-medium transition-colors ${
                  !udpSettings.enabled
                    ? "bg-primary text-primary-foreground"
                    : "bg-secondary text-secondary-foreground hover:bg-secondary/80"
                }`}
              >
                Disabled
              </button>
              <button
                onClick={() => handleUDPToggle(true)}
                className={`cursor-pointer px-4 h-10 text-sm font-medium transition-colors border-l border-foreground/20 ${
                  udpSettings.enabled
                    ? "bg-primary text-primary-foreground"
                    : "bg-secondary text-secondary-foreground hover:bg-secondary/80"
                }`}
              >
                Enabled
              </button>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <span className="text-sm font-medium text-text-muted">Max UDP</span>
            <div className="flex items-center gap-2">
              <input
                type="number"
                min="0"
                value={maxLeasesInput}
                onChange={(e) => setMaxLeasesInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") handleMaxLeasesSave();
                }}
                className="w-20 h-10 px-3 text-sm border border-foreground/20 rounded-lg bg-secondary text-foreground"
                placeholder="0"
              />
              <button
                onClick={handleMaxLeasesSave}
                className="cursor-pointer h-10 px-4 text-sm font-medium rounded-lg bg-primary text-primary-foreground hover:bg-primary/90 transition-colors"
              >
                Save
              </button>
            </div>
          </div>
        </>
      )}
      {onTCPPortSettingsChange && tcpPortSettings && (
        <>
          <div className="flex items-center gap-3">
            <span className="text-sm font-medium text-text-muted">TCP</span>
            <div className="flex rounded-lg overflow-hidden border border-foreground/20">
              <button
                onClick={() => handleTCPPortToggle(false)}
                className={`cursor-pointer px-4 h-10 text-sm font-medium transition-colors ${
                  !tcpPortSettings.enabled
                    ? "bg-primary text-primary-foreground"
                    : "bg-secondary text-secondary-foreground hover:bg-secondary/80"
                }`}
              >
                Disabled
              </button>
              <button
                onClick={() => handleTCPPortToggle(true)}
                className={`cursor-pointer px-4 h-10 text-sm font-medium transition-colors border-l border-foreground/20 ${
                  tcpPortSettings.enabled
                    ? "bg-primary text-primary-foreground"
                    : "bg-secondary text-secondary-foreground hover:bg-secondary/80"
                }`}
              >
                Enabled
              </button>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <span className="text-sm font-medium text-text-muted">Max TCP</span>
            <div className="flex items-center gap-2">
              <input
                type="number"
                min="0"
                value={tcpPortMaxLeasesInput}
                onChange={(e) => setTCPPortMaxLeasesInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") handleTCPPortMaxLeasesSave();
                }}
                className="w-20 h-10 px-3 text-sm border border-foreground/20 rounded-lg bg-secondary text-foreground"
                placeholder="0"
              />
              <button
                onClick={handleTCPPortMaxLeasesSave}
                className="cursor-pointer h-10 px-4 text-sm font-medium rounded-lg bg-primary text-primary-foreground hover:bg-primary/90 transition-colors"
              >
                Save
              </button>
            </div>
          </div>
        </>
      )}
    </>
  );

  const renderServerCard = ({
    server,
    adminServer,
  }: {
    server: ListServer;
    adminServer?: AdminServer;
  }) => {
    const isSelected = adminServer
      ? selectedIdentityKeys.has(adminServer.identityKey)
      : false;

    return (
      <ServerCard
        key={server.id}
        serverId={server.id}
        name={server.name}
        description={server.description}
        tags={server.tags}
        thumbnail={server.thumbnail}
        owner={server.owner}
        online={server.online}
        dns={server.dns}
        navigationPath={server.link || "#"}
        navigationState={{
          id: server.id,
          name: server.name,
          description: server.description,
          tags: server.tags,
          thumbnail: server.thumbnail,
          owner: server.owner,
          online: server.online,
          serverUrl: server.link,
        }}
        firstSeen={server.firstSeen}
        isFavorite={favoriteIds.has(server.id)}
        onToggleFavorite={onToggleFavorite}
        showAdminControls={isAdmin && !!adminServer}
        identityKey={adminServer?.identityKey}
        address={adminServer?.address}
        isBanned={adminServer?.isBanned}
        isApproved={adminServer?.isApproved}
        isDenied={adminServer?.isDenied}
        bps={adminServer?.bps}
        ip={adminServer?.ip}
        displayIP={adminServer?.displayIP}
        isIPBanned={adminServer?.isIPBanned}
        onBanStatusChange={onBanStatusChange}
        onBPSChange={onBPSChange}
        onApproveStatusChange={onApproveStatusChange}
        onDenyStatusChange={onDenyStatusChange}
        onIPBanStatusChange={onIPBanStatusChange}
        isSelected={isSelected}
        onToggleSelect={handleToggleSelect}
      />
    );
  };

  const gridClasses =
    `grid grid-cols-1 gap-6 ${isAdmin ? "p-4 min-[500px]:p-6" : "py-4 min-[500px]:py-6"} min-[500px]:grid-cols-2 md:grid-cols-3`;
  const serverCards = serverRows.map(renderServerCard);
  const serverGrid =
    serverCards.length > 0 ? (
      <div className={gridClasses}>{serverCards}</div>
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
      hideFiltersOnMobile={isAdmin}
      setShowFilterModal={isAdmin ? setShowFilterModal : undefined}
    />
  );
  const publicFooter = (
    <footer className="w-full bg-secondary/35">
      <div className="flex w-full flex-col gap-6 px-6 py-8 sm:px-8 md:flex-row md:items-end md:justify-between lg:px-10">
        <div className="space-y-1.5">
          <a
            href={ROUTE_PATHS.home}
            className="inline-block text-lg font-bold tracking-tight text-foreground transition-colors hover:text-primary"
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
        {isAdmin ? (
          <>
            <div className="sticky top-0 z-10 w-full bg-background pb-4 pt-5">
              <div className="flex w-full flex-col px-4 sm:px-6 lg:px-8">
                <Header title={title} isAdmin={isAdmin} onLogout={onLogout} />
                <div className="flex items-center gap-2">
                  <div className="flex-1">{searchBar}</div>
                </div>
                <div className="mt-4 hidden flex-wrap items-center gap-6 sm:flex">
                  {adminFilterControls}
                </div>
                {onApprovalModeChange && (
                  <div className="mt-4 flex items-center gap-3 sm:hidden">
                    <span className="text-sm font-medium text-text-muted">
                      Approval
                    </span>
                    <ApprovalModeToggle
                      approvalMode={approvalMode}
                      onApprovalModeChange={onApprovalModeChange}
                    />
                  </div>
                )}
              </div>
              {onLandingPageEnabledChange && (
                <div className="mt-4 flex items-center gap-3 px-4 sm:hidden">
                  <span className="text-sm font-medium text-text-muted">
                    Landing
                  </span>
                  <div className="flex overflow-hidden rounded-lg border border-foreground/20">
                    <button
                      onClick={() => handleLandingPageToggle(true)}
                      className={`cursor-pointer px-4 h-10 text-sm font-medium transition-colors ${
                        landingPageEnabled
                          ? "bg-primary text-primary-foreground"
                          : "bg-secondary text-secondary-foreground hover:bg-secondary/80"
                      }`}
                    >
                      Shown
                    </button>
                    <button
                      onClick={() => handleLandingPageToggle(false)}
                      className={`cursor-pointer border-l border-foreground/20 px-4 h-10 text-sm font-medium transition-colors ${
                        !landingPageEnabled
                          ? "bg-primary text-primary-foreground"
                          : "bg-secondary text-secondary-foreground hover:bg-secondary/80"
                      }`}
                    >
                      Hidden
                    </button>
                  </div>
                </div>
              )}
            </div>
            <div className="mx-auto flex w-full max-w-6xl flex-1 flex-col px-0">
              <main className="z-0 flex-1">
                {serverGrid ?? (
                  <div className="py-12 text-center">
                    {noMatchingServersMessage}
                  </div>
                )}
              </main>
            </div>
          </>
        ) : (
          <>
            <div className="sticky top-0 z-20 w-full bg-background/95 py-5 backdrop-blur supports-backdrop-filter:bg-background/80">
              <div className="flex w-full flex-col px-6 sm:px-8 lg:px-10">
                <Header
                  title={title}
                  isAdmin={isAdmin}
                  onLogout={onLogout}
                  showQuickStartLink={landingPageEnabled}
                />
              </div>
            </div>
            <div className="mx-auto flex w-full max-w-6xl flex-1 flex-col border-x border-border/80">
              <main className="z-0 flex-1 pb-14">
                {showLandingHero && (
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
                      <p className="text-sm font-semibold uppercase tracking-[0.3em] text-primary">
                        Live apps
                      </p>
                      <h2
                        id="live-servers-title"
                        className="text-3xl font-semibold tracking-tight text-foreground"
                      >
                        Browse live apps
                      </h2>
                    </div>
                    <TunnelCommandModal />
                  </div>

                  {serverRows.length > 0 ? (
                    <div className="mt-6">
                      {searchBar}
                      <div className="px-1 pt-3 text-sm text-text-muted">
                        {filteredServers.length.toLocaleString()} services visible
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
                      <p className="text-sm font-semibold uppercase tracking-[0.3em] text-primary">
                        Relays
                      </p>
                      <h2
                        id="public-relays-title"
                        className="text-3xl font-semibold tracking-tight text-foreground"
                      >
                        Public relays
                      </h2>
                    </div>
                    <a
                      href={OFFICIAL_REGISTRY_SOURCE_URL}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex h-10 items-center justify-center rounded-full bg-primary/12 px-4 text-sm font-semibold text-primary transition-colors hover:bg-primary/20"
                    >
                      Open registry.json
                    </a>
                  </div>

                  <div className="mt-6 rounded-xl border border-border/80 bg-secondary/35 p-5 sm:p-6">
                    {relayDiscoveryLoading ? (
                      <div className="rounded-2xl border border-border/70 bg-background/90 px-4 py-3 text-sm text-text-muted">
                        Loading known relays...
                      </div>
                    ) : knownRelays.length === 0 ? (
                      <div className="rounded-2xl border border-border/70 bg-background/90 px-4 py-3 text-sm text-text-muted">
                        No known relays discovered from this relay.
                      </div>
                    ) : (
                      <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3">
                        {knownRelays.map((relay) => (
                          <div
                            key={relay.relayURL}
                            className="flex min-w-0 items-center justify-between gap-3 rounded-2xl border border-border/70 bg-background/90 px-4 py-3"
                          >
                            <a
                              href={relay.relayURL}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="min-w-0 flex-1 overflow-hidden text-ellipsis whitespace-nowrap font-mono text-[13px] text-foreground underline-offset-4 hover:underline sm:text-sm"
                            >
                              {relay.relayURL}
                            </a>
                            <div className="flex shrink-0 items-center gap-2">
                              <span className="rounded-full bg-background px-2.5 py-1 font-mono text-[11px] font-medium text-text-muted ring-1 ring-border">
                                {relayReleaseVersions[relay.relayURL] || "offline"}
                              </span>
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                    {relayDiscoveryMessage ? (
                      <div className="mt-3 text-sm text-text-muted">
                        {relayDiscoveryMessage}
                      </div>
                    ) : null}
                  </div>
                </section>
              </main>
            </div>
            {publicFooter}
          </>
        )}
      </div>

      {isAdmin && (
        <Dialog open={showFilterModal} onOpenChange={setShowFilterModal}>
          <DialogContent className="sm:hidden max-w-sm rounded-sm">
            <DialogHeader>
              <DialogTitle>Filters</DialogTitle>
            </DialogHeader>
            <div className="flex flex-col gap-4">
              <div className="flex flex-col gap-2">
                <span className="text-sm font-medium text-text-muted">
                  Status
                </span>
                <StatusSelect
                  status={status}
                  onStatusChange={onStatusChange}
                  className="w-full!"
                />
              </div>
              {onBanFilterChange && (
                <div className="flex flex-col gap-2">
                  <span className="text-sm font-medium text-text-muted">
                    Ban Status
                  </span>
                  <BanStatusButtons
                    className="[&>button]:w-full"
                    banFilter={banFilter}
                    onBanFilterChange={onBanFilterChange}
                  />
                </div>
              )}
              <div className="flex flex-col gap-2">
                <span className="text-sm font-medium text-text-muted">Sort</span>
                <SortbySelect
                  className="w-full!"
                  sortBy={sortBy}
                  onSortByChange={onSortByChange}
                />
              </div>
              <div className="flex flex-col gap-2">
                <span className="text-sm font-medium text-text-muted">Tags</span>
                <TagCombobox
                  availableTags={availableTags}
                  selectedTags={selectedTags}
                  onAdd={onTagToggle}
                  onRemove={onTagToggle}
                />
              </div>
            </div>
          </DialogContent>
        </Dialog>
      )}

      {isAdmin && (
        <FloatingActionBar
          selectedCount={selectedIdentityKeys.size}
          totalCount={allIdentityKeys.length}
          isAllSelected={isAllSelected}
          onSelectAll={handleSelectAll}
          onApprove={handleBulkApprove}
          onDeny={handleBulkDeny}
          onBan={handleBulkBan}
        />
      )}
    </div>
  );
}
