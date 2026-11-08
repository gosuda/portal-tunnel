import { useState, type ReactNode } from "react";
import { Home, Globe, Plus, Search, Star, Terminal } from "lucide-react";
import { AppShell, SidebarItem } from "@/components/shell/AppShell";
import { Button } from "@/components/ui/button";
import { AppSection, TileGrid, TileSkeletons } from "@/components/list/AppSection";
import { approval, firstSeenTime } from "@/components/list/appStats";
import { ListToolbar, SearchField, TagChips } from "@/components/list/ListControls";
import { readRecentAppIds } from "@/components/list/recentApps";
import { appListTitle, emptyListMessage } from "@/components/list/listMessages";
import { ServerCommentsPanel } from "@/components/comments/ServerCommentsPanel";
import { PublicRelaysSection } from "@/components/relays/PublicRelaysSection";
import { TunnelCommandModal } from "@/components/tunnel/TunnelCommandModal";
import { useCopy } from "@/hooks/useCopy";
import { useRelayDiscovery } from "@/hooks/useRelayDiscovery";
import { useServerComments } from "@/hooks/useServerComments";
import { useServerList } from "@/hooks/useServerList";
import type { BaseServer } from "@/lib/server";
import type { ReputationVoteAction } from "@/types/api";

const RECOMMENDED_LIMIT = 12;
const CONTINUE_LIMIT = 20;

export function ServerList() {
  const {
    commentServer,
    toggleComments,
    closeComments,
    browseView,
    handleBrowseViewChange,
    searchQuery,
    sortBy,
    selectedTags,
    availableTags,
    filteredServers,
    favorites,
    showHidden,
    setShowHidden,
    hiddenCount,
    handleSearchChange,
    handleSortByChange,
    handleTagToggle,
    clearTags,
    onVote,
    leases,
  } = useServerList();
  const { copiedKey: copiedRelayURL, copy: copyRelayURL } = useCopy(1500);
  const { knownRelays, relayReleases, loading: relayDiscoveryLoading } = useRelayDiscovery();

  const isAppView = browseView !== "relays";
  const hasActiveFilters = searchQuery.trim() !== "" || selectedTags.length > 0;
  const showConnecting = leases === null && !hasActiveFilters;
  const emptyMessage = emptyListMessage(browseView, showConnecting, hasActiveFilters);
  const showSections = browseView === "home" && !hasActiveFilters;
  const tileHandlers = { onOpenComments: toggleComments, onVote };

  const toolbar = (
    <ListToolbar
      sortBy={sortBy}
      onSortByChange={handleSortByChange}
      showHidden={showHidden}
      hiddenCount={hiddenCount}
      onShowHiddenChange={setShowHidden}
    />
  );

  const sidebar = (
    <>
      <SidebarItem icon={<Home />} label="Home" current={browseView === "home"} onClick={() => handleBrowseViewChange("home")} />
      <SidebarItem
        icon={<Star />}
        label="Favorites"
        badge={
          <span className="flex h-5 min-w-5 items-center justify-center rounded-full bg-content-emphasis px-1 type-title-small text-surface-0">
            {favorites}
          </span>
        }
        current={browseView === "favorites"}
        onClick={() => handleBrowseViewChange("favorites")}
      />
      <SidebarItem icon={<Globe />} label="Relays" current={browseView === "relays"} onClick={() => handleBrowseViewChange("relays")} />
      <div className="flex flex-col items-start gap-2 rounded-lg border border-stroke bg-surface-100 p-3">
        <Terminal className="size-5 text-content-emphasis" />
        <p className="type-body-medium text-content">Expose a local app in one command.</p>
        <TunnelCommandModal
          trigger={
            <button type="button" className="rounded-sm type-label-medium text-content-emphasis underline">
              Launch
            </button>
          }
        />
      </div>
    </>
  );

  return (
    <AppShell
      sidebar={sidebar}
      search={
        <SearchField
          value={searchQuery}
          onChange={(value) => {
            if (!isAppView) handleBrowseViewChange("home");
            handleSearchChange(value);
          }}
        />
      }
      actions={
        <TunnelCommandModal
          trigger={
            <Button variant="secondary" size="sm" aria-label="Launch App">
              <Plus className="size-4" />
              <span className="hidden sm:inline">Launch App</span>
            </Button>
          }
        />
      }
    >
      <div className="@container mx-auto w-full max-w-[2400px] px-4 pb-12 pt-6 min-[600px]:px-6">
        {isAppView ? (
          <>
            <div className="mb-4 flex flex-wrap items-baseline gap-x-3">
              <h1 className="type-heading-large text-content-emphasis">
                {showSections ? "Home" : appListTitle(browseView, searchQuery, sortBy)}
              </h1>
            </div>
            <TagChips availableTags={availableTags} selectedTags={selectedTags} onTagToggle={handleTagToggle} onClearTags={clearTags} />
            {filteredServers.length === 0 ? (
              showConnecting ? (
                <div aria-busy="true">
                  <TileSkeletons />
                </div>
              ) : (
                <>
                  <div className="mb-3">{toolbar}</div>
                  <div className="mx-auto flex min-h-[50vh] max-w-md flex-col items-center justify-center gap-2 text-center">
                    {browseView === "favorites" ? <Star className="size-12 text-content-muted" /> : <Search className="size-12 text-content-muted" />}
                    <h2 className="type-heading-small text-content-emphasis">{emptyMessage.title}</h2>
                    <p className="type-body-medium text-content-muted">{emptyMessage.body}</p>
                  </div>
                </>
              )
            ) : showSections ? (
              <HomeSections servers={filteredServers} toolbar={toolbar} {...tileHandlers} />
            ) : (
              <>
                <div className="mb-3">{toolbar}</div>
                <TileGrid servers={filteredServers} variant="wide" {...tileHandlers} />
              </>
            )}
          </>
        ) : (
          <PublicRelaysSection
            knownRelays={knownRelays}
            relayReleases={relayReleases}
            loading={relayDiscoveryLoading}
            copiedURL={copiedRelayURL}
            onCopyURL={copyRelayURL}
          />
        )}
      </div>
      {commentServer && (
        <CommentsThread
          key={commentServer.id}
          server={commentServer}
          onClose={closeComments}
          onVoteApp={onVote}
        />
      )}
    </AppShell>
  );
}

interface HomeSectionsProps {
  servers: BaseServer[];
  toolbar: ReactNode;
  onOpenComments: (server: BaseServer) => void;
  onVote?: (hostname: string, vote: ReputationVoteAction) => void | Promise<void>;
}

function HomeSections({ servers, toolbar, ...handlers }: HomeSectionsProps) {
  const recommended = [...servers].sort(
    (a, b) =>
      (b.reputation?.up ?? 0) - (a.reputation?.up ?? 0) ||
      (approval(b) ?? 0) - (approval(a) ?? 0) ||
      firstSeenTime(b) - firstSeenTime(a)
  );
  const [recentIdsAtVisit] = useState(readRecentAppIds);
  const recent = recentIdsAtVisit.flatMap((id) => servers.find((server) => server.id === id) ?? []).slice(0, CONTINUE_LIMIT);

  return (
    <div className="flex flex-col gap-8">
      <AppSection title="Recommended" layout="grid" servers={recommended.slice(0, RECOMMENDED_LIMIT)} {...handlers} />
      {recent.length > 0 && <AppSection title="Continue" layout="carousel" servers={recent} {...handlers} />}
      <AppSection title="All apps" layout="grid" servers={servers} headingTrailing={toolbar} {...handlers} />
    </div>
  );
}

function CommentsThread({
  server,
  onClose,
  onVoteApp,
}: {
  server: BaseServer;
  onClose: () => void;
  onVoteApp?: (hostname: string, vote: ReputationVoteAction) => void | Promise<void>;
}) {
  const comments = useServerComments(server);
  return (
    <ServerCommentsPanel
      server={server}
      onClose={onClose}
      onVoteApp={onVoteApp}
      {...comments}
    />
  );
}
