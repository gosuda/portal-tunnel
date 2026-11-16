import { useState, type JSX } from "react";
import { useSearchParams } from "react-router-dom";
import { SsgoiTransition } from "@ssgoi/react";
import { useServerList } from "@/hooks/useServerList";
import { ServerListView } from "@/components/ServerListView";
import { ServerCommentsPanel } from "@/components/ServerCommentsPanel";
import { useServerComments } from "@/hooks/useServerComments";
import { useFederatedComments } from "@/hooks/useFederatedComments";
import type { BaseServer } from "@/lib/server";
import type { ReputationVoteAction } from "@/types/api";
import { useServiceDiscovery } from "@/hooks/useServiceDiscovery";
import { ServiceRelaysPanel } from "@/components/ServiceRelaysPanel";

export function ServerList(): JSX.Element {
  const [params, setParams] = useSearchParams();
  const identityAddress = params.get("identity")?.trim() ?? "";
  const [identityOpen, setIdentityOpen] = useState(false);
  const [networkScope, setNetworkScope] = useState(true);
  const [relayServerId, setRelayServerId] = useState<string | null>(null);
  const {
    commentServer,
    toggleComments,
    closeComments,
    browseView,
    sidebarOpen,
    setSidebarOpen,
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
    identityDiscovery,
  } = useServerList(identityAddress, networkScope);
  const relayServer = filteredServers.find((server) => server.id === relayServerId);
  const hasCatalogLocations = Boolean(relayServer?.locations?.length);
  const relayDiscovery = useServiceDiscovery(
    relayServer?.address ?? "",
    relayServer?.serviceName ?? "",
    Boolean(relayServer) && !hasCatalogLocations,
    true,
  );
  const relayPanel = hasCatalogLocations
    ? { response: identityDiscovery.response, loading: false }
    : relayDiscovery;

  return (
    <SsgoiTransition id="/">
      <ServerListView
        onOpenRelays={(server) => setRelayServerId(server.id)}
        identityFilter={<div className="space-y-3 px-4 pb-3 lg:px-8">
          {browseView === "home" && (
            <div role="group" aria-label="Service directory scope" className="flex flex-wrap gap-2">
              <button type="button" aria-pressed={networkScope} onClick={() => setNetworkScope(true)} className={`portal-category ${networkScope ? "bg-foreground text-background" : "bg-secondary text-foreground"}`}>All services (network)</button>
              <button type="button" aria-pressed={!networkScope} onClick={() => setNetworkScope(false)} className={`portal-category ${!networkScope ? "bg-foreground text-background" : "bg-secondary text-foreground"}`}>This relay</button>
            </div>
          )}
          <button type="button" aria-expanded={identityOpen || Boolean(identityAddress)} onClick={() => setIdentityOpen(!identityOpen)} className={`portal-category ${identityAddress ? "bg-foreground text-background" : "bg-secondary text-foreground"}`}>Identity{identityAddress ? " · Filtered" : ""}</button>
          {(identityOpen || identityAddress) && <form className="flex flex-wrap gap-2" onSubmit={(event) => {
            event.preventDefault();
            const address = String(new FormData(event.currentTarget).get("identity") ?? "").trim();
            const next = new URLSearchParams(params);
            next.set("identity", address);
            setParams(next);
          }}>
            <input key={identityAddress} name="identity" aria-label="Identity address filter" defaultValue={identityAddress} required pattern="0[xX][0-9a-fA-F]{40}" placeholder="0x… identity address" className="min-w-0 flex-1 rounded-lg border border-border bg-background px-3 py-2 font-mono text-sm sm:max-w-md" />
            <button type="submit" className="rounded-lg bg-primary px-4 py-2 text-sm text-primary-foreground">Apply</button>
            <button type="button" className="rounded-lg bg-secondary px-4 py-2 text-sm" onClick={() => { const next = new URLSearchParams(params); next.delete("identity"); setParams(next); setIdentityOpen(false); }}>Clear identity</button>
          </form>}
          {networkScope && browseView === "home" && <p className="text-xs text-muted-foreground">Only services observed on eligible relays are shown. Remote locations are relay-reported, not independently verified, and may expire.</p>}
          {identityAddress && !/^0x[0-9a-f]{40}$/i.test(identityAddress) && <p role="alert" className="text-sm">Enter a 0x-prefixed address with 40 hexadecimal characters.</p>}
          {identityDiscovery.loading && <p role="status" className="text-xs text-muted-foreground">Checking known relay directories… The local directory is available independently.</p>}
          {identityDiscovery.error && <p role="alert" className="text-xs text-muted-foreground">{identityDiscovery.error}</p>}
          {(identityDiscovery.response?.partial || identityDiscovery.error) && <button type="button" disabled={identityDiscovery.loading} onClick={identityDiscovery.checkMore} className="rounded-lg bg-secondary px-4 py-2 text-sm disabled:opacity-50">Check more relays</button>}
          {identityDiscovery.response && <p className="text-xs text-muted-foreground">{identityDiscovery.response.relays_checked} directories observed; {identityDiscovery.response.relays_skipped} unavailable or skipped.{identityDiscovery.response.partial ? " Partial lookup." : ""}</p>}
        </div>}
        browseView={browseView}
        sidebarOpen={sidebarOpen}
        onSidebarOpenChange={setSidebarOpen}
        onBrowseViewChange={handleBrowseViewChange}
        leases={leases}
        searchQuery={searchQuery}
        sortBy={sortBy}
        selectedTags={selectedTags}
        availableTags={availableTags}
        filteredServers={filteredServers}
        favorites={favorites}
        showHidden={showHidden}
        onShowHiddenChange={setShowHidden}
        hiddenCount={hiddenCount}
        onSearchChange={handleSearchChange}
        onSortByChange={handleSortByChange}
        onTagToggle={handleTagToggle}
        onClearTags={clearTags}
        onOpenComments={toggleComments}
        onVote={onVote}
      />
      {relayServer && <ServiceRelaysPanel server={relayServer} {...relayPanel} onCheckMore={hasCatalogLocations ? identityDiscovery.checkMore : relayDiscovery.checkMore} localReputation={leases === null ? undefined : relayServer.observedLocalReputation} onClose={() => setRelayServerId(null)} />}
      {commentServer && (
        <CommentsThread
          key={commentServer.id}
          server={commentServer}
          onClose={closeComments}
          onVoteApp={onVote}
        />
      )}
    </SsgoiTransition>
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
  const comments = useServerComments(server, !server.remoteOnly);
  const federation = useFederatedComments(server);
  return (
    <ServerCommentsPanel
      server={server}
      onClose={onClose}
      onVoteApp={server.remoteOnly ? undefined : onVoteApp}
      federation={federation}
      {...comments}
    />
  );
}
