import { useState, type JSX } from "react";
import { useSearchParams } from "react-router-dom";
import { SsgoiTransition } from "@ssgoi/react";
import { useServerList } from "@/hooks/useServerList";
import { ServerListView } from "@/components/ServerListView";
import { ServerCommentsPanel } from "@/components/ServerCommentsPanel";
import { useServerComments } from "@/hooks/useServerComments";
import type { BaseServer } from "@/lib/server";
import type { ReputationVoteAction } from "@/types/api";
import { useServiceDiscovery } from "@/hooks/useServiceDiscovery";
import { ServiceRelaysPanel } from "@/components/ServiceRelaysPanel";

export function ServerList(): JSX.Element {
  const [params, setParams] = useSearchParams();
  const identityAddress = params.get("identity")?.trim() ?? "";
  const [identityOpen, setIdentityOpen] = useState(false);
  const [relayServer, setRelayServer] = useState<BaseServer | null>(null);
  const [relaysOpen, setRelaysOpen] = useState(false);
  const relayDiscovery = useServiceDiscovery(relayServer?.address ?? "", relayServer?.serviceName ?? "", relaysOpen);
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
  } = useServerList(identityAddress);
  const relayCount = relayDiscovery.response?.services.find((service) => service.name === (relayServer?.serviceName ?? "") && service.address.toLowerCase() === relayServer?.address?.toLowerCase())?.locations.length;

  return (
    <SsgoiTransition id="/">
      <ServerListView
        onOpenRelays={(server) => { setRelayServer(server); setRelaysOpen(true); }}
        relayCounts={relayServer && relayCount !== undefined ? { [relayServer.id]: relayCount } : undefined}
        identityFilter={<div className="space-y-3 px-4 pb-3 lg:px-8">
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
          {identityAddress && <p className="text-xs text-muted-foreground">Observed public services for this address. Remote locations are relay-reported and have not been independently verified. Other services may exist.</p>}
          {identityAddress && !/^0x[0-9a-f]{40}$/i.test(identityAddress) && <p role="alert" className="text-sm">Enter a 0x-prefixed address with 40 hexadecimal characters.</p>}
          {identityDiscovery.loading && <p role="status" className="text-xs text-muted-foreground">Checking known relay directories…</p>}
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
      {relaysOpen && relayServer && <ServiceRelaysPanel server={relayServer} {...relayDiscovery} onCheckMore={relayDiscovery.checkMore} onClose={() => setRelaysOpen(false)} />}
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
