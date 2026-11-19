import { useEffect, useRef, useState, type JSX } from "react";
import { useNavigationType, useSearchParams } from "react-router-dom";
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

const isHexAddress = (val: string) => /^0x[0-9a-fA-F]{40}$/i.test(val.trim());

export function ServerList(): JSX.Element {
  const [params, setParams] = useSearchParams();
  const identityParam = params.get("identity")?.trim() ?? "";
  const activeIdentity = isHexAddress(identityParam) ? identityParam : "";
  const navigationType = useNavigationType();
  const previousIdentity = useRef("");
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
  } = useServerList(activeIdentity, networkScope);

  useEffect(() => {
    const previous = previousIdentity.current;
    if (previous === activeIdentity) return;
    previousIdentity.current = activeIdentity;
    if (activeIdentity || navigationType === "POP") {
      handleSearchChange(activeIdentity);
    }
  }, [activeIdentity, handleSearchChange, navigationType]);

  const onSearchChange = (value: string) => {
    const trimmed = value.trim();
    if (trimmed && selectedTags.length > 0) {
      clearTags();
    }
    handleSearchChange(value);
    if (isHexAddress(trimmed)) {
      setNetworkScope(true);
      if (activeIdentity.toLowerCase() !== trimmed.toLowerCase()) {
        const next = new URLSearchParams(params);
        next.set("identity", trimmed);
        setParams(next);
      }
    } else if (params.has("identity")) {
      const next = new URLSearchParams(params);
      next.delete("identity");
      setParams(next);
    }
  };

  const handleTagToggleWithReset = (tag: string) => {
    if (searchQuery) {
      onSearchChange("");
    }
    handleTagToggle(tag);
  };

  const handleClearAll = () => {
    clearTags();
    setNetworkScope(true);
    if (searchQuery) {
      onSearchChange("");
    }
  };

  const handleSelectIdentity = (address: string) => {
    clearTags();
    setNetworkScope(true);
    onSearchChange(address);
    document.querySelector<HTMLInputElement>('input[type="search"]')?.focus();
  };

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
        thisRelayActive={!networkScope}
        onToggleThisRelay={() => setNetworkScope(!networkScope)}
        discoveryLoading={identityDiscovery.loading}
        discoveryError={identityDiscovery.error}
        discoveryCheckMore={
          (identityDiscovery.response?.partial || identityDiscovery.error)
            ? identityDiscovery.checkMore
            : undefined
        }
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
        onSearchChange={onSearchChange}
        onSortByChange={handleSortByChange}
        onTagToggle={handleTagToggleWithReset}
        onClearTags={handleClearAll}
        onSelectIdentity={handleSelectIdentity}
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
