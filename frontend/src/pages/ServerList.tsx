import { SsgoiTransition } from "@ssgoi/react";
import { useServerList } from "@/hooks/useServerList";
import { ServerListView } from "@/components/ServerListView";
import { ServerCommentsPanel } from "@/components/ServerCommentsPanel";
import { useServerComments } from "@/hooks/useServerComments";
import type { BaseServer } from "@/hooks/useList";
import type { ReputationVoteAction } from "@/types/api";

export function ServerList() {
  const {
    commentServer,
    setCommentServer,
    browseView,
    sidebarOpen,
    setSidebarOpen,
    handleBrowseViewChange,
    searchQuery,
    status,
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
    onVote,
    leases,
  } = useServerList();

  return (
    <SsgoiTransition id="/">
      <ServerListView
        browseView={browseView}
        sidebarOpen={sidebarOpen}
        onSidebarOpenChange={setSidebarOpen}
        onBrowseViewChange={handleBrowseViewChange}
        leases={leases}
        searchQuery={searchQuery}
        status={status}
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
        onOpenComments={(server) =>
          setCommentServer((current) => (current?.id === server.id ? null : server))
        }
      />
      {commentServer && (
        <CommentsThread
          key={commentServer.id}
          server={commentServer}
          onClose={() => setCommentServer(null)}
          onVoteApp={onVote}
        />
      )}
    </SsgoiTransition>
  );
}

// The keyed page section owns the request and draft lifetime of one app.
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
