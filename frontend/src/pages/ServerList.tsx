import { SsgoiTransition } from "@ssgoi/react";
import { useServerList } from "@/hooks/useServerList";
import { ServerListView } from "@/components/ServerListView";
import { ServerCommentsPanel } from "@/components/ServerCommentsPanel";
import { useServerComments } from "@/hooks/useServerComments";
import type { BaseServer } from "@/lib/server";
import type { ReputationVoteAction } from "@/types/api";

export function ServerList() {
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
