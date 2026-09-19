import { SsgoiTransition } from "@ssgoi/react";
import { useServerList } from "@/hooks/useServerList";
import { ServerListView } from "@/components/ServerListView";

export function ServerList() {
  const {
    searchQuery,
    status,
    sortBy,
    selectedTags,
    availableTags,
    filteredServers,
    favorites,
    handleSearchChange,
    handleStatusChange,
    handleSortByChange,
    handleTagToggle,
    handleToggleFavorite,
    landingPageEnabled,
    leases,
  } = useServerList();

  return (
    <SsgoiTransition id="/">
      <ServerListView
        landingPageEnabled={landingPageEnabled}
        leases={leases}
        searchQuery={searchQuery}
        status={status}
        sortBy={sortBy}
        selectedTags={selectedTags}
        availableTags={availableTags}
        filteredServers={filteredServers}
        favorites={favorites}
        onSearchChange={handleSearchChange}
        onStatusChange={handleStatusChange}
        onSortByChange={handleSortByChange}
        onTagToggle={handleTagToggle}
        onToggleFavorite={handleToggleFavorite}
      />
    </SsgoiTransition>
  );
}
