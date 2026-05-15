import { SsgoiTransition } from "@ssgoi/react";
import { Header } from "@/components/Header";
import { useAdmin } from "@/hooks/useAdmin";
import { useAuth } from "@/hooks/useAuth";
import { ServerListView } from "@/components/ServerListView";

export function Admin() {
  const {
    isAuthenticated,
    isLoading: authLoading,
    checkAuth,
  } = useAuth("admin");

  const {
    servers,
    filteredServers,
    availableTags,
    searchQuery,
    status,
    sortBy,
    selectedTags,
    banFilter,
    approvalMode,
    landingPageEnabled,
    udpSettings,
    tcpPortSettings,
    favorites,
    loading,
    error,
    handleSearchChange,
    handleStatusChange,
    handleSortByChange,
    handleTagToggle,
    handleBanFilterChange,
    handleToggleFavorite,
    handleBanStatus,
    handleBPSChange,
    handleApprovalModeChange,
    handleLandingPageEnabledChange,
    handleUDPSettingsChange,
    handleTCPPortSettingsChange,
    handleApproveStatus,
    handleDenyStatus,
    handleIPBanStatus,
    handleBulkApprove,
    handleBulkDeny,
    handleBulkBan,
  } = useAdmin(isAuthenticated);

  const handleAuthChange = async () => {
    await checkAuth();
  };

  if (authLoading) {
    return <div className="p-8 text-foreground">Checking authentication...</div>;
  }

  if (!isAuthenticated) {
    return (
      <SsgoiTransition id="admin">
        <div className="relative flex min-h-screen w-full flex-col bg-background">
          <div className="sticky top-0 z-10 w-full bg-background pb-4 pt-5">
            <div className="flex w-full flex-col px-4 sm:px-6 lg:px-8">
              <Header
                title="PORTAL ADMIN"
                isAdmin={true}
                onAuthChange={handleAuthChange}
              />
            </div>
          </div>
          <main className="mx-auto flex w-full max-w-6xl flex-1 items-center justify-center px-6 py-16">
            <div className="rounded-lg border border-border bg-card px-6 py-5 text-center text-sm text-muted-foreground shadow-sm">
              Connect a wallet from the header to view admin controls.
            </div>
          </main>
        </div>
      </SsgoiTransition>
    );
  }

  if (loading && servers.length === 0) {
    return <div className="p-8 text-foreground">Loading...</div>;
  }
  if (error && servers.length === 0) {
    return <div className="p-8 text-red-500">Error: {error}</div>;
  }

  return (
    <SsgoiTransition id="admin">
      <ServerListView
        title="PORTAL ADMIN"
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
        // Admin-specific props
        isAdmin={true}
        banFilter={banFilter}
        approvalMode={approvalMode}
        landingPageEnabled={landingPageEnabled}
        udpSettings={udpSettings}
        tcpPortSettings={tcpPortSettings}
        onBanFilterChange={handleBanFilterChange}
        onBanStatusChange={handleBanStatus}
        onBPSChange={handleBPSChange}
        onApprovalModeChange={handleApprovalModeChange}
        onLandingPageEnabledChange={handleLandingPageEnabledChange}
        onUDPSettingsChange={handleUDPSettingsChange}
        onTCPPortSettingsChange={handleTCPPortSettingsChange}
        onApproveStatusChange={handleApproveStatus}
        onDenyStatusChange={handleDenyStatus}
        onIPBanStatusChange={handleIPBanStatus}
        onBulkApprove={handleBulkApprove}
        onBulkDeny={handleBulkDeny}
        onBulkBan={handleBulkBan}
        onAuthChange={handleAuthChange}
      />
    </SsgoiTransition>
  );
}
