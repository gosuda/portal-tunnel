import type { JSX } from "react";
import { SsgoiTransition } from "@ssgoi/react";
import { AdminHeader } from "@/components/AdminHeader";
import { useAdmin } from "@/hooks/useAdmin";
import { useAuth } from "@/hooks/useAuth";
import { AdminServerList } from "@/components/AdminServerList";

export function Admin(): JSX.Element {
  const auth = useAuth();
  const { isAuthenticated, isLoading: authLoading } = auth;

  const {
    pending,
    filteredServers,
    availableTags,
    searchQuery,
    status,
    sortBy,
    selectedTags,
    banFilter,
    approvalMode,
    udpSettings,
    tcpPortSettings,
    policySaving,
    loaded,
    loading,
    error,
    refresh,
    handleSearchChange,
    handleStatusChange,
    handleSortByChange,
    handleTagToggle,
    handleBanFilterChange,
    handleBanStatus,
    handleBPSChange,
    handleApprovalModeChange,
    handleUDPSettingsChange,
    handleTCPPortSettingsChange,
    handleApproveStatus,
    handleDenyStatus,
    handleBulkApprove,
    handleBulkDeny,
    handleBulkBan,
  } = useAdmin(isAuthenticated);

  if (authLoading) {
    return <div className="p-8 text-foreground">Checking authentication...</div>;
  }

  if (!isAuthenticated) {
    return (
      <SsgoiTransition id="admin">
        <div className="relative flex min-h-screen w-full flex-col bg-background">
          <div className="sticky top-0 z-10 w-full bg-background pb-4 pt-5">
            <div className="flex w-full flex-col px-4 sm:px-6 lg:px-8">
              <AdminHeader auth={auth} />
            </div>
          </div>
          <main className="mx-auto flex w-full max-w-6xl flex-1 items-center justify-center px-6 py-16">
            <div className="rounded-lg border border-border bg-card px-6 py-5 text-center text-sm text-muted-foreground shadow-sm">
              Enter the admin token from the header to view admin controls.
            </div>
          </main>
        </div>
      </SsgoiTransition>
    );
  }

  if (!loaded && loading) {
    return <div className="p-8 text-foreground">Loading...</div>;
  }
  if (!loaded && error) {
    return <div className="p-8 text-red-500">
      <p role="alert">Error: {error}</p>
      <button type="button" onClick={() => void refresh()}>Refresh policy</button>
    </div>;
  }

  return (
    <SsgoiTransition id="admin">
      {error && <p role="alert" className="p-4 text-red-500">Error: {error}</p>}
      <AdminServerList
        title="PORTAL ADMIN"
        pending={pending}
        onRefresh={refresh}
        searchQuery={searchQuery}
        status={status}
        sortBy={sortBy}
        selectedTags={selectedTags}
        availableTags={availableTags}
        filteredServers={filteredServers}
        onSearchChange={handleSearchChange}
        onStatusChange={handleStatusChange}
        onSortByChange={handleSortByChange}
        onTagToggle={handleTagToggle}
        banFilter={banFilter}
        approvalMode={approvalMode}
        udpSettings={udpSettings}
        tcpPortSettings={tcpPortSettings}
        policySaving={policySaving}
        onBanFilterChange={handleBanFilterChange}
        onBanStatusChange={handleBanStatus}
        onBPSChange={handleBPSChange}
        onApprovalModeChange={handleApprovalModeChange}
        onUDPSettingsChange={handleUDPSettingsChange}
        onTCPPortSettingsChange={handleTCPPortSettingsChange}
        onApproveStatusChange={handleApproveStatus}
        onDenyStatusChange={handleDenyStatus}
        onBulkApprove={handleBulkApprove}
        onBulkDeny={handleBulkDeny}
        onBulkBan={handleBulkBan}
        auth={auth}
      />
    </SsgoiTransition>
  );
}
