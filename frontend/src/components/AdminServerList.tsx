import { useEffect, useMemo, useState } from "react";
import { Header } from "@/components/Header";
import { SearchBar } from "@/components/SearchBar";
import { AdminServerCard } from "@/components/AdminServerCard";
import { TagCombobox } from "@/components/TagCombobox";
import { StatusSelect } from "@/components/select/StatusSelect";
import { BanStatusButtons } from "@/components/button/BanStatusButtons";
import { SortbySelect } from "@/components/select/SortbySelect";
import { ApprovalModeToggle } from "@/components/button/ApprovalModeToggle";
import { FloatingActionBar } from "@/components/FloatingActionBar";
import type { AdminServer, ApprovalMode, UDPSettings, TCPPortSettings } from "@/hooks/useAdmin";
import type { BanFilter, SortOption, StatusFilter } from "@/types/filters";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";

interface AdminServerListProps {
  title?: string;
  searchQuery: string;
  status: StatusFilter;
  sortBy: SortOption;
  selectedTags: string[];
  availableTags: string[];
  filteredServers: AdminServer[];
  onSearchChange: (value: string) => void;
  onStatusChange: (value: StatusFilter) => void;
  onSortByChange: (value: SortOption) => void;
  onTagToggle: (tag: string) => void;
  banFilter: BanFilter;
  approvalMode: ApprovalMode;
  landingPageEnabled: boolean;
  policySaving: boolean;
  error: string;
  onBanFilterChange: (value: BanFilter) => void;
  onBanStatusChange: (identityKey: string, isBan: boolean) => void | Promise<void>;
  onBPSChange: (identityKey: string, bps: number) => void | Promise<void>;
  onApprovalModeChange: (mode: ApprovalMode) => void | Promise<void>;
  onLandingPageEnabledChange: (enabled: boolean) => void | Promise<void>;
  udpSettings: UDPSettings;
  onUDPSettingsChange: (settings: UDPSettings) => void | Promise<void>;
  tcpPortSettings: TCPPortSettings;
  onTCPPortSettingsChange: (settings: TCPPortSettings) => void | Promise<void>;
  onApproveStatusChange: (identityKey: string, approve: boolean) => void | Promise<void>;
  onDenyStatusChange: (identityKey: string, deny: boolean) => void | Promise<void>;
  onIPBanStatusChange: (ip: string, isBan: boolean) => void | Promise<void>;
  onBulkApprove: (identityKeys: string[]) => void | Promise<void>;
  onBulkDeny: (identityKeys: string[]) => void | Promise<void>;
  onBulkBan: (identityKeys: string[]) => void | Promise<void>;
  onAuthChange?: () => void | Promise<void>;
}

export function AdminServerList({
  title = "PORTAL ADMIN",
  searchQuery,
  status,
  sortBy,
  selectedTags,
  availableTags,
  filteredServers,
  onSearchChange,
  onStatusChange,
  onSortByChange,
  onTagToggle,
  banFilter,
  approvalMode,
  landingPageEnabled,
  policySaving,
  error,
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
  onAuthChange,
}: AdminServerListProps) {
  const [showFilterModal, setShowFilterModal] = useState(false);
  const [selectedIdentityKeys, setSelectedIdentityKeys] = useState<Set<string>>(
    new Set()
  );

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

  const allIdentityKeys = useMemo(
    () => [
      ...new Set(
        filteredServers
          .map((server) => server.identityKey)
          .filter(
            (identityKey) =>
              typeof identityKey === "string" && identityKey.trim().length > 0
          )
      ),
    ],
    [filteredServers]
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
    handler: (identityKeys: string[]) => void | Promise<void>
  ) => {
    if (selectedIdentityKeys.size === 0) {
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
    String(udpSettings.maxLeases ?? 0)
  );
  const [tcpPortMaxLeasesInput, setTCPPortMaxLeasesInput] = useState(
    String(tcpPortSettings.maxLeases ?? 0)
  );

  useEffect(() => {
    setMaxLeasesInput(String(udpSettings.maxLeases ?? 0));
  }, [udpSettings.maxLeases]);

  useEffect(() => {
    setTCPPortMaxLeasesInput(String(tcpPortSettings.maxLeases ?? 0));
  }, [tcpPortSettings.maxLeases]);

  const runPolicyAction = async (action: () => void | Promise<void>) => {
    try {
      await action();
    } catch {
      // useAdmin owns the shared action error displayed by this view.
    }
  };

  const handleUDPToggle = (enabled: boolean) => {
    void runPolicyAction(() => onUDPSettingsChange({ ...udpSettings, enabled }));
  };

  const handleTCPPortToggle = (enabled: boolean) => {
    void runPolicyAction(() => onTCPPortSettingsChange({ ...tcpPortSettings, enabled }));
  };

  const handleLandingPageToggle = (enabled: boolean) => {
    void runPolicyAction(() => onLandingPageEnabledChange(enabled));
  };

  const handleMaxLeasesSave = () => {
    const value = Math.max(0, parseInt(maxLeasesInput, 10) || 0);
    setMaxLeasesInput(String(value));
    void runPolicyAction(() => onUDPSettingsChange({ ...udpSettings, maxLeases: value }));
  };

  const handleTCPPortMaxLeasesSave = () => {
    const value = Math.max(0, parseInt(tcpPortMaxLeasesInput, 10) || 0);
    setTCPPortMaxLeasesInput(String(value));
    void runPolicyAction(() => onTCPPortSettingsChange({ ...tcpPortSettings, maxLeases: value }));
  };

  const policyControls = (
    <fieldset
      disabled={policySaving}
      aria-label="Relay policy"
      aria-busy={policySaving}
      className="flex min-w-0 flex-wrap items-center gap-4 sm:gap-6 disabled:opacity-60 [&_button:disabled]:cursor-wait [&_input:disabled]:cursor-wait"
    >
      <div className="flex items-center gap-3">
        <span className="text-sm font-medium text-text-muted">Approval</span>
        <ApprovalModeToggle
          approvalMode={approvalMode}
          onApprovalModeChange={(mode) => {
            void runPolicyAction(() => onApprovalModeChange(mode));
          }}
        />
      </div>
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
      <div role="group" aria-label="UDP" className="flex items-center gap-3">
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
            aria-label="Max UDP leases"
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
            aria-label="Save max UDP leases"
            className="cursor-pointer h-10 px-4 text-sm font-medium rounded-lg bg-primary text-primary-foreground hover:bg-primary/90 transition-colors"
          >
            Save
          </button>
        </div>
      </div>
      <div role="group" aria-label="TCP" className="flex items-center gap-3">
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
            aria-label="Max TCP leases"
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
            aria-label="Save max TCP leases"
            className="cursor-pointer h-10 px-4 text-sm font-medium rounded-lg bg-primary text-primary-foreground hover:bg-primary/90 transition-colors"
          >
            Save
          </button>
        </div>
      </div>
      {policySaving && <p role="status" className="text-sm text-text-muted">Saving policy...</p>}
    </fieldset>
  );

  const serverCards = filteredServers.map((server) => (
    <AdminServerCard
      key={server.id}
      server={server}
      isSelected={selectedIdentityKeys.has(server.identityKey)}
      onToggleSelect={handleToggleSelect}
      onBanStatusChange={onBanStatusChange}
      onBPSChange={onBPSChange}
      onApproveStatusChange={onApproveStatusChange}
      onDenyStatusChange={onDenyStatusChange}
      onIPBanStatusChange={onIPBanStatusChange}
    />
  ));

  const gridClasses =
    "grid grid-cols-1 gap-6 p-4 min-[500px]:p-6 min-[500px]:grid-cols-2 md:grid-cols-3";
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
      hideFiltersOnMobile
      setShowFilterModal={setShowFilterModal}
    />
  );

  return (
    <div className="relative flex h-auto min-h-screen w-full flex-col">
      <div className="flex h-full grow flex-col">
        <div className="sticky top-0 z-10 w-full bg-background pb-4 pt-5">
          <div className="flex w-full flex-col px-4 sm:px-6 lg:px-8">
            <Header
              title={title}
              isAdmin
              onAuthChange={onAuthChange}
            />
            {error && !showFilterModal && (
              <p role="alert" className="mt-4 text-sm text-destructive">{error}</p>
            )}
            <div className="flex items-center gap-2">
              <div className="flex-1">{searchBar}</div>
            </div>
            <div className="mt-4 hidden flex-wrap items-center gap-6 sm:flex">
              <div className="flex items-center gap-3">
                <span className="text-sm font-medium text-text-muted">Ban Status</span>
                <BanStatusButtons banFilter={banFilter} onBanFilterChange={onBanFilterChange} />
              </div>
              {policyControls}
            </div>
          </div>
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
      </div>

      <Dialog open={showFilterModal} onOpenChange={setShowFilterModal}>
        <DialogContent className="sm:hidden max-w-sm max-h-[calc(100dvh-2rem)] overflow-y-auto rounded-sm" aria-describedby={undefined}>
          <DialogHeader>
            <DialogTitle>Filters and policy</DialogTitle>
          </DialogHeader>
          {error && <p role="alert" className="text-sm text-destructive">{error}</p>}
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
            {policyControls}
          </div>
        </DialogContent>
      </Dialog>

      <FloatingActionBar
        selectedCount={selectedIdentityKeys.size}
        totalCount={allIdentityKeys.length}
        isAllSelected={isAllSelected}
        onSelectAll={handleSelectAll}
        onApprove={handleBulkApprove}
        onDeny={handleBulkDeny}
        onBan={handleBulkBan}
      />
    </div>
  );
}
