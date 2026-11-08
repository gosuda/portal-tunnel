import { useEffect, useMemo, useState } from "react";
import { Search, Settings } from "lucide-react";
import { AdminHeader } from "@/components/AdminHeader";
import { Input } from "@/components/ui/input";
import { AdminServerCard } from "@/components/AdminServerCard";
import { TagCombobox } from "@/components/TagCombobox";
import type { AdminServer, ApprovalMode, PortSettings } from "@/hooks/useAdmin";
import type { BanFilter, SortOption, StatusFilter } from "@/types/filters";
import { StatusSelect } from "@/components/select/StatusSelect";
import { BanStatusButtons } from "@/components/button/BanStatusButtons";
import { SortbySelect } from "@/components/select/SortbySelect";
import { ApprovalModeToggle } from "@/components/button/ApprovalModeToggle";
import { FloatingActionBar } from "@/components/FloatingActionBar";
import { TransportPolicyControl } from "@/components/TransportPolicyControl";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";

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
  policySaving: boolean;
  onBanFilterChange: (value: BanFilter) => void;
  onBanStatusChange: (
    identityKey: string,
    isBan: boolean
  ) => void | Promise<void>;
  onBPSChange: (identityKey: string, bps: number) => void | Promise<void>;
  onApprovalModeChange: (mode: ApprovalMode) => void;
  udpSettings: PortSettings;
  onUDPSettingsChange: (settings: PortSettings) => void | Promise<void>;
  tcpPortSettings: PortSettings;
  onTCPPortSettingsChange: (settings: PortSettings) => void | Promise<void>;
  onApproveStatusChange: (
    identityKey: string,
    approve: boolean
  ) => void | Promise<void>;
  onDenyStatusChange: (
    identityKey: string,
    deny: boolean
  ) => void | Promise<void>;
  onBulkApprove: (identityKeys: string[]) => void | Promise<void>;
  onBulkDeny: (identityKeys: string[]) => void | Promise<void>;
  onBulkBan: (identityKeys: string[]) => void | Promise<void>;
  onAuthChange: () => void | Promise<void>;
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
  policySaving,
  onBanFilterChange,
  onBanStatusChange,
  onBPSChange,
  onApprovalModeChange,
  udpSettings,
  onUDPSettingsChange,
  tcpPortSettings,
  onTCPPortSettingsChange,
  onApproveStatusChange,
  onDenyStatusChange,
  onBulkApprove,
  onBulkDeny,
  onBulkBan,
  onAuthChange,
}: AdminServerListProps) {
  const [showFilterModal, setShowFilterModal] = useState(false);
  const [selectedIdentityKeys, setSelectedIdentityKeys] = useState<Set<string>>(new Set());
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
    () => [...new Set(filteredServers.map((server) => server.identityKey).filter((key) => key.trim().length > 0))],
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

  const adminFilterControls = (
    <>
      <div className="flex items-center gap-3">
        <span className="text-sm font-medium text-text-muted">
          Ban Status
        </span>
        <BanStatusButtons
          banFilter={banFilter}
          onBanFilterChange={onBanFilterChange}
        />
      </div>
      <div className="flex items-center gap-3">
        <span className="text-sm font-medium text-text-muted">Approval</span>
        <ApprovalModeToggle
          approvalMode={approvalMode}
          disabled={policySaving}
          onApprovalModeChange={onApprovalModeChange}
        />
      </div>
    </>
  );

  const transportPolicyControls = (
    <>
      <TransportPolicyControl label="UDP" settings={udpSettings} disabled={policySaving} onChange={onUDPSettingsChange} />
      <TransportPolicyControl label="TCP" settings={tcpPortSettings} disabled={policySaving} onChange={onTCPPortSettingsChange} />
    </>
  );

  const serverGrid = filteredServers.length > 0 ? (
    <div className="grid grid-cols-1 gap-6 p-4 min-[500px]:p-6 min-[500px]:grid-cols-2 md:grid-cols-3">
      {filteredServers.map((server) => (
        <AdminServerCard
          key={server.id}
          server={server}
          isSelected={selectedIdentityKeys.has(server.identityKey)}
          onToggleSelect={handleToggleSelect}
          onBanStatusChange={onBanStatusChange}
          onBPSChange={onBPSChange}
          onApproveStatusChange={onApproveStatusChange}
          onDenyStatusChange={onDenyStatusChange}
        />
      ))}
    </div>
  ) : null;
  const noMatchingServersMessage = (
    <p className="text-lg text-text-muted">No servers match these filters</p>
  );

  const searchBar = (
    <div className="flex flex-wrap mt-5 items-center gap-3 border-b border-border pb-4">
      <div className="flex gap-2 items-center w-full lg:w-auto lg:min-w-72 lg:flex-1">
        <label className="flex min-w-0 flex-1 items-stretch h-10 relative">
          <div className="left-0 h-full absolute text-text-muted flex items-center justify-center pl-3 pr-2 rounded-l-md bg-border border border-border">
            <Search className="w-4 h-4" />
          </div>
          <Input
            aria-label="Search live apps"
            type="search"
            placeholder="Search apps, descriptions, or tags"
            value={searchQuery}
            onChange={(e) => onSearchChange(e.target.value)}
            className="h-10 pl-12 border border-border rounded-md"
          />
        </label>
        <button
          onClick={() => setShowFilterModal(true)}
          className="sm:hidden flex items-center justify-center w-10 h-10 rounded-lg bg-secondary hover:bg-secondary/80 transition-colors"
          aria-label="Filter settings"
        >
          <Settings className="w-5 h-5 text-secondary-foreground" />
        </button>
      </div>

      <StatusSelect
        className="flex-1 sm:flex-none"
        status={status}
        onStatusChange={onStatusChange}
        hideFiltersOnMobile
      />

      <SortbySelect
        className="flex-1 sm:flex-none"
        sortBy={sortBy}
        onSortByChange={onSortByChange}
        hideFiltersOnMobile
      />

      <div className="relative hidden w-full flex-1 sm:flex sm:w-auto sm:min-w-48 lg:max-w-72">
        <TagCombobox
          availableTags={availableTags}
          selectedTags={selectedTags}
          onAdd={onTagToggle}
          onRemove={onTagToggle}
        />
      </div>
    </div>
  );
  return (
    <div className="relative flex h-auto min-h-screen w-full flex-col">
      <div className="flex h-full grow flex-col">
        <div className="sticky top-0 z-10 w-full bg-background pb-4 pt-5">
          <div className="flex w-full flex-col px-4 sm:px-6 lg:px-8">
            <AdminHeader
              title={title}
              onAuthChange={onAuthChange}
            />
            <div className="flex items-center gap-2">
              <div className="flex-1">{searchBar}</div>
            </div>
            <div className="mt-4 hidden flex-wrap items-center gap-6 sm:flex">
              {adminFilterControls}
              {transportPolicyControls}
            </div>
            <div className="mt-4 flex items-center gap-3 sm:hidden">
              <span className="text-sm font-medium text-text-muted">
                Approval
              </span>
              <ApprovalModeToggle
                approvalMode={approvalMode}
                disabled={policySaving}
                onApprovalModeChange={onApprovalModeChange}
              />
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
        <DialogContent className="sm:hidden max-w-sm max-h-[90dvh] overflow-y-auto rounded-sm">
          <DialogHeader>
            <DialogTitle>Filters and policy</DialogTitle>
          </DialogHeader>
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
            {transportPolicyControls}
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
