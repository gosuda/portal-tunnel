import { useState } from "react";
import { SearchX } from "lucide-react";
import type { AdminState } from "@/hooks/useAdmin";
import { cn } from "@/lib/utils";
import { StateMessage } from "./AdminStates";
import { BulkBar } from "./BulkBar";
import { LEASE_GRID, LeaseRow } from "./LeaseRow";

type LeaseListProps = Pick<
  AdminState,
  | "filteredServers"
  | "handleBanStatus"
  | "handleBPSChange"
  | "handleApproveStatus"
  | "handleDenyStatus"
  | "handleBulkApprove"
  | "handleBulkDeny"
  | "handleBulkBan"
>;

export function LeaseList({ filteredServers, handleBulkApprove, handleBulkDeny, handleBulkBan, ...rowHandlers }: LeaseListProps) {
  const [selected, setSelected] = useState<Set<string>>(new Set());

  const filteredKeys = [...new Set(filteredServers.map((server) => server.identityKey).filter((key) => key.length > 0))];
  const selectedKeys = filteredKeys.filter((key) => selected.has(key));
  const allSelected = filteredKeys.length > 0 && selectedKeys.length === filteredKeys.length;

  const toggle = (identityKey: string) =>
    setSelected((prev) => {
      const next = new Set(prev);
      if (!next.delete(identityKey)) next.add(identityKey);
      return next;
    });

  if (filteredServers.length === 0) {
    return (
      <StateMessage icon={<SearchX />} title="No servers match these filters">
        Change the search or filters to see more leases.
      </StateMessage>
    );
  }

  return (
    <>
      <div className={cn(LEASE_GRID, "border-b border-stroke py-2 text-xs font-semibold text-content-muted")}>
        <label className="flex size-10 items-center justify-center">
          <input
            type="checkbox"
            checked={allSelected}
            disabled={filteredKeys.length === 0}
            onChange={() => setSelected(allSelected ? new Set() : new Set(filteredKeys))}
            aria-label="Select all"
            className="size-5 accent-primary"
          />
        </label>
        <span>{filteredServers.length} apps</span>
        <span className="hidden md:block">Owner</span>
        <span className="hidden md:block">Status</span>
        <span className="hidden md:block">Speed limit</span>
        <span className="hidden text-right md:block">Actions</span>
      </div>
      <ul>
        {filteredServers.map((server) => (
          <LeaseRow key={server.id} server={server} selected={selected.has(server.identityKey)} onToggleSelect={toggle} {...rowHandlers} />
        ))}
      </ul>
      {selectedKeys.length > 0 && (
        <BulkBar
          selectedKeys={selectedKeys}
          onClear={() => setSelected(new Set())}
          handleBulkApprove={handleBulkApprove}
          handleBulkDeny={handleBulkDeny}
          handleBulkBan={handleBulkBan}
        />
      )}
    </>
  );
}
