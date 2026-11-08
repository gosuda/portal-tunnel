import { Ban, Check, X } from "lucide-react";
import { Button, IconButton } from "@/components/ui/button";
import type { AdminState } from "@/hooks/useAdmin";
import { useBusy } from "./useBusy";

type BulkBarProps = {
  selectedKeys: string[];
  onClear: () => void;
} & Pick<AdminState, "handleBulkApprove" | "handleBulkDeny" | "handleBulkBan">;

export function BulkBar({ selectedKeys, onClear, handleBulkApprove, handleBulkDeny, handleBulkBan }: BulkBarProps) {
  const { busy, run } = useBusy();
  const apply = async (handler: (identityKeys: string[]) => Promise<void>) => {
    if (await run(() => handler(selectedKeys))) onClear();
  };

  return (
    <div className="fixed inset-x-4 bottom-4 z-30 flex justify-center nav:left-sidebar">
      <div
        role="toolbar"
        aria-label="Bulk actions"
        className="flex max-w-full flex-wrap items-center gap-2 rounded-lg border border-stroke bg-surface-300 p-2 shadow-2xl"
      >
        <span className="px-2 text-sm font-semibold text-content-emphasis">{selectedKeys.length} selected</span>
        <Button variant="primary" size="sm" disabled={busy} onClick={() => void apply(handleBulkApprove)}>
          <Check className="size-4" aria-hidden />
          Approve
        </Button>
        <Button variant="secondary" size="sm" disabled={busy} onClick={() => void apply(handleBulkDeny)}>
          <X className="size-4" aria-hidden />
          Deny
        </Button>
        <Button variant="danger" size="sm" disabled={busy} onClick={() => void apply(handleBulkBan)}>
          <Ban className="size-4" aria-hidden />
          Ban
        </Button>
        <IconButton aria-label="Clear selection" onClick={onClear}>
          <X className="size-4" />
        </IconButton>
      </div>
    </div>
  );
}
