import { Ban, Check, ImageOff, Undo2, X } from "lucide-react";
import { Badge } from "@/components/ui/chip";
import { Button } from "@/components/ui/button";
import type { AdminServer, AdminState } from "@/hooks/useAdmin";
import { cn } from "@/lib/utils";
import { BpsEditor } from "./BpsEditor";
import { useBusy } from "./useBusy";

export const LEASE_GRID =
  "grid grid-cols-[40px_minmax(0,1fr)] items-center gap-x-2 gap-y-1 md:grid-cols-[40px_minmax(0,2fr)_minmax(0,1fr)_minmax(0,1.2fr)_9rem_14rem]";

const CELL = "col-start-2 min-w-0 md:col-start-auto";

type LeaseRowProps = {
  server: AdminServer;
  selected: boolean;
  onToggleSelect: (identityKey: string) => void;
} & Pick<AdminState, "handleBanStatus" | "handleBPSChange" | "handleApproveStatus" | "handleDenyStatus">;

export function LeaseRow({
  server,
  selected,
  onToggleSelect,
  handleBanStatus,
  handleBPSChange,
  handleApproveStatus,
  handleDenyStatus,
}: LeaseRowProps) {
  const { identityKey, isBanned, isApproved, isDenied, bps, ip, displayIP, online } = server;
  const { busy, run } = useBusy();
  const pending = !isApproved && !isDenied;

  return (
    <li className={cn(LEASE_GRID, "border-b border-stroke py-3 md:py-2", selected && "bg-state-hover")}>
      <label className="flex size-10 items-center justify-center">
        <input
          type="checkbox"
          checked={selected}
          disabled={!identityKey}
          onChange={() => onToggleSelect(identityKey)}
          aria-label={`Select ${server.name}`}
          className="size-5 accent-primary"
        />
      </label>

      <div className="flex min-w-0 items-center gap-3">
        {server.thumbnail ? (
          <img src={server.thumbnail} alt="" loading="lazy" className="aspect-video w-16 shrink-0 rounded-sm bg-surface-200 object-cover" />
        ) : (
          <span className="flex aspect-video w-16 shrink-0 items-center justify-center rounded-sm bg-surface-200 text-content-muted">
            <ImageOff className="size-4" aria-hidden />
          </span>
        )}
        <div className="min-w-0">
          <p className="truncate font-semibold text-content-emphasis">{server.name}</p>
          <p className="truncate text-xs text-content-muted">{server.dns}</p>
          {isApproved && ip && (
            <p className="truncate font-mono text-xs text-content-muted">
              {displayIP && displayIP !== ip ? `Client ${ip} · Reported ${displayIP}` : ip}
            </p>
          )}
        </div>
      </div>

      <p className={cn(CELL, "truncate text-sm text-content-muted")}>
        <span className="md:hidden">Owner: </span>
        {server.owner || "—"}
      </p>

      <div className={cn(CELL, "flex flex-wrap gap-1")}>
        <Badge tone={online ? "success" : "neutral"}>{online ? "Online" : "Offline"}</Badge>
        {isApproved && <Badge tone="success">Approved</Badge>}
        {isDenied && <Badge tone="danger">Denied</Badge>}
        {pending && <Badge tone="warning">Pending</Badge>}
        {isBanned && <Badge tone="danger">Banned</Badge>}
      </div>

      <div className={cn(CELL, "min-w-0")}>
        {identityKey && (
          <BpsEditor bps={bps} disabled={busy} onSave={(next) => void run(() => handleBPSChange(identityKey, next))} />
        )}
      </div>

      <div className={cn(CELL, "flex gap-2 md:justify-end")}>
        {identityKey &&
          (pending ? (
            <>
              <Button variant="primary" size="sm" disabled={busy} onClick={() => void run(() => handleApproveStatus(identityKey, true))}>
                <Check className="size-4" aria-hidden />
                Approve
              </Button>
              <Button variant="danger" size="sm" disabled={busy} onClick={() => void run(() => handleDenyStatus(identityKey, true))}>
                <X className="size-4" aria-hidden />
                Deny
              </Button>
            </>
          ) : (
            <Button
              variant={isBanned ? "secondary" : "danger"}
              size="sm"
              disabled={busy}
              onClick={() => void run(() => handleBanStatus(identityKey, !isBanned))}
            >
              {isBanned ? <Undo2 className="size-4" aria-hidden /> : <Ban className="size-4" aria-hidden />}
              {isBanned ? "Unban" : "Ban"}
            </Button>
          ))}
      </div>
    </li>
  );
}
