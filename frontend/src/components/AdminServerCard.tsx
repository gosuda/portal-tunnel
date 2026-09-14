import { useState } from "react";
import clsx from "clsx";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { ServerCardBody } from "@/components/ServerCard";
import type { AdminServer } from "@/hooks/useAdmin";

interface AdminServerCardProps {
  server: AdminServer;
  isSelected: boolean;
  onToggleSelect: (identityKey: string) => void;
  onBanStatusChange: (identityKey: string, isBan: boolean) => void | Promise<void>;
  onBPSChange: (identityKey: string, bps: number) => void | Promise<void>;
  onApproveStatusChange: (identityKey: string, approve: boolean) => void | Promise<void>;
  onDenyStatusChange: (identityKey: string, deny: boolean) => void | Promise<void>;
  onIPBanStatusChange: (ip: string, isBan: boolean) => void | Promise<void>;
}

const BPS_STEPS = [0, 10, 100, 1000, 10000, 100000, 1000000, 10000000];

function bpsToSliderIndex(value: number): number {
  if (value === 0) return 0;
  const idx = BPS_STEPS.findIndex((step) => step >= value);
  return idx === -1 ? BPS_STEPS.length - 1 : idx;
}

export function AdminServerCard({
  server,
  isSelected,
  onToggleSelect,
  onBanStatusChange,
  onBPSChange,
  onApproveStatusChange,
  onDenyStatusChange,
  onIPBanStatusChange,
}: AdminServerCardProps) {
  const [showBPSModal, setShowBPSModal] = useState(false);
  const [bpsInput, setBpsInput] = useState(server.bps.toString());
  const [sliderIndex, setSliderIndex] = useState(bpsToSliderIndex(server.bps));


  const runAsyncAdminAction = (action: () => void | Promise<void>) => {
    try {
      const result = action();
      if (result instanceof Promise) {
        void result.catch((error) => {
          console.error("Failed admin action", error);
        });
      }
    } catch (error) {
      console.error("Failed admin action", error);
    }
  };

  const handleSelectClick = (event: React.MouseEvent) => {
    event.preventDefault();
    event.stopPropagation();
    onToggleSelect(server.identityKey);
  };

  const handleBanClick = (event: React.MouseEvent) => {
    event.preventDefault();
    event.stopPropagation();
    runAsyncAdminAction(() => onBanStatusChange(server.identityKey, !server.isBanned));
  };

  const handleApproveClick = (event: React.MouseEvent) => {
    event.preventDefault();
    event.stopPropagation();
    runAsyncAdminAction(() => onApproveStatusChange(server.identityKey, !server.isApproved));
  };

  const handleDenyClick = (event: React.MouseEvent) => {
    event.preventDefault();
    event.stopPropagation();
    runAsyncAdminAction(() => onDenyStatusChange(server.identityKey, !server.isDenied));
  };

  const handleIPBanClick = (event: React.MouseEvent) => {
    event.preventDefault();
    event.stopPropagation();
    if (server.ip) {
      runAsyncAdminAction(() => onIPBanStatusChange(server.ip, !server.isIPBanned));
    }
  };

  const handleBPSSettingsClick = (event: React.MouseEvent) => {
    event.preventDefault();
    event.stopPropagation();
    setSliderIndex(bpsToSliderIndex(server.bps));
    setBpsInput(server.bps.toString());
    setShowBPSModal(true);
  };

  const handleSliderChange = (idx: number) => {
    setSliderIndex(idx);
    setBpsInput(BPS_STEPS[idx].toString());
  };

  const handleBPSSave = () => {
    const newBps = parseInt(bpsInput, 10) || 0;
    runAsyncAdminAction(() => onBPSChange(server.identityKey, newBps));
    setShowBPSModal(false);
  };

  const formatSliderLabel = (value: number): string => {
    if (value === 0) return "Unlimited";
    if (value >= 1000000) return `${value / 1000000} MB/s`;
    if (value >= 1000) return `${value / 1000} KB/s`;
    return `${value} B/s`;
  };

  const formatStepLabel = (value: number): string => {
    if (value === 0) return "No cap";
    if (value >= 1000000) return `${value / 1000000}M`;
    if (value >= 1000) return `${value / 1000}K`;
    return value.toString();
  };

  const formatBPS = (value: number): string => {
    if (value === 0) return "Unlimited";
    if (value >= 1_000_000_000)
      return `${(value / 1_000_000_000).toFixed(1)} GB/s`;
    if (value >= 1_000_000) return `${(value / 1_000_000).toFixed(1)} MB/s`;
    if (value >= 1_000) return `${(value / 1_000).toFixed(1)} KB/s`;
    return `${value} B/s`;
  };

  const selectButton = (
    <button
      onClick={handleSelectClick}
      className={clsx(
        "flex size-8 items-center justify-center rounded-md backdrop-blur-md transition-colors border border-white/8 cursor-pointer",
        isSelected
          ? "bg-primary text-black"
          : "bg-black/40 text-white/70 hover:bg-primary hover:text-black"
      )}
      aria-label={isSelected ? "Deselect" : "Select"}
    >
      <svg
        xmlns="http://www.w3.org/2000/svg"
        viewBox="0 0 24 24"
        className="w-4.5 h-4.5"
        fill="none"
        stroke="currentColor"
        strokeWidth="3"
        strokeLinecap="round"
        strokeLinejoin="round"
      >
        {isSelected && <polyline points="20 6 9 17 4 12" />}
      </svg>
    </button>
  );

  const adminControls = (
    <div className="flex flex-col gap-2 w-full mt-2">
      <div className="flex items-center justify-between w-full">
        <span className="text-xs text-white/60">
          BPS: <span className="font-medium text-white">{formatBPS(server.bps)}</span>
        </span>
        <button
          onClick={handleBPSSettingsClick}
          className="px-3 py-1 text-[10px] rounded-md bg-white/10 hover:bg-white/20 text-white/80 transition-colors cursor-pointer border border-white/10"
        >
          Settings
        </button>
      </div>

      {server.isApproved && server.ip && (
        <div className="text-[10px] text-white/50">
          IP: <span className="font-mono">{server.displayIP || server.ip}</span>
          {server.isIPBanned && (
            <span className="ml-2 text-red-400">(Banned)</span>
          )}
        </div>
      )}

      {!server.isApproved && !server.isDenied ? (
        <div className="flex gap-2 w-full">
          <button
            onClick={handleApproveClick}
            className="flex-1 px-4 py-2 rounded-md font-medium text-xs transition-colors cursor-pointer text-white bg-green-600/80 hover:bg-green-600 backdrop-blur-sm"
          >
            Approve
          </button>
          <button
            onClick={handleDenyClick}
            className="flex-1 px-4 py-2 rounded-md font-medium text-xs transition-colors cursor-pointer text-white bg-red-600/80 hover:bg-red-600 backdrop-blur-sm"
          >
            Deny
          </button>
        </div>
      ) : (
        <button
          onClick={server.ip ? handleIPBanClick : handleBanClick}
          className={clsx(
            "w-full px-4 py-2 rounded-md font-medium text-xs transition-colors cursor-pointer text-white backdrop-blur-sm",
            (server.ip ? server.isIPBanned : server.isBanned)
              ? "bg-green-600/80 hover:bg-green-600"
              : "bg-red-600/80 hover:bg-red-600"
          )}
        >
          {server.ip
            ? server.isIPBanned
              ? "Unban IP"
              : "Ban IP"
            : server.isBanned
              ? "Unban"
              : "Ban"}
        </button>
      )}
    </div>
  );

  return (
    <>
      <div className="relative">
        <ServerCardBody
          server={server}
          topRight={selectButton}
          footer={adminControls}
        />
      </div>

      <Dialog open={showBPSModal} onOpenChange={setShowBPSModal}>
        <DialogContent className="max-w-sm rounded-lg">
          <DialogHeader>
            <DialogTitle>BPS Settings</DialogTitle>
            <DialogDescription>
              Set bytes-per-second limit (0 = unlimited)
            </DialogDescription>
          </DialogHeader>
          <div className="text-center text-xl font-bold text-primary">
            {formatSliderLabel(parseInt(bpsInput, 10) || 0)}
          </div>
          <input
            type="range"
            min="0"
            max={BPS_STEPS.length - 1}
            value={sliderIndex}
            onChange={(event) => {
              const idx = parseInt(event.target.value, 10);
              handleSliderChange(idx);
            }}
            className="w-full h-2 bg-secondary rounded-md appearance-none cursor-pointer"
          />
          <div className="flex justify-between text-xs text-text-muted">
            {BPS_STEPS.map((step, idx) => (
              <span
                key={idx}
                className={clsx(
                  "cursor-pointer hover:text-foreground transition-colors",
                  sliderIndex === idx && "text-primary font-medium"
                )}
                onClick={() => handleSliderChange(idx)}
              >
                {formatStepLabel(step)}
              </span>
            ))}
          </div>
          <div>
            <label className="text-xs text-text-muted mb-1 block">
              Custom value (B/s)
            </label>
            <input
              type="number"
              value={bpsInput}
              onChange={(event) => {
                setBpsInput(event.target.value);
                const value = parseInt(event.target.value, 10) || 0;
                setSliderIndex(bpsToSliderIndex(value));
              }}
              className="w-full px-3 py-2 border border-foreground/20 rounded bg-background text-foreground"
              placeholder="Enter BPS limit"
              min="0"
            />
          </div>
          <DialogFooter className="gap-2 sm:gap-0">
            <Button
              className="cursor-pointer"
              variant="secondary"
              onClick={() => setShowBPSModal(false)}
            >
              Cancel
            </Button>
            <Button className="cursor-pointer" onClick={handleBPSSave}>
              Save
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
