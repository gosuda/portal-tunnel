import { useState } from "react";
import clsx from "clsx";
import { ServerCard } from "@/components/ServerCard";
import type { AdminServer } from "@/hooks/useAdmin";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";

interface AdminServerCardProps {
  server: AdminServer;
  isSelected: boolean;
  onToggleSelect: (identityKey: string) => void;
  onBanStatusChange: (identityKey: string, isBan: boolean) => void | Promise<void>;
  onBPSChange: (identityKey: string, bps: number) => void | Promise<void>;
  onApproveStatusChange: (identityKey: string, approve: boolean) => void | Promise<void>;
  onDenyStatusChange: (identityKey: string, deny: boolean) => void | Promise<void>;
}

export function AdminServerCard({
  server,
  isSelected,
  onToggleSelect,
  onBanStatusChange,
  onBPSChange,
  onApproveStatusChange,
  onDenyStatusChange,
}: AdminServerCardProps) {
  const { identityKey, isBanned, isApproved, isDenied, bps, ip, displayIP } = server;
  const [showBPSModal, setShowBPSModal] = useState(false);
  const [bpsInput, setBpsInput] = useState(bps.toString());
  const bpsSteps = [0, 10, 100, 1000, 10000, 100000, 1000000, 10000000];

  const bpsToSliderIndex = (value: number): number => {
    if (value === 0) return 0;
    const idx = bpsSteps.findIndex((step) => step >= value);
    return idx === -1 ? bpsSteps.length - 1 : idx;
  };

  const [sliderIndex, setSliderIndex] = useState(bpsToSliderIndex(bps));

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

  const handleSliderChange = (idx: number) => {
    setSliderIndex(idx);
    setBpsInput(bpsSteps[idx].toString());
  };

  const syncSliderFromInput = (value: number) => {
    const idx = bpsToSliderIndex(value);
    setSliderIndex(idx);
  };

  const handleSelectClick = (event: React.MouseEvent) => {
    event.preventDefault();
    event.stopPropagation();
    if (identityKey) {
      onToggleSelect(identityKey);
    }
  };

  const handleBanClick = (event: React.MouseEvent) => {
    event.preventDefault();
    event.stopPropagation();
    if (identityKey) {
      runAsyncAdminAction(() => onBanStatusChange(identityKey, !isBanned));
    }
  };

  const handleApproveClick = (event: React.MouseEvent) => {
    event.preventDefault();
    event.stopPropagation();
    if (identityKey) {
      runAsyncAdminAction(() => onApproveStatusChange(identityKey, !isApproved));
    }
  };

  const handleDenyClick = (event: React.MouseEvent) => {
    event.preventDefault();
    event.stopPropagation();
    if (identityKey) {
      runAsyncAdminAction(() => onDenyStatusChange(identityKey, !isDenied));
    }
  };

  const handleBPSSettingsClick = (event: React.MouseEvent) => {
    event.preventDefault();
    event.stopPropagation();
    setSliderIndex(bpsToSliderIndex(bps));
    setBpsInput(bps.toString());
    setShowBPSModal(true);
  };

  const handleBPSSave = () => {
    if (identityKey) {
      const newBps = parseInt(bpsInput, 10) || 0;
      runAsyncAdminAction(() => onBPSChange(identityKey, newBps));
    }
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

  return (
    <>
      <ServerCard
        server={server}
        navigable={false}
        action={
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
        }
      >
        {identityKey && (
          <div className="flex flex-col gap-2 w-full mt-2">
            <div className="flex items-center justify-between w-full">
              <span className="text-xs text-white/60">
                BPS: <span className="font-medium text-white">{formatBPS(bps)}</span>
              </span>
              <button
                onClick={handleBPSSettingsClick}
                className="px-3 py-1 text-[10px] rounded-md bg-white/10 hover:bg-white/20 text-white/80 transition-colors cursor-pointer border border-white/10"
              >
                Settings
              </button>
            </div>

            {isApproved && ip && (
              <div className="text-[10px] text-white/50">
                {displayIP && displayIP !== ip ? (
                  <>
                    <div>
                      Client IP: <span className="font-mono">{ip}</span>
                    </div>
                    <div>
                      Reported IP: <span className="font-mono">{displayIP}</span>
                    </div>
                  </>
                ) : (
                  <>
                    IP: <span className="font-mono">{ip}</span>
                  </>
                )}
              </div>
            )}

            {!isApproved && !isDenied ? (
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
                onClick={handleBanClick}
                className={clsx(
                  "w-full px-4 py-2 rounded-md font-medium text-xs transition-colors cursor-pointer text-white backdrop-blur-sm",
                  isBanned
                    ? "bg-green-600/80 hover:bg-green-600"
                    : "bg-red-600/80 hover:bg-red-600"
                )}
              >
                {isBanned ? "Unban identity" : "Ban identity"}
              </button>
            )}
          </div>
        )}
      </ServerCard>

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
            max={bpsSteps.length - 1}
            value={sliderIndex}
            onChange={(event) => {
              const idx = parseInt(event.target.value, 10);
              handleSliderChange(idx);
            }}
            className="w-full h-2 bg-secondary rounded-md appearance-none cursor-pointer"
          />
          <div className="flex justify-between text-xs text-text-muted">
            {bpsSteps.map((step, idx) => (
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
                syncSliderFromInput(parseInt(event.target.value, 10) || 0);
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
