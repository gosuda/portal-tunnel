import type { JSX } from "react";
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
  onBPSChange: (identityKey: string, bps: number | null) => void | Promise<void>;
  onApproveStatusChange: (identityKey: string, approve: boolean) => void | Promise<void>;
  onDenyStatusChange: (identityKey: string, deny: boolean) => void | Promise<void>;
}
const BPS_STEPS = [0, 10, 100, 1000, 10000, 100000, 1000000, 10000000];

function sliderIndexForBPS(value: number): number {
  if (value === 0) return 0;
  const idx = BPS_STEPS.findIndex((step) => step >= value);
  return idx === -1 ? BPS_STEPS.length - 1 : idx;
}

function runAsyncAdminAction(action: () => void | Promise<void>): void {
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
}

function swallowCardClick(event: React.MouseEvent): void {
  event.preventDefault();
  event.stopPropagation();
}

function parseBPSInput(value: string): number {
  return parseInt(value, 10) || 0;
}

function formatSliderLabel(value: number): string {
  if (value === 0) return "Unlimited";
  if (value >= 1000000) return `${value / 1000000} MB/s`;
  if (value >= 1000) return `${value / 1000} KB/s`;
  return `${value} B/s`;
}

function formatStepLabel(value: number): string {
  if (value === 0) return "No cap";
  if (value >= 1000000) return `${value / 1000000}M`;
  if (value >= 1000) return `${value / 1000}K`;
  return value.toString();
}

function formatBPS(value: number): string {
  if (value === 0) return "Unlimited";
  if (value >= 1_000_000_000)
    return `${(value / 1_000_000_000).toFixed(1)} GB/s`;
  if (value >= 1_000_000) return `${(value / 1_000_000).toFixed(1)} MB/s`;
  if (value >= 1_000) return `${(value / 1_000).toFixed(1)} KB/s`;
  return `${value} B/s`;
}

function runIdentityAction(identityKey: string, action: (key: string) => void | Promise<void>): void {
  if (!identityKey) {
    return;
  }
  runAsyncAdminAction(() => action(identityKey));
}

function SelectAction({ isSelected, onSelectClick }: { isSelected: boolean; onSelectClick: (event: React.MouseEvent) => void }): JSX.Element {
  return (
    <button
      onClick={onSelectClick}
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
}

function IPLine({ isApproved, ip, displayIP }: { isApproved: boolean; ip: string; displayIP: string }): JSX.Element | null {
  if (!isApproved || !ip) {
    return null;
  }
  if (displayIP && displayIP !== ip) {
    return (
      <div className="text-[10px] text-muted-foreground">
        <div>
          Client IP: <span className="font-mono">{ip}</span>
        </div>
        <div>
          Reported IP: <span className="font-mono">{displayIP}</span>
        </div>
      </div>
    );
  }
  return (
    <div className="text-[10px] text-muted-foreground">
      IP: <span className="font-mono">{ip}</span>
    </div>
  );
}

function ModerationControls({ isApproved, isDenied, isBanned, onApproveClick, onDenyClick, onBanClick }: { isApproved: boolean; isDenied: boolean; isBanned: boolean; onApproveClick: (event: React.MouseEvent) => void; onDenyClick: (event: React.MouseEvent) => void; onBanClick: (event: React.MouseEvent) => void }): JSX.Element {
  if (!isApproved && !isDenied) {
    return (
      <div className="flex gap-2 w-full">
        <button
          onClick={onApproveClick}
          className="flex-1 px-4 py-2 rounded-md font-medium text-xs transition-colors cursor-pointer text-white bg-green-600/80 hover:bg-green-600 backdrop-blur-sm"
        >
          Approve
        </button>
        <button
          onClick={onDenyClick}
          className="flex-1 px-4 py-2 rounded-md font-medium text-xs transition-colors cursor-pointer text-white bg-red-600/80 hover:bg-red-600 backdrop-blur-sm"
        >
          Deny
        </button>
      </div>
    );
  }
  return (
    <button
      onClick={onBanClick}
      className={clsx(
        "w-full px-4 py-2 rounded-md font-medium text-xs transition-colors cursor-pointer text-white backdrop-blur-sm",
        isBanned
          ? "bg-green-600/80 hover:bg-green-600"
          : "bg-red-600/80 hover:bg-red-600"
      )}
    >
      {isBanned ? "Unban identity" : "Ban identity"}
    </button>
  );
}

function IdentityPanel({ server, bps, onBPSSettingsClick, onApproveClick, onDenyClick, onBanClick }: { server: AdminServer; bps: number; onBPSSettingsClick: (event: React.MouseEvent) => void; onApproveClick: (event: React.MouseEvent) => void; onDenyClick: (event: React.MouseEvent) => void; onBanClick: (event: React.MouseEvent) => void }): JSX.Element | null {
  if (!server.identityKey) {
    return null;
  }
  return (
    <div className="flex flex-col gap-2 w-full mt-2">
      <div className="flex items-center justify-between w-full">
        <span className="text-xs text-muted-foreground">
          BPS: <span className="font-medium text-foreground">{formatBPS(bps)}</span>
        </span>
        <button
          onClick={onBPSSettingsClick}
          className="px-3 py-1 text-[10px] rounded-md bg-secondary hover:bg-accent text-foreground transition-colors cursor-pointer border border-border"
        >
          Settings
        </button>
      </div>
      <IPLine isApproved={server.isApproved} ip={server.ip} displayIP={server.displayIP} />
      <ModerationControls isApproved={server.isApproved} isDenied={server.isDenied} isBanned={server.isBanned} onApproveClick={onApproveClick} onDenyClick={onDenyClick} onBanClick={onBanClick} />
    </div>
  );
}

function BPSDialog({ showBPSModal, onOpenChange, bpsInput, sliderIndex, onSliderChange, onBPSInputChange, onUseDefault, onClose, onSave }: { showBPSModal: boolean; onOpenChange: (open: boolean) => void; bpsInput: string; sliderIndex: number; onSliderChange: (idx: number) => void; onBPSInputChange: (value: string) => void; onUseDefault: () => void; onClose: () => void; onSave: () => void }): JSX.Element {
  return (
    <Dialog open={showBPSModal} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-sm rounded-lg">
        <DialogHeader>
          <DialogTitle>BPS Settings</DialogTitle>
          <DialogDescription>
            Set bytes-per-second limit (0 = unlimited)
          </DialogDescription>
        </DialogHeader>
        <div className="text-center text-xl font-bold text-primary">
          {formatSliderLabel(parseBPSInput(bpsInput))}
        </div>
        <input
          type="range"
          min="0"
          max={BPS_STEPS.length - 1}
          value={sliderIndex}
          onChange={(event) => {
            onSliderChange(parseBPSInput(event.target.value));
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
              onClick={() => onSliderChange(idx)}
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
              onBPSInputChange(event.target.value);
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
            onClick={onUseDefault}
          >
            Use relay default
          </Button>
          <Button
            className="cursor-pointer"
            variant="secondary"
            onClick={onClose}
          >
            Cancel
          </Button>
          <Button className="cursor-pointer" onClick={onSave}>
            Save
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export function AdminServerCard({
  server,
  isSelected,
  onToggleSelect,
  onBanStatusChange,
  onBPSChange,
  onApproveStatusChange,
  onDenyStatusChange,
}: AdminServerCardProps): JSX.Element {
  const { identityKey, bps } = server;
  const [showBPSModal, setShowBPSModal] = useState(false);
  const [bpsInput, setBpsInput] = useState(bps.toString());

  const [sliderIndex, setSliderIndex] = useState(sliderIndexForBPS(bps));

  const handleSliderChange = (idx: number) => {
    setSliderIndex(idx);
    setBpsInput(BPS_STEPS[idx].toString());
  };

  const syncSliderFromInput = (value: number) => {
    const idx = sliderIndexForBPS(value);
    setSliderIndex(idx);
  };

  const handleSelectClick = (event: React.MouseEvent) => {
    swallowCardClick(event);
    runIdentityAction(identityKey, onToggleSelect);
  };

  const handleBanClick = (event: React.MouseEvent) => {
    swallowCardClick(event);
    runIdentityAction(identityKey, (key) => onBanStatusChange(key, !server.isBanned));
  };

  const handleApproveClick = (event: React.MouseEvent) => {
    swallowCardClick(event);
    runIdentityAction(identityKey, (key) => onApproveStatusChange(key, !server.isApproved));
  };

  const handleDenyClick = (event: React.MouseEvent) => {
    swallowCardClick(event);
    runIdentityAction(identityKey, (key) => onDenyStatusChange(key, !server.isDenied));
  };

  const handleBPSSettingsClick = (event: React.MouseEvent) => {
    swallowCardClick(event);
    setSliderIndex(sliderIndexForBPS(bps));
    setBpsInput(bps.toString());
    setShowBPSModal(true);
  };

  const handleBPSSave = () => {
    runIdentityAction(identityKey, (key) => onBPSChange(key, parseBPSInput(bpsInput)));
    setShowBPSModal(false);
  };

  const handleBPSInputChange = (value: string) => {
    setBpsInput(value);
    syncSliderFromInput(parseBPSInput(value));
  };

  const handleBPSUseDefault = () => {
    runAsyncAdminAction(() => onBPSChange(identityKey, null));
    setShowBPSModal(false);
  };

  const handleBPSClose = () => {
    setShowBPSModal(false);
  };


  return (
    <>
      <ServerCard
        server={server}
        navigable={false}
        action={
          <SelectAction isSelected={isSelected} onSelectClick={handleSelectClick} />
        }
      >
        {identityKey && (
          <IdentityPanel server={server} bps={bps} onBPSSettingsClick={handleBPSSettingsClick} onApproveClick={handleApproveClick} onDenyClick={handleDenyClick} onBanClick={handleBanClick} />
        )}
      </ServerCard>
      <BPSDialog showBPSModal={showBPSModal} onOpenChange={setShowBPSModal} bpsInput={bpsInput} sliderIndex={sliderIndex} onSliderChange={handleSliderChange} onBPSInputChange={handleBPSInputChange} onUseDefault={handleBPSUseDefault} onClose={handleBPSClose} onSave={handleBPSSave} />
    </>
  );
}
