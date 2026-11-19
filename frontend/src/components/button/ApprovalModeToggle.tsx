import type { JSX } from "react";
import type { ApprovalMode } from "@/hooks/useAdmin";

interface ApprovalModeToggleProps {
  approvalMode: ApprovalMode;
  disabled?: boolean;
  onApprovalModeChange: (mode: ApprovalMode) => void;
}

export const ApprovalModeToggle = ({
  approvalMode,
  disabled = false,
  onApprovalModeChange,
}: ApprovalModeToggleProps): JSX.Element => (
  <div className="flex rounded-lg overflow-hidden border border-foreground/20">
    {(["auto", "manual", "strict"] as const).map((mode) => (
      <button
        key={mode}
        disabled={disabled}
        aria-pressed={approvalMode === mode}
        onClick={() => onApprovalModeChange(mode)}
        className={`cursor-pointer disabled:cursor-wait disabled:opacity-50 px-4 h-10 text-sm font-medium capitalize transition-colors ${approvalMode === mode
          ? "bg-primary text-primary-foreground"
          : "bg-secondary text-secondary-foreground hover:bg-secondary/80"}`}
      >
        {mode}
      </button>
    ))}
  </div>
);
