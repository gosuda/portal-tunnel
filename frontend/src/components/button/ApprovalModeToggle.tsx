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
}: ApprovalModeToggleProps) => (
  <div className="flex rounded-lg overflow-hidden border border-foreground/20">
    <button
      disabled={disabled}
      onClick={() => onApprovalModeChange("auto")}
      className={`cursor-pointer disabled:cursor-wait disabled:opacity-50 px-4 h-10 text-sm font-medium transition-colors ${
        approvalMode === "auto"
          ? "bg-primary text-primary-foreground"
          : "bg-secondary text-secondary-foreground hover:bg-secondary/80"
      }`}
    >
      Auto
    </button>
    <button
      disabled={disabled}
      onClick={() => onApprovalModeChange("manual")}
      className={`cursor-pointer disabled:cursor-wait disabled:opacity-50 px-4 h-10 text-sm font-medium transition-colors border-l border-foreground/20 ${
        approvalMode === "manual"
          ? "bg-primary text-primary-foreground"
          : "bg-secondary text-secondary-foreground hover:bg-secondary/80"
      }`}
    >
      Manual
    </button>
  </div>
);
