import { useState } from "react";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Button } from "@/components/ui/button";

type BulkAction = "approve" | "deny" | "ban";

interface FloatingActionBarProps {
  selectedCount: number;
  totalCount: number;
  isAllSelected: boolean;
  onSelectAll: () => void;
  onApprove: () => void;
  onDeny: () => void;
  onBan: () => void;
}

export const FloatingActionBar = ({
  selectedCount,
  totalCount,
  isAllSelected,
  onSelectAll,
  onApprove,
  onDeny,
  onBan,
}: FloatingActionBarProps) => {
  const [selectedAction, setSelectedAction] = useState<BulkAction>("approve");

  const handleExecute = () => {
    switch (selectedAction) {
      case "approve":
        onApprove();
        break;
      case "deny":
        onDeny();
        break;
      case "ban":
        onBan();
        break;
    }
  };

  const getExecuteButtonStyle = () => {
    switch (selectedAction) {
      case "approve":
        return "bg-green-600 hover:bg-green-700";
      case "deny":
        return "bg-red-600 hover:bg-red-700";
      case "ban":
        return "bg-orange-600 hover:bg-orange-700";
    }
  };

  return (
    <div className="fixed bottom-6 left-1/2 -translate-x-1/2 z-50 animate-in slide-in-from-bottom-4 fade-in duration-200">
      <div className="flex items-center gap-2 px-3 py-2 bg-background rounded-xl shadow-2xl border border-foreground/20">
        <button
          onClick={onSelectAll}
          className={`px-3 h-10 text-sm font-medium rounded-lg transition-colors whitespace-nowrap ${
            isAllSelected
              ? "bg-primary text-primary-foreground"
              : "bg-secondary text-secondary-foreground hover:bg-secondary/80"
          }`}
        >
          {isAllSelected ? "Deselect" : "Select All"}
        </button>
        <span className="text-sm font-medium text-foreground whitespace-nowrap px-1">
          {selectedCount}/{totalCount}
        </span>
        {selectedCount > 0 && (
          <>
            <Select
              value={selectedAction}
              onValueChange={(v) => setSelectedAction(v as BulkAction)}
            >
              <SelectTrigger className="w-25 h-10">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="approve">Approve</SelectItem>
                <SelectItem value="deny">Deny</SelectItem>
                <SelectItem value="ban">Ban</SelectItem>
              </SelectContent>
            </Select>
            <Button
              onClick={handleExecute}
              className={`h-10 px-4 text-white ${getExecuteButtonStyle()}`}
            >
              Run
            </Button>
          </>
        )}
      </div>
    </div>
  );
};
