import type { BanFilter } from "@/types/filters";
import clsx from "clsx";

interface BanStatusButtonsProps {
  banFilter: BanFilter;
  onBanFilterChange: (value: BanFilter) => void;
  className?: string;
}

export const BanStatusButtons = ({
  banFilter,
  onBanFilterChange,
  className,
}: BanStatusButtonsProps) => (
  <div
    className={clsx(
      "flex rounded-lg overflow-hidden border border-foreground/20",
      className
    )}
  >
    <button
      onClick={() => onBanFilterChange("all")}
      className={`cursor-pointer px-4 h-10 text-sm font-medium transition-colors ${
        banFilter === "all"
          ? "bg-primary text-primary-foreground"
          : "bg-secondary text-secondary-foreground hover:bg-secondary/80"
      }`}
    >
      All
    </button>
    <button
      onClick={() => onBanFilterChange("active")}
      className={`cursor-pointer px-4 h-10 text-sm font-medium transition-colors border-l border-foreground/20 ${
        banFilter === "active"
          ? "bg-green-600 text-white"
          : "bg-secondary text-secondary-foreground hover:bg-secondary/80"
      }`}
    >
      Active
    </button>
    <button
      onClick={() => onBanFilterChange("banned")}
      className={`cursor-pointer px-4 h-10 text-sm font-medium transition-colors border-l border-foreground/20 ${
        banFilter === "banned"
          ? "bg-red-600 text-white"
          : "bg-secondary text-secondary-foreground hover:bg-secondary/80"
      }`}
    >
      Banned
    </button>
  </div>
);
