import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import type { StatusFilter } from "@/types/filters";
import clsx from "clsx";

interface StatusSelectProps {
  status: StatusFilter;
  onStatusChange: (value: StatusFilter) => void;
  hideFiltersOnMobile?: boolean;
  className?: string;
}

export const StatusSelect = ({
  status,
  onStatusChange,
  hideFiltersOnMobile,
  className,
}: StatusSelectProps) => (
  <Select
    value={status}
    onValueChange={(value) => onStatusChange(value as StatusFilter)}
  >
    <SelectTrigger
      className={clsx(
        "w-32.5 h-10 border-border!",
        hideFiltersOnMobile && "hidden sm:flex",
        className
      )}
    >
      <SelectValue placeholder="Status" />
    </SelectTrigger>
    <SelectContent>
      <SelectItem value="all">All Status</SelectItem>
      <SelectItem value="online">Online</SelectItem>
      <SelectItem value="offline">Offline</SelectItem>
    </SelectContent>
  </Select>
);
