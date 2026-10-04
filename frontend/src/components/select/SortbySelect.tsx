import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import type { SortOption } from "@/types/filters";
import clsx from "clsx";

interface SortbySelectProps {
  sortBy: SortOption;
  onSortByChange: (value: SortOption) => void;
  hideFiltersOnMobile?: boolean;
  allowRecommendationSort?: boolean;
  className?: string;
}

export const SortbySelect = ({
  sortBy,
  onSortByChange,
  hideFiltersOnMobile,
  allowRecommendationSort = false,
  className,
}: SortbySelectProps) => (
  <Select
    value={sortBy}
    onValueChange={(value) => onSortByChange(value as SortOption)}
  >
    <SelectTrigger
      aria-label="Sort by"
      className={clsx(
        "h-10 border-border!",
        allowRecommendationSort ? "w-48" : "w-37.5",
        hideFiltersOnMobile && "hidden sm:flex",
        className
      )}
    >
      <SelectValue placeholder="Sort By" />
    </SelectTrigger>
    <SelectContent>
      <SelectItem value="default">Default</SelectItem>
      {allowRecommendationSort && (
        <SelectItem value="recommended">Most recommended</SelectItem>
      )}
      <SelectItem value="name-asc">Name (A-Z)</SelectItem>
      <SelectItem value="name-desc">Name (Z-A)</SelectItem>
      <SelectItem value="updated">Recently Updated</SelectItem>
      <SelectItem value="duration">Duration (Maintained)</SelectItem>
      <SelectItem value="description">Description</SelectItem>
      <SelectItem value="tags">Tags</SelectItem>
      <SelectItem value="owner">Owner</SelectItem>
    </SelectContent>
  </Select>
);
