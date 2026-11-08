import { Search } from "lucide-react";
import { Chip } from "@/components/ui/chip";
import { Input, Select } from "@/components/ui/input";
import type { AdminState } from "@/hooks/useAdmin";
import type { BanFilter, SortOption, StatusFilter } from "@/types/filters";

type LeaseFiltersProps = Pick<
  AdminState,
  | "searchQuery"
  | "status"
  | "sortBy"
  | "banFilter"
  | "selectedTags"
  | "availableTags"
  | "handleSearchChange"
  | "handleStatusChange"
  | "handleSortByChange"
  | "handleBanFilterChange"
  | "handleTagToggle"
>;

const SELECT = "w-auto flex-1 md:flex-none";

export function LeaseFilters({
  searchQuery,
  status,
  sortBy,
  banFilter,
  selectedTags,
  availableTags,
  handleSearchChange,
  handleStatusChange,
  handleSortByChange,
  handleBanFilterChange,
  handleTagToggle,
}: LeaseFiltersProps) {
  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap gap-2">
        <div className="relative min-w-0 flex-1 basis-full sm:basis-64">
          <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-content-muted" aria-hidden />
          <Input
            type="search"
            aria-label="Search apps"
            placeholder="Search apps, descriptions, or tags"
            value={searchQuery}
            onChange={(event) => handleSearchChange(event.target.value)}
            className="pl-9"
          />
        </div>
        <Select aria-label="Status" className={SELECT} value={status} onChange={(event) => handleStatusChange(event.target.value as StatusFilter)}>
          <option value="all">All status</option>
          <option value="online">Online</option>
          <option value="offline">Offline</option>
        </Select>
        <Select aria-label="Ban status" className={SELECT} value={banFilter} onChange={(event) => handleBanFilterChange(event.target.value as BanFilter)}>
          <option value="all">All identities</option>
          <option value="active">Active</option>
          <option value="banned">Banned</option>
        </Select>
        <Select aria-label="Sort by" className={SELECT} value={sortBy} onChange={(event) => handleSortByChange(event.target.value as SortOption)}>
          <option value="default">Newest</option>
          <option value="name-asc">Name (A-Z)</option>
          <option value="name-desc">Name (Z-A)</option>
          <option value="updated">Recently updated</option>
          <option value="duration">Duration (maintained)</option>
          <option value="description">Description</option>
          <option value="tags">Tags</option>
          <option value="owner">Owner</option>
        </Select>
      </div>
      {availableTags.length > 0 && (
        <div role="group" aria-label="Tags" className="no-scrollbar flex gap-2 overflow-x-auto">
          {availableTags.map((tag) => (
            <Chip key={tag} selected={selectedTags.includes(tag)} onClick={() => handleTagToggle(tag)}>
              {tag}
            </Chip>
          ))}
        </div>
      )}
    </div>
  );
}
