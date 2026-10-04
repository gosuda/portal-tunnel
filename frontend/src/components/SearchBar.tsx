import { Search, Settings } from "lucide-react";
import { Input } from "@/components/ui/input";
import type { SortOption, StatusFilter } from "@/types/filters";
import { TagCombobox } from "@/components/TagCombobox";
import type { Dispatch, SetStateAction } from "react";
import { StatusSelect } from "@/components/select/StatusSelect";
import { SortbySelect } from "@/components/select/SortbySelect";

interface SearchBarProps {
  searchQuery: string;
  onSearchChange: (value: string) => void;
  status: StatusFilter;
  onStatusChange: (value: StatusFilter) => void;
  sortBy: SortOption;
  onSortByChange: (value: SortOption) => void;
  availableTags: string[];
  selectedTags: string[];
  onAddTag: (tag: string) => void;
  onRemoveTag: (tag: string) => void;
  hideFiltersOnMobile?: boolean;
  allowRecommendationSort?: boolean;
  setShowFilterModal?: Dispatch<SetStateAction<boolean>>;
}

export function SearchBar({
  searchQuery,
  onSearchChange,
  status,
  onStatusChange,
  sortBy,
  onSortByChange,
  availableTags,
  selectedTags,
  onAddTag,
  onRemoveTag,
  hideFiltersOnMobile = false,
  allowRecommendationSort = false,
  setShowFilterModal,
}: SearchBarProps) {
  return (
    <div className="flex flex-wrap mt-4 sm:mt-6 items-center gap-3 px-0">
      <div className="flex gap-2 items-center w-full">
        <label className="flex min-w-55 flex-1 items-stretch h-10 relative">
          <div className="left-0 h-full absolute text-text-muted flex items-center justify-center pl-3 pr-2 rounded-l-md bg-border border border-border">
            <Search className="w-4 h-4" />
          </div>
          <Input
            placeholder="Search live apps..."
            value={searchQuery}
            onChange={(e) => onSearchChange(e.target.value)}
            className="h-10 pl-12 border border-border rounded-md"
          />
        </label>
        {hideFiltersOnMobile && setShowFilterModal && (
          <button
            onClick={() => setShowFilterModal(true)}
            className="sm:hidden flex items-center justify-center w-10 h-10 rounded-lg bg-secondary hover:bg-secondary/80 transition-colors"
            aria-label="Filter settings"
          >
            <Settings className="w-5 h-5 text-secondary-foreground" />
          </button>
        )}
      </div>

      <StatusSelect
        status={status}
        onStatusChange={onStatusChange}
        hideFiltersOnMobile={hideFiltersOnMobile}
      />

      <SortbySelect
        allowRecommendationSort={allowRecommendationSort}
        sortBy={sortBy}
        onSortByChange={onSortByChange}
        hideFiltersOnMobile={hideFiltersOnMobile}
      />

      <div
        className={`relative flex w-full sm:w-auto sm:min-w-[320px] flex-1 ${
          hideFiltersOnMobile ? "hidden sm:flex" : ""
        }`}
      >
        <TagCombobox
          availableTags={availableTags}
          selectedTags={selectedTags}
          onAdd={onAddTag}
          onRemove={onRemoveTag}
        />
      </div>
    </div>
  );
}
