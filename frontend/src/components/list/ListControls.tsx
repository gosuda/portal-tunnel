import { Search, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Chip } from "@/components/ui/chip";
import { Select } from "@/components/ui/input";
import type { SortOption } from "@/types/filters";

export function SearchField({ value, onChange }: { value: string; onChange: (value: string) => void }) {
  return (
    <div role="search" className="relative w-full">
      <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-content-muted" />
      <input
        type="search"
        aria-label="Search apps"
        placeholder="Search"
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="h-8 w-full rounded-full border border-stroke bg-surface-200 pl-9 pr-9 type-body-medium text-content-emphasis placeholder:text-content-muted focus-visible:border-primary [&::-webkit-search-cancel-button]:appearance-none"
      />
      {value && (
        <span className="absolute right-1 top-1/2 -translate-y-1/2">
          <button
            type="button"
            aria-label="Clear search"
            onClick={() => onChange("")}
            className="interactive flex size-6 items-center justify-center rounded-full text-content-muted"
          >
            <X className="size-4" />
          </button>
        </span>
      )}
    </div>
  );
}

interface TagChipsProps {
  availableTags: string[];
  selectedTags: string[];
  onTagToggle: (tag: string) => void;
  onClearTags: () => void;
}

export function TagChips({ availableTags, selectedTags, onTagToggle, onClearTags }: TagChipsProps) {
  if (availableTags.length === 0) return null;
  return (
    <div role="group" aria-label="Browse by tag" className="mb-8">
      <p className="mb-2 type-caption-large text-content-muted">Browse by tag</p>
      <div className="no-scrollbar flex gap-2 overflow-x-auto">
        <Chip selected={selectedTags.length === 0} onClick={onClearTags}>All</Chip>
        {availableTags.map((tag) => (
          <Chip key={tag} selected={selectedTags.includes(tag)} onClick={() => onTagToggle(tag)}>{tag}</Chip>
        ))}
      </div>
    </div>
  );
}

interface ListToolbarProps {
  sortBy: SortOption;
  onSortByChange: (value: SortOption) => void;
  showHidden: boolean;
  hiddenCount: number;
  onShowHiddenChange: (show: boolean) => void;
}

export function ListToolbar({ sortBy, onSortByChange, showHidden, hiddenCount, onShowHiddenChange }: ListToolbarProps) {
  return (
    <div className="flex flex-wrap items-center justify-end gap-2">
      {(hiddenCount > 0 || showHidden) && (
        <Button variant="ghost" size="sm" aria-pressed={showHidden} onClick={() => onShowHiddenChange(!showHidden)} className="text-content-muted">
          {showHidden ? "Hide downvoted apps" : `Show hidden apps (${hiddenCount})`}
        </Button>
      )}
      <Select aria-label="Sort by" value={sortBy} onChange={(event) => onSortByChange(event.target.value as SortOption)} className="h-8 w-auto">
        <option value="default">Newest</option>
        <option value="recommended">Most recommended</option>
        <option value="name-asc">Name (A-Z)</option>
        <option value="name-desc">Name (Z-A)</option>
        <option value="updated">Recently Updated</option>
        <option value="duration">Duration (Maintained)</option>
        <option value="description">Description</option>
        <option value="tags">Tags</option>
        <option value="owner">Owner</option>
      </Select>
    </div>
  );
}
