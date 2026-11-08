export type StatusFilter = "all" | "online" | "offline";
export type BanFilter = "all" | "banned" | "active";

export type SortOption =
  | "default"
  | "recommended"
  | "description"
  | "tags"
  | "owner"
  | "name-asc"
  | "name-desc"
  | "updated"
  | "duration";

/** The order the directory opens in and returns to on Home: newest first. */
export const DEFAULT_SORT: SortOption = "default";

export type TagMode = "AND" | "OR";

export type BrowseView = "home" | "favorites" | "relays";
