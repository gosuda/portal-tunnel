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

export const DEFAULT_SORT: SortOption = "default";

export type BrowseView = "home" | "favorites" | "relays";
