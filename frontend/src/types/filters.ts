export type StatusFilter = "all" | "online" | "offline";
export type BanFilter = "all" | "banned" | "active";

export type SortOption =
  | "default"
  | "description"
  | "tags"
  | "owner"
  | "name-asc"
  | "name-desc"
  | "updated"
  | "duration";

export type TagMode = "AND" | "OR";
