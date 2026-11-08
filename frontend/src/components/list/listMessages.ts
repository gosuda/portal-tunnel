import type { BrowseView, SortOption } from "@/types/filters";

export function appListTitle(browseView: BrowseView, searchQuery: string, sortBy: SortOption): string {
  if (browseView === "favorites") return "Favorites";
  if (searchQuery.trim() !== "") return `Results for ${searchQuery}`;
  if (sortBy === "recommended") return "Most recommended";
  return "Home";
}

export function emptyListMessage(
  browseView: BrowseView,
  connecting: boolean,
  filtered: boolean
): { title: string; body: string } {
  if (connecting) return { title: "Finding live apps", body: "Waiting for this relay to respond." };
  if (filtered) return { title: "No results found", body: "Try another search or change your filters." };
  if (browseView === "favorites") {
    return { title: "Keep your favorite apps here", body: "Recommend an app to find it here later." };
  }
  return { title: "No apps are live yet", body: "Create a tunnel to share your first app." };
}
