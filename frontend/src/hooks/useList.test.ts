import { act, renderHook } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { useList } from "./useList";
import type { BaseServer } from "@/lib/server";

const server = (id: string, up?: number, name = id): BaseServer => ({
  id,
  name,
  description: "",
  tags: ["tools"],
  thumbnail: "",
  owner: "",
  online: true,
  dns: id,
  link: `https://${id}/`,
  ...(up === undefined ? {} : {
    reputation: { hostname: id, up, down: 0, total: up, viewer_vote: "" },
  }),
});

describe("filter reset", () => {
  it("clears search, status and tags and applies the given order", () => {
    const servers = [server("b"), { ...server("a"), online: false }];
    const { result } = renderHook(() => useList({ servers }));

    act(() => {
      result.current.handleSearchChange("zzz");
      result.current.handleStatusChange("online");
      result.current.handleTagToggle("tools");
    });
    expect(result.current.filteredServers).toEqual([]);

    act(() => result.current.resetFilters("name-asc"));

    expect(result.current.searchQuery).toBe("");
    expect(result.current.status).toBe("all");
    expect(result.current.selectedTags).toEqual([]);
    expect(result.current.filteredServers.map(({ id }) => id)).toEqual(["a", "b"]);
  });

  it("defaults to newest first by firstSeen timestamp", () => {
    const servers = [
      { ...server("old"), firstSeen: "2026-01-01T00:00:00Z" },
      { ...server("newest"), firstSeen: "2026-01-03T00:00:00Z" },
      { ...server("middle"), firstSeen: "2026-01-02T00:00:00Z" },
    ];
    const { result } = renderHook(() => useList({ servers }));

    expect(result.current.filteredServers.map(({ id }) => id)).toEqual([
      "newest", "middle", "old",
    ]);
  });
});

describe("default order", () => {
  it("opens in the order resetFilters returns to", () => {
    const { result } = renderHook(() => useList({ servers: [server("a")] }));
    const initial = result.current.sortBy;
    act(() => {
      result.current.handleSortByChange("name-desc");
      result.current.resetFilters();
    });
    expect(result.current.sortBy).toBe(initial);
  });
});

describe("recommendation sorting", () => {
  it("orders by recommendation count, then name and hostname, treating missing votes as zero", () => {
    const servers = [
      server("z", 4, "Same name"),
      server("unrated"),
      server("a", 4, "Same name"),
      server("zero", 0),
      server("popular", 12),
      server("alpha", 4, "Alpha"),
    ];
    const { result } = renderHook(() => useList({ servers }));

    act(() => result.current.handleSortByChange("recommended"));

    expect(result.current.filteredServers.map(({ id }) => id)).toEqual([
      "popular", "alpha", "a", "z", "unrated", "zero",
    ]);
  });

  it("applies recommendation order to the filtered apps", () => {
    const servers = [
      server("favorite-low", 1),
      server("popular", 12),
      server("favorite-high", 4),
      { ...server("offline", 100), online: false },
      { ...server("other-tag", 100), tags: ["games"] },
    ];
    const { result } = renderHook(() => useList({ servers }));

    act(() => {
      result.current.handleStatusChange("online");
      result.current.handleTagToggle("tools");
      result.current.handleSortByChange("recommended");
    });

    expect(result.current.filteredServers.map(({ id }) => id)).toEqual([
      "popular", "favorite-high", "favorite-low",
    ]);
  });

  it("reorders when refreshed vote counts change without resetting the selected sort", () => {
    const { result, rerender } = renderHook(
      ({ servers }) => useList({ servers }),
      { initialProps: { servers: [server("alpha", 2), server("beta", 1)] } }
    );
    act(() => result.current.handleSortByChange("recommended"));
    expect(result.current.filteredServers.map(({ id }) => id)).toEqual(["alpha", "beta"]);

    rerender({ servers: [server("alpha", 2), server("beta", 3)] });

    expect(result.current.sortBy).toBe("recommended");
    expect(result.current.filteredServers.map(({ id }) => id)).toEqual(["beta", "alpha"]);
  });
});
