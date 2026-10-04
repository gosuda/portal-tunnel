import { act, renderHook } from "@testing-library/react";
import { beforeEach, describe, expect, it } from "vitest";
import { useList, type BaseServer } from "./useList";

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

beforeEach(() => localStorage.clear());

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
    const { result } = renderHook(() => useList({ servers, storageKey: "favorites" }));

    act(() => result.current.handleSortByChange("recommended"));

    expect(result.current.filteredServers.map(({ id }) => id)).toEqual([
      "popular", "alpha", "a", "z", "unrated", "zero",
    ]);
  });

  it("keeps favorites first and applies recommendation order within the filtered groups", () => {
    const servers = [
      server("favorite-low", 1),
      server("popular", 12),
      server("favorite-high", 4),
      { ...server("offline", 100), online: false },
      { ...server("other-tag", 100), tags: ["games"] },
    ];
    const { result } = renderHook(() => useList({ servers, storageKey: "favorites" }));

    act(() => {
      result.current.handleToggleFavorite("favorite-low");
      result.current.handleToggleFavorite("favorite-high");
      result.current.handleStatusChange("online");
      result.current.handleTagToggle("tools");
      result.current.handleSortByChange("recommended");
    });

    expect(result.current.filteredServers.map(({ id }) => id)).toEqual([
      "favorite-high", "favorite-low", "popular",
    ]);
  });

  it("reorders when refreshed vote counts change without resetting the selected sort", () => {
    const { result, rerender } = renderHook(
      ({ servers }) => useList({ servers, storageKey: "favorites" }),
      { initialProps: { servers: [server("alpha", 2), server("beta", 1)] } }
    );
    act(() => result.current.handleSortByChange("recommended"));
    expect(result.current.filteredServers.map(({ id }) => id)).toEqual(["alpha", "beta"]);

    rerender({ servers: [server("alpha", 2), server("beta", 3)] });

    expect(result.current.sortBy).toBe("recommended");
    expect(result.current.filteredServers.map(({ id }) => id)).toEqual(["beta", "alpha"]);
  });
});
