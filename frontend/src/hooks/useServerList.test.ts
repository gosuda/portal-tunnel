import { act, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { PublicStateResponse } from "@/types/api";
import { useServerList } from "@/hooks/useServerList";
import { RELAY_API_PATHS } from "@/lib/apiPaths";
import { apiClient } from "@/lib/apiClient";

vi.mock("@/hooks/useList", () => ({
  useList: vi.fn(() => ({
    searchQuery: "",
    status: "all",
    sortBy: "default",
    selectedTags: [],
    favorites: [],
    availableTags: [],
    filteredServers: [],
    handleSearchChange: vi.fn(),
    handleStatusChange: vi.fn(),
    handleSortByChange: vi.fn(),
    handleTagToggle: vi.fn(),
    handleToggleFavorite: vi.fn(),
  })),
}));

vi.mock("@/lib/apiClient", async () => {
  const actual = await vi.importActual<typeof import("@/lib/apiClient")>(
    "@/lib/apiClient",
  );

  return {
    ...actual,
    apiClient: {
      get: vi.fn(),
      post: vi.fn(),
    },
  };
});

const mockGet = vi.mocked(apiClient.get);

function stateResponse(hostname: string): PublicStateResponse {
  return {
    leases: [
      {
        name: hostname,
        expires_at: "2026-03-04T00:00:00Z",
        first_seen_at: "2026-03-02T00:00:00Z",
        last_seen_at: "2026-03-03T00:00:00Z",
        hostname,
        metadata: {},
        ready: 1,
      },
    ],
    landing_page_enabled: false,
  };
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((res) => {
    resolve = res;
  });
  return { promise, resolve };
}

describe("useServerList /api/state polling", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    mockGet.mockReset();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  // The poller used to fire on a fixed interval regardless of in-flight
  // requests, so a slow older response could settle after a newer one and
  // regress state. The next request must be scheduled only after the previous
  // one settles.
  it("does not start the next request before the previous one settles", async () => {
    const first = deferred<PublicStateResponse>();
    mockGet.mockReturnValueOnce(first.promise);

    const { result } = renderHook(() => useServerList());
    expect(mockGet).toHaveBeenCalledTimes(1);
    expect(mockGet).toHaveBeenCalledWith(RELAY_API_PATHS.public.state);

    await act(async () => {
      await vi.advanceTimersByTimeAsync(10_000);
    });
    expect(mockGet).toHaveBeenCalledTimes(1);

    await act(async () => {
      first.resolve(stateResponse("first.example.com"));
      await vi.advanceTimersByTimeAsync(0);
    });
    expect(result.current.leases[0]?.hostname).toBe("first.example.com");

    await act(async () => {
      await vi.advanceTimersByTimeAsync(1_500);
    });
    expect(mockGet).toHaveBeenCalledTimes(2);
  });

  it("keeps polling on the serialized cadence", async () => {
    mockGet.mockResolvedValue(stateResponse("tick.example.com"));

    renderHook(() => useServerList());

    await act(async () => {
      await vi.advanceTimersByTimeAsync(1_500);
    });
    expect(mockGet).toHaveBeenCalledTimes(2);

    await act(async () => {
      await vi.advanceTimersByTimeAsync(1_500);
    });
    expect(mockGet).toHaveBeenCalledTimes(3);
  });

  it("stops scheduling after unmount", async () => {
    mockGet.mockResolvedValue(stateResponse("gone.example.com"));

    const { unmount } = renderHook(() => useServerList());
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });
    unmount();

    await act(async () => {
      await vi.advanceTimersByTimeAsync(10_000);
    });
    expect(mockGet).toHaveBeenCalledTimes(1);
  });
});
