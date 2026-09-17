import { act, renderHook, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { useServerList } from "./useServerList";
import { apiClient } from "@/lib/apiClient";
import type { ReputationSummary } from "@/types/api";

vi.mock("@/lib/apiClient", () => ({
  apiClient: {
    get: vi.fn(),
    postReputationVote: vi.fn(),
  },
}));

const HOSTNAME = "minecraft.relay.example.com";

function mockPublicState(
  leases?: { hostname: string; name?: string }[]
) {
  vi.mocked(apiClient.get).mockResolvedValueOnce({
    leases:
      leases ??
      [
        {
          name: "minecraft",
          hostname: HOSTNAME,
          ready: 1,
          expires_at: "2099-01-01T00:00:00Z",
          first_seen_at: "2026-01-01T00:00:00Z",
          last_seen_at: "2026-01-01T00:00:00Z",
          metadata: {},
          reputation: {
            up: 1,
            down: 0,
            total: 1,
            down_ratio: 0,
            warning: false,
            viewer_vote: "",
            is_new: false,
            identity_changed_recently: false,
          },
        },
      ],
    landing_page_enabled: false,
  });
}

function voteSummary(
  overrides?: Partial<ReputationSummary>
): ReputationSummary {
  return {
    up: 0,
    down: 0,
    total: 0,
    down_ratio: 0,
    warning: false,
    viewer_vote: "",
    is_new: false,
    identity_changed_recently: false,
    ...overrides,
  };
}

describe("useServerList", () => {
  beforeEach(() => {
    // Auto-advance fake timers so waitFor gets real elapsed time.
    vi.useFakeTimers({ shouldAdvanceTime: true });
    mockPublicState();
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.clearAllMocks();
  });

  describe("handleVote stale-response race", () => {
    it("discards a slow first response when a fast second vote fires for the same hostname", async () => {
      const { result } = renderHook(() => useServerList());

      await waitFor(
        () => {
          expect(result.current.filteredServers.length).toBeGreaterThan(0);
        },
        { timeout: 5000 }
      );

      // Deferred resolver for the "slow" first vote.
      let resolveSlow: (v: ReputationSummary) => void = () => {};
      const slowPromise = new Promise<ReputationSummary>((r) => {
        resolveSlow = r;
      });

      vi.mocked(apiClient.postReputationVote).mockImplementationOnce(
        () => slowPromise
      );
      // Immediate resolve for the "fast" second vote.
      vi.mocked(apiClient.postReputationVote).mockImplementationOnce(() =>
        Promise.resolve(voteSummary({ up: 5, total: 5 }))
      );

      // Fire first (slow) vote — seq=1
      await act(async () => {
        void result.current.onVote(HOSTNAME, "up");
      });

      // Fire second (fast) vote before the first resolves — seq=2
      await act(async () => {
        void result.current.onVote(HOSTNAME, "up");
      });

      // Now resolve the slow first promise — seq won't match (2 != 1), discarded.
      act(() => {
        resolveSlow(voteSummary({ up: 99, total: 99 }));
      });

      await waitFor(
        () => {
          const server = result.current.filteredServers.find(
            (s) => s.id === HOSTNAME
          );
          // Fast vote (up=5) must win; stale slow response (up=99) discarded.
          expect(server?.reputation?.up).toBe(5);
          expect(server?.reputation?.total).toBe(5);
        },
        { timeout: 5000 }
      );
    });

    it("applies the vote result normally when only one vote fires", async () => {
      const { result } = renderHook(() => useServerList());

      await waitFor(
        () => {
          expect(result.current.filteredServers.length).toBeGreaterThan(0);
        },
        { timeout: 5000 }
      );

      vi.mocked(apiClient.postReputationVote).mockResolvedValueOnce(
        voteSummary({ up: 7, total: 7 })
      );

      await act(async () => {
        await result.current.onVote(HOSTNAME, "up");
      });

      await waitFor(
        () => {
          const server = result.current.filteredServers.find(
            (s) => s.id === HOSTNAME
          );
          expect(server?.reputation?.up).toBe(7);
          expect(server?.reputation?.total).toBe(7);
        },
        { timeout: 5000 }
      );
    });

    it("handles vote failure without throwing", async () => {
      const { result } = renderHook(() => useServerList());

      await waitFor(
        () => {
          expect(result.current.filteredServers.length).toBeGreaterThan(0);
        },
        { timeout: 5000 }
      );

      vi.mocked(apiClient.postReputationVote).mockRejectedValueOnce(
        new Error("network error")
      );

      // Must not throw
      await act(async () => {
        await result.current.onVote(HOSTNAME, "up");
      });

      // State is unchanged — original up=1
      const server = result.current.filteredServers.find(
        (s) => s.id === HOSTNAME
      );
      expect(server?.reputation?.up).toBe(1);
    });
  });
});
