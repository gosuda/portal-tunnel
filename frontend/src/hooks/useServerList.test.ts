import { act, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { apiClient } from "@/lib/apiClient";
import type { Lease } from "@/types/api";
import type { BaseServer } from "@/hooks/useList";
import { useServerList } from "./useServerList";

vi.mock("@/lib/apiClient", () => ({ apiClient: { get: vi.fn() } }));
vi.mock("@/hooks/useList", () => ({
  useList: ({ servers }: { servers: BaseServer[] }) => ({ filteredServers: servers }),
}));

const lease: Lease = {
  hostname: "demo.relay.example",
  expires_at: "",
  first_seen_at: "",
  last_seen_at: "",
  metadata: {},
  ready: 0,
};

beforeEach(() => {
  vi.useFakeTimers();
  vi.mocked(apiClient.get).mockReset();
});
afterEach(() => vi.useRealTimers());

describe("useServerList public snapshot", () => {
  it("refreshes the original leases and directory entries together", async () => {
    vi.mocked(apiClient.get)
      .mockResolvedValueOnce({ leases: [lease], landing_page_enabled: true })
      .mockResolvedValueOnce({ leases: [{ ...lease, ready: 1 }], landing_page_enabled: true });
    const { result, unmount } = renderHook(() => useServerList());
    await act(async () => {});

    expect(result.current.leases[0].ready).toBe(0);
    expect(result.current.filteredServers[0].online).toBe(false);

    await act(async () => { await vi.advanceTimersByTimeAsync(1500); });

    expect(result.current.leases[0].ready).toBe(1);
    expect(result.current.filteredServers[0].online).toBe(true);
    unmount();
  });

  it("clears stale lease status on failure and recovers without hiding the hero", async () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    vi.mocked(apiClient.get)
      .mockResolvedValueOnce({ leases: [{ ...lease, ready: 1 }], landing_page_enabled: true })
      .mockRejectedValueOnce(new Error("unavailable"))
      .mockResolvedValueOnce({ leases: [lease], landing_page_enabled: true });
    const { result, unmount } = renderHook(() => useServerList());
    await act(async () => {});

    await act(async () => { await vi.advanceTimersByTimeAsync(1500); });
    expect(result.current.leases).toEqual([]);
    expect(result.current.filteredServers).toEqual([]);
    expect(result.current.landingPageEnabled).toBe(true);

    await act(async () => { await vi.advanceTimersByTimeAsync(1500); });
    expect(result.current.leases).toEqual([lease]);
    expect(result.current.filteredServers[0].online).toBe(false);
    unmount();
  });
});
