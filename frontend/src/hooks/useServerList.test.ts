import { act, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { apiClient } from "@/lib/apiClient";
import type { Lease, ServiceDiscoveryResponse } from "@/types/api";
import type { BaseServer } from "@/lib/server";
import { useServerList } from "./useServerList";

vi.mock("@/lib/apiClient", () => ({
  apiClient: { get: vi.fn() },
  APIClientError: class extends Error {},
}));
vi.mock("@/hooks/useList", () => ({
  useList: ({ servers }: { servers: BaseServer[] }) => ({ filteredServers: servers }),
}));

const lease: Lease = {
  address: "0x0123456789012345678901234567890123456789",
  hostname: "demo.relay.example",
  canonical_hostname: "demo-0123456789012345678901234567890123456789.relay.example",
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

  it("adds remote-only observations in network scope and keeps the local list when switched", async () => {
    const directory: ServiceDiscoveryResponse = {
      partial: true,
      relays_checked: 2,
      relays_skipped: 1,
      services: [{
        name: "remote",
        address: lease.address,
        metadata: { tags: ["network"] },
        locations: [{
          relay_url: "https://other.example",
          url: "https://remote.other.example/",
          current_relay: false,
          reported_ready: true,
          observed_at: new Date().toISOString(),
          expires_at: new Date(Date.now() + 60_000).toISOString(),
          verification: "relay-reported",
        }],
      }],
    };
    vi.mocked(apiClient.get).mockImplementation(async (path) =>
      path === "/api/services" ? directory : { leases: [lease] });
    const { result, rerender, unmount } = renderHook(({ network }) => useServerList("", network), {
      initialProps: { network: true },
    });
    await act(async () => {});
    expect(result.current.filteredServers).toHaveLength(2);
    expect(result.current.filteredServers.find((server) => server.remoteOnly)?.name).toBe("remote");
    expect(result.current.identityDiscovery.response?.partial).toBe(true);

    rerender({ network: false });
    expect(result.current.filteredServers.map((server) => server.id)).toEqual([lease.canonical_hostname]);
    expect(result.current.identityDiscovery.response).toBeUndefined();
    unmount();
  });

  it("keeps unexpired remote cards after a failed refresh, then removes them at expiry", async () => {
    const remoteLocation = {
      relay_url: "https://other.example",
      url: "https://remote.other.example/",
      current_relay: false,
      reported_ready: true,
      observed_at: new Date().toISOString(),
      expires_at: new Date(Date.now() + 60_000).toISOString(),
      verification: "relay-reported",
    } as const;
    let failed = false;
    vi.mocked(apiClient.get).mockImplementation(async (path) => {
      if (path !== "/api/services") return { leases: [lease] };
      if (failed) throw new Error("network directory unavailable");
      return {
        partial: false,
        relays_checked: 2,
        relays_skipped: 0,
        services: [{ name: "remote", address: lease.address, metadata: {}, locations: [remoteLocation] }],
      };
    });
    const { result, unmount } = renderHook(() => useServerList("", true));
    await act(async () => {});
    expect(result.current.filteredServers).toHaveLength(2);

    failed = true;
    await act(async () => { await vi.advanceTimersByTimeAsync(30_000); });
    expect(result.current.filteredServers).toHaveLength(2);
    expect(result.current.filteredServers.find((server) => server.remoteOnly)?.name).toBe("remote");
    expect(result.current.identityDiscovery.error).toContain("local directory is still available");

    await act(async () => { await vi.advanceTimersByTimeAsync(30_000); });
    expect(result.current.filteredServers.map((server) => server.id)).toEqual([lease.canonical_hostname]);
    expect(result.current.identityDiscovery.response?.partial).toBe(true);
    expect(result.current.identityDiscovery.error).toContain("local directory is still available");
    unmount();
  });
  it("distinguishes local reputation observed in public state from the local action fallback", async () => {
    const hostname = lease.canonical_hostname ?? lease.hostname;
    vi.mocked(apiClient.get)
      .mockResolvedValueOnce({ leases: [lease] })
      .mockResolvedValueOnce({ leases: [lease], reputation: [{ hostname, up: 0, down: 0, total: 0 }] });
    const { result, unmount } = renderHook(() => useServerList());
    await act(async () => {});
    expect(result.current.filteredServers[0].reputation?.total).toBe(0);
    expect(result.current.filteredServers[0].observedLocalReputation).toBeUndefined();

    await act(async () => { await vi.advanceTimersByTimeAsync(1500); });
    expect(result.current.filteredServers[0].observedLocalReputation).toMatchObject({ up: 0, down: 0 });
    unmount();
  });

  it("refreshes the original leases and directory entries together", async () => {
    vi.mocked(apiClient.get)
      .mockResolvedValueOnce({ leases: [lease] })
      .mockResolvedValueOnce({ leases: [{ ...lease, ready: 1 }] });
    const { result, unmount } = renderHook(() => useServerList());
    await act(async () => {});

    expect(result.current.leases?.[0].ready).toBe(0);
    expect(result.current.filteredServers[0].online).toBe(false);

    await act(async () => { await vi.advanceTimersByTimeAsync(1500); });

    expect(result.current.leases?.[0].ready).toBe(1);
    expect(result.current.filteredServers[0].online).toBe(true);
    unmount();
  });

  it("marks status unavailable without replacing the last directory snapshot, then recovers", async () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    vi.mocked(apiClient.get)
      .mockResolvedValueOnce({ leases: [{ ...lease, ready: 1 }] })
      .mockRejectedValueOnce(new Error("unavailable"))
      .mockResolvedValueOnce({ leases: [lease] });
    const { result, unmount } = renderHook(() => useServerList());
    await act(async () => {});

    const lastDirectory = result.current.filteredServers;
    await act(async () => { await vi.advanceTimersByTimeAsync(1500); });
    expect(result.current.leases).toBeNull();
    expect(result.current.filteredServers).toBe(lastDirectory);
    expect(result.current.filteredServers[0].online).toBe(true);

    await act(async () => { await vi.advanceTimersByTimeAsync(1500); });
    expect(result.current.leases).toEqual([lease]);
    expect(result.current.filteredServers[0].online).toBe(false);
    unmount();
  });

  it("treats a successful empty snapshot as authoritative", async () => {
    vi.mocked(apiClient.get)
      .mockResolvedValueOnce({ leases: [lease] })
      .mockResolvedValueOnce({ leases: [] });
    const { result, unmount } = renderHook(() => useServerList());
    await act(async () => {});

    await act(async () => { await vi.advanceTimersByTimeAsync(1500); });
    expect(result.current.leases).toEqual([]);
    expect(result.current.filteredServers).toEqual([]);
    unmount();
  });

  it("keeps the same directory when a poll returns an unchanged snapshot", async () => {
    vi.mocked(apiClient.get).mockResolvedValue({ leases: [{ ...lease, ready: 1 }] });
    const { result, unmount } = renderHook(() => useServerList());
    await act(async () => {});

    const directory = result.current.filteredServers;
    await act(async () => { await vi.advanceTimersByTimeAsync(1500); });

    expect(apiClient.get).toHaveBeenCalledTimes(2);
    expect(result.current.filteredServers).toBe(directory);
    unmount();
  });

  it("stops polling while the tab is hidden and refreshes when it shows again", async () => {
    let hidden = false;
    vi.spyOn(document, "hidden", "get").mockImplementation(() => hidden);
    vi.mocked(apiClient.get).mockResolvedValue({ leases: [lease] });
    const { unmount } = renderHook(() => useServerList());
    await act(async () => {});
    expect(apiClient.get).toHaveBeenCalledTimes(1);

    hidden = true;
    await act(async () => { document.dispatchEvent(new Event("visibilitychange")); });
    await act(async () => { await vi.advanceTimersByTimeAsync(6000); });
    expect(apiClient.get).toHaveBeenCalledTimes(1);

    hidden = false;
    await act(async () => { document.dispatchEvent(new Event("visibilitychange")); });
    expect(apiClient.get).toHaveBeenCalledTimes(2);
    unmount();
  });
  it("keeps the open comments on the app's latest entry and closes them when it leaves", async () => {
    vi.mocked(apiClient.get)
      .mockResolvedValueOnce({ leases: [lease] })
      .mockResolvedValueOnce({ leases: [{ ...lease, ready: 1 }] })
      .mockResolvedValueOnce({ leases: [] });
    const { result, unmount } = renderHook(() => useServerList());
    await act(async () => {});

    act(() => result.current.toggleComments(result.current.filteredServers[0]));
    expect(result.current.commentServer?.online).toBe(false);

    await act(async () => { await vi.advanceTimersByTimeAsync(1500); });
    expect(result.current.commentServer?.online).toBe(true);

    await act(async () => { await vi.advanceTimersByTimeAsync(1500); });
    expect(result.current.commentServer).toBeNull();
    unmount();
  });

  it("closes the comments when the same app is toggled again", async () => {
    vi.mocked(apiClient.get).mockResolvedValue({ leases: [lease] });
    const { result, unmount } = renderHook(() => useServerList());
    await act(async () => {});
    const app = result.current.filteredServers[0];

    act(() => result.current.toggleComments(app));
    act(() => result.current.toggleComments(app));

    expect(result.current.commentServer).toBeNull();
    unmount();
  });
});
