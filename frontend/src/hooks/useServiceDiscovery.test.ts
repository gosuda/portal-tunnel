import { act, renderHook } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { apiClient } from "@/lib/apiClient";
import { useServiceDiscovery } from "./useServiceDiscovery";

vi.mock("@/lib/apiClient", () => ({
  apiClient: { get: vi.fn() },
  APIClientError: class extends Error {},
}));
const address = "0x1111111111111111111111111111111111111111";
beforeEach(() => {
  vi.mocked(apiClient.get).mockReset();
});

describe("service discovery", () => {
  it("queries the current backend only after the relay selector is opened", async () => {
    vi.mocked(apiClient.get).mockResolvedValue({ services: [], partial: false, relays_checked: 1, relays_skipped: 0 });
    const { result, rerender } = renderHook(({ open }) => useServiceDiscovery(address, "blog", open), { initialProps: { open: false } });
    expect(apiClient.get).not.toHaveBeenCalled();
    rerender({ open: true });
    await act(async () => {});
    expect(apiClient.get).toHaveBeenCalledWith(`/api/services?address=${address}&name=blog`);
    expect(result.current.response?.relays_checked).toBe(1);
  });

  it("drops expired locations even if no new directory snapshot has arrived", async () => {
    vi.useFakeTimers();
    try {
      vi.mocked(apiClient.get).mockResolvedValue({
        services: [{
          name: "blog",
          address,
          metadata: {},
          locations: [{
            relay_url: "https://remote.example",
            current_relay: false,
            reported_ready: true,
            observed_at: new Date().toISOString(),
            expires_at: new Date(Date.now() + 1000).toISOString(),
            verification: "relay-reported",
          }],
        }],
        partial: false,
        relays_checked: 2,
        relays_skipped: 0,
      });
      const { result, unmount } = renderHook(() => useServiceDiscovery(undefined));
      await act(async () => {});
      expect(result.current.response?.services).toHaveLength(1);
      await act(async () => { await vi.advanceTimersByTimeAsync(1000); });
      expect(result.current.response?.services).toEqual([]);
      expect(result.current.response?.partial).toBe(true);
      unmount();
    } finally {
      vi.useRealTimers();
    }
  });

  it("does not carry another identity's response into a new filter", async () => {
    vi.mocked(apiClient.get).mockResolvedValueOnce({ services: [], partial: false, relays_checked: 1, relays_skipped: 0 });
    const { result, rerender } = renderHook(({ owner }) => useServiceDiscovery(owner), { initialProps: { owner: address } });
    await act(async () => {});
    expect(result.current.response).toBeDefined();
    vi.mocked(apiClient.get).mockImplementation(() => new Promise(() => {}));
    rerender({ owner: "0x2222222222222222222222222222222222222222" });
    expect(result.current.response).toBeUndefined();
    expect(result.current.loading).toBe(true);
  });
});
