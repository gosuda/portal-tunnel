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
  it("refreshes cached locations at expiry instead of waiting a full polling interval", async () => {
    vi.useFakeTimers();
    try {
      const observedAt = Date.now();
      vi.mocked(apiClient.get).mockImplementation(async () => ({
        services: [{
          name: "blog",
          address,
          metadata: {},
          locations: [{
            relay_url: "https://remote.example",
            current_relay: false,
            reported_ready: true,
            observed_at: new Date(observedAt).toISOString(),
            expires_at: new Date(Date.now() < observedAt + 30_000
              ? observedAt + 30_000 : Date.now() + 30_000).toISOString(),
            verification: "relay-reported",
          }],
        }],
        partial: false,
        relays_checked: 2,
        relays_skipped: 0,
      }));
      const { result, unmount } = renderHook(() => useServiceDiscovery(undefined, undefined, true, true));
      await act(async () => {});
      await act(async () => { await vi.advanceTimersByTimeAsync(25_000); });
      expect(result.current.response?.services).toHaveLength(1);
      await act(async () => { await vi.advanceTimersByTimeAsync(5_001); });
      expect(result.current.response?.services).toHaveLength(1);
      expect(Date.parse(result.current.response!.services[0].locations[0].expires_at)).toBeGreaterThan(Date.now());
      unmount();
    } finally {
      vi.useRealTimers();
    }
  });

  it("merges newly discovered locations and dispatches portal:relay-discovered event only for newly added locations", async () => {
    const eventHandler = vi.fn();
    window.addEventListener("portal:relay-discovered", eventHandler);
    try {
      vi.mocked(apiClient.get).mockResolvedValueOnce({
        services: [{
          name: "blog",
          address,
          metadata: {},
          locations: [{
            relay_url: "https://relay-1.example",
            current_relay: false,
            reported_ready: true,
            observed_at: new Date().toISOString(),
            expires_at: new Date(Date.now() + 30_000).toISOString(),
            verification: "relay-reported",
          }],
        }],
        partial: true,
        relays_checked: 5,
        relays_skipped: 5,
      });

      const { result } = renderHook(() => useServiceDiscovery(address));
      await act(async () => {});

      expect(eventHandler).toHaveBeenCalledTimes(1);
      expect(result.current.response?.services[0].locations).toHaveLength(1);

      // Second response has a new relay location for the same service
      vi.mocked(apiClient.get).mockResolvedValueOnce({
        services: [{
          name: "blog",
          address,
          metadata: {},
          locations: [
            {
              relay_url: "https://relay-2.example",
              current_relay: false,
              reported_ready: true,
              observed_at: new Date().toISOString(),
              expires_at: new Date(Date.now() + 30_000).toISOString(),
              verification: "relay-reported",
            },
          ],
        }],
        partial: false,
        relays_checked: 10,
        relays_skipped: 0,
      });

      act(() => result.current.checkMore());
      await act(async () => {});

      expect(eventHandler).toHaveBeenCalledTimes(2);
      // Both relay locations must be retained
      expect(result.current.response?.services[0].locations).toHaveLength(2);
      const urls = result.current.response?.services[0].locations.map((l) => l.relay_url);
      expect(urls).toContain("https://relay-1.example");
      expect(urls).toContain("https://relay-2.example");
    } finally {
      window.removeEventListener("portal:relay-discovered", eventHandler);
    }
  });

  it("queries the current backend only after the relay selector is opened", async () => {
    vi.mocked(apiClient.get).mockResolvedValue({ services: [], partial: false, relays_checked: 1, relays_skipped: 0 });
    const { result, rerender } = renderHook(({ open }) => useServiceDiscovery(address, "blog", open), { initialProps: { open: false } });
    expect(apiClient.get).not.toHaveBeenCalled();
    rerender({ open: true });
    await act(async () => {});
    expect(apiClient.get).toHaveBeenCalledWith(`/api/services?address=${address}&name=blog`);
    expect(result.current.response?.relays_checked).toBe(1);
  });

  it("does not drop previously discovered locations when a later poll does not contain them", async () => {
    vi.mocked(apiClient.get).mockResolvedValueOnce({
      services: [{
        name: "blog",
        address,
        metadata: {},
        locations: [{
          relay_url: "https://remote.example",
          current_relay: false,
          reported_ready: true,
          observed_at: new Date().toISOString(),
          expires_at: new Date(Date.now() + 30_000).toISOString(),
          verification: "relay-reported",
        }],
      }],
      partial: false,
      relays_checked: 2,
      relays_skipped: 0,
    });
    const { result } = renderHook(() => useServiceDiscovery(undefined));
    await act(async () => {});
    expect(result.current.response?.services).toHaveLength(1);

    // Later poll returns empty (e.g. backend rotated away), previous observation remains
    vi.mocked(apiClient.get).mockResolvedValueOnce({
      services: [],
      partial: false,
      relays_checked: 2,
      relays_skipped: 0,
    });
    act(() => result.current.checkMore());
    await act(async () => {});
    expect(result.current.response?.services).toHaveLength(1);
  });

  it("does not carry another identity's response into a new filter", async () => {
    vi.mocked(apiClient.get).mockResolvedValueOnce({ services: [], partial: false, relays_checked: 1, relays_skipped: 0 });
    const { result, rerender } = renderHook(({ owner }) => useServiceDiscovery(owner), { initialProps: { owner: address } });
    await act(async () => {});
    expect(result.current.response).toBeDefined();
    vi.mocked(apiClient.get).mockRejectedValueOnce(new Error("lookup failed"));
    rerender({ owner: "0x2222222222222222222222222222222222222222" });
    expect(result.current.response).toBeUndefined();
    expect(result.current.loading).toBe(true);
    await act(async () => {});
    expect(result.current.response).toBeUndefined();
    expect(result.current.error).toContain("local directory is still available");
  });
});
