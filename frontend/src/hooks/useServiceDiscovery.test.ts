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
  it("checks the next relay window only when requested and keeps existing observations while loading", async () => {
    vi.mocked(apiClient.get).mockResolvedValueOnce({ services: [], partial: true, relays_checked: 9, relays_skipped: 3 });
    const { result } = renderHook(() => useServiceDiscovery(address));
    await act(async () => {});
    expect(result.current.response?.relays_checked).toBe(9);
    expect(apiClient.get).toHaveBeenCalledTimes(1);
    vi.mocked(apiClient.get).mockResolvedValueOnce({ services: [], partial: false, relays_checked: 12, relays_skipped: 0 });
    act(() => result.current.checkMore());
    expect(result.current.loading).toBe(true);
    expect(result.current.response?.relays_checked).toBe(9);
    await act(async () => {});
    expect(result.current.loading).toBe(false);
    expect(result.current.response?.relays_checked).toBe(12);
    expect(apiClient.get).toHaveBeenCalledTimes(2);
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
