import { act, renderHook } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { apiClient } from "@/lib/apiClient";
import type { BaseServer } from "@/lib/server";
import { useFederatedComments } from "./useFederatedComments";
import { useServerComments } from "./useServerComments";

vi.mock("@/lib/apiClient", () => ({ apiClient: { get: vi.fn(), post: vi.fn() } }));

const address = "0x1111111111111111111111111111111111111111";
const remoteOnly: BaseServer = {
  id: "service:blog", name: "Blog", serviceName: "blog", address, remoteOnly: true,
  description: "", tags: [], thumbnail: "", owner: "", online: true, dns: "", link: "",
};
const report = { relays_checked: 2, relays_skipped: 0, partial: false };
const row = { id: "same", relay_url: "https://relay-a.example", text: "A", created_at: "2026-11-01T00:00:00Z" };

beforeEach(() => {
  vi.mocked(apiClient.get).mockReset();
  vi.mocked(apiClient.post).mockReset();
});

describe("federated comments", () => {
  it("loads only from this relay's federation endpoint for a remote-only service", async () => {
    vi.mocked(apiClient.get).mockResolvedValue({ ...report, comments: [row] });
    const { result } = renderHook(() => ({
      local: useServerComments(remoteOnly, false),
      federation: useFederatedComments(remoteOnly),
    }));
    await act(async () => {});
    expect(vi.mocked(apiClient.get).mock.calls.map(([path]) => path)).toEqual([
      `/api/services/comments?address=${address}&name=blog`,
    ]);
    expect(result.current.federation.response?.comments).toEqual([row]);

    await act(async () => {
      await result.current.local.submit();
      await result.current.local.remove("same");
      await result.current.local.voteComment("same", "up");
      await result.current.local.refresh();
    });
    expect(apiClient.post).not.toHaveBeenCalled();
    expect(apiClient.get).toHaveBeenCalledTimes(1);
  });

  it("preserves same IDs from distinct origins, refreshes removals, and keeps partial state", async () => {
    vi.mocked(apiClient.get)
      .mockResolvedValueOnce({ ...report, partial: true, next_offset: 1, comments: [row] })
      .mockResolvedValueOnce({ ...report, comments: [{ ...row, relay_url: "https://relay-b.example" }] })
      .mockResolvedValueOnce({ ...report, comments: [{ ...row, text: "", deleted: true }] });
    const { result } = renderHook(() => useFederatedComments(remoteOnly));
    await act(async () => {});
    await act(async () => { result.current.loadMore?.(); });
    expect(result.current.response?.comments.map((comment) => comment.relay_url)).toEqual([
      "https://relay-a.example", "https://relay-b.example",
    ]);
    expect(result.current.response?.partial).toBe(true);

    await act(async () => { result.current.refresh(); });
    expect(result.current.response?.comments.map(({ relay_url, deleted }) => [relay_url, deleted]))
      .toEqual([["https://relay-a.example", true]]);
  });
});
