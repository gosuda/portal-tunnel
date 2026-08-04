import { act, renderHook, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { PolicyLease, PolicySettings } from "@/types/api";
import { useAdmin } from "@/hooks/useAdmin";
import { BROWSER_API_PATHS } from "@/lib/apiPaths";
import { APIClientError, apiClient } from "@/lib/apiClient";

type DeferredPolicyState = {
  leases: PolicyLease[];
  policy: PolicySettings;
};

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

function buildSettings(approvalMode: "auto" | "manual" = "auto"): PolicySettings {
  return {
    approval_mode: approvalMode,
    landing_page_enabled: false,
    udp: { enabled: false, max_leases: 0 },
    tcp_port: { enabled: false, max_leases: 0 },
  };
}

function buildLease(address: string, name: string = "relay-1"): PolicyLease {
  return {
    expires_at: "2026-03-04T00:00:00Z",
    first_seen_at: "2026-03-02T00:00:00Z",
    last_seen_at: "2026-03-03T00:00:00Z",
    identity_key: `${name.toLowerCase()}:${address.toLowerCase()}`,
    address,
    name,
    bps: 1024,
    client_ip: "203.0.113.10",
    reported_ip: "",
    hostname: "relay.example.com",
    metadata: {
      description: "relay",
      tags: ["core"],
      thumbnail: "",
      owner: "ops",
    },
    ready: 1,
    is_approved: true,
    is_banned: address === "0x00000000000000000000000000000000000000A1",
    is_denied: false,
    is_ip_banned: false,
  };
}

async function waitForLoaded(result: { current: { loading: boolean } }) {
  await waitFor(() => {
    expect(result.current.loading).toBe(false);
  });
}

describe("useAdmin", () => {
  const mockGet = vi.mocked(apiClient.get);
  const mockPost = vi.mocked(apiClient.post);

  beforeEach(() => {
    vi.clearAllMocks();

    mockGet.mockImplementation(async (path: string) => {
      if (path === BROWSER_API_PATHS.policy.state) {
        return {
          leases: [buildLease("0x00000000000000000000000000000000000000A1")],
          policy: { ...buildSettings(), approval_mode: "not-a-mode" },
        } as never;
      }
      throw new Error(`Unexpected GET path: ${path}`);
    });

    mockPost.mockImplementation(async <T,>(path: string, body?: unknown): Promise<T> => {
      if (path === BROWSER_API_PATHS.policy.root) {
        return body as T;
      }
      return {} as T;
    });
  });

  it("normalizes fetchData results on success", async () => {
    const { result } = renderHook(() => useAdmin());

    await waitForLoaded(result);

    expect(result.current.error).toBe("");
    expect(result.current.approvalMode).toBe("auto");
    expect(result.current.servers[0]?.address).toBe("0x00000000000000000000000000000000000000A1");
    expect(result.current.servers[0]?.isBanned).toBe(true);
    expect(result.current.servers[0]?.bps).toBe(1024);
  });

  it("surfaces fetchData API errors", async () => {
    mockGet.mockImplementation(async (path: string) => {
      if (path === BROWSER_API_PATHS.policy.state) {
        throw new APIClientError("failed to load leases", 500, "server_error");
      }
      throw new Error(`Unexpected GET path: ${path}`);
    });

    const { result } = renderHook(() => useAdmin());

    await waitForLoaded(result);

    expect(result.current.error).toBe("failed to load leases");
  });

  it("maps contract error codes to resilient admin messages", async () => {
    const { result } = renderHook(() => useAdmin());
    await waitForLoaded(result);

    mockPost.mockRejectedValueOnce(
      new APIClientError("request failed", 400, "invalid_mode"),
    );

    await act(async () => {
      await expect(result.current.handleApprovalModeChange("manual")).rejects.toBeInstanceOf(
        APIClientError,
      );
    });

    await waitFor(() => {
      expect(result.current.error).toBe(
        "Invalid approval mode. Choose auto or manual and retry.",
      );
    });
  });

  it("validates missing IP in handleIPBanStatus", async () => {
    const { result } = renderHook(() => useAdmin());
    await waitForLoaded(result);

    await act(async () => {
      await expect(result.current.handleIPBanStatus("   ", true)).rejects.toThrow(
        "Missing IP address",
      );
    });
    await waitFor(() => {
      expect(result.current.error).toContain("Missing IP address");
    });
  });

  it("posts identity keys in lease policy bodies", async () => {
    const { result } = renderHook(() => useAdmin());
    await waitForLoaded(result);
    const identityKey = "relay-1:0x00000000000000000000000000000000000000a1";

    await act(async () => {
      await result.current.handleApproveStatus(identityKey, true);
    });

    const calledPaths = mockPost.mock.calls.map(([path]) => path as string);
    expect(calledPaths).toContain(BROWSER_API_PATHS.policy.leases);
    expect(mockPost).toHaveBeenCalledWith(BROWSER_API_PATHS.policy.leases, {
      identity_key: identityKey,
      is_approved: true,
    });
  });

  it("posts bps updates to the lease policy endpoint", async () => {
    const { result } = renderHook(() => useAdmin());
    await waitForLoaded(result);

    await act(async () => {
      await result.current.handleBPSChange(
        "relay-1:0x00000000000000000000000000000000000000a1",
        4096
      );
    });

    expect(mockPost).toHaveBeenCalledWith(
      BROWSER_API_PATHS.policy.leases,
      {
        identity_key: "relay-1:0x00000000000000000000000000000000000000a1",
        bps: 4096,
      },
    );
  });

  it("keeps loading false while refreshing bps in the background", async () => {
    let getCalls = 0;
    let resolveRefresh:
      | ((value: DeferredPolicyState | PromiseLike<DeferredPolicyState>) => void)
      | undefined;

    mockGet.mockImplementation((path: string) => {
      if (path !== BROWSER_API_PATHS.policy.state) {
        throw new Error(`Unexpected GET path: ${path}`);
      }
      getCalls++;
      if (getCalls === 1) {
        return Promise.resolve({
          leases: [buildLease("0x00000000000000000000000000000000000000A1")],
          policy: buildSettings(),
        } as never);
      }
      return new Promise<DeferredPolicyState>((resolve) => {
        resolveRefresh = resolve;
      }) as never;
    });

    const { result } = renderHook(() => useAdmin());
    await waitForLoaded(result);

    let pending: Promise<void> | undefined;
    act(() => {
      pending = result.current.handleBPSChange(
        "relay-1:0x00000000000000000000000000000000000000a1",
        2048
      );
    });

    await waitFor(() => {
      expect(getCalls).toBe(2);
    });
    expect(result.current.loading).toBe(false);

    await act(async () => {
      resolveRefresh?.({
        leases: [{ ...buildLease("0x00000000000000000000000000000000000000A1"), bps: 2048 }],
        policy: buildSettings(),
      });
      await pending;
    });

    expect(result.current.servers[0]?.bps).toBe(2048);
  });

  it("bulk deny posts deduped identity keys in lease policy bodies", async () => {
    mockGet.mockImplementation(async (path: string) => {
      if (path === BROWSER_API_PATHS.policy.state) {
        return {
          leases: [
            buildLease("0x00000000000000000000000000000000000000A1", "relay-1"),
            buildLease("0x00000000000000000000000000000000000000B2", "relay-2"),
          ],
          policy: buildSettings(),
        } as never;
      }
      throw new Error(`Unexpected GET path: ${path}`);
    });

    const { result } = renderHook(() => useAdmin());
    await waitForLoaded(result);
    const identityKeyA = "relay-1:0x00000000000000000000000000000000000000a1";
    const identityKeyB = "relay-2:0x00000000000000000000000000000000000000b2";

    await act(async () => {
      await result.current.handleBulkDeny([
        identityKeyA,
        identityKeyA,
        identityKeyB,
      ]);
    });

    const denyCalls = mockPost.mock.calls.filter(([, body]) => {
      return (body as { is_denied?: boolean }).is_denied === true;
    });
    expect(denyCalls).toHaveLength(2);
    expect(denyCalls).toEqual(
      expect.arrayContaining([
        [BROWSER_API_PATHS.policy.leases, { identity_key: identityKeyA, is_denied: true }],
        [BROWSER_API_PATHS.policy.leases, { identity_key: identityKeyB, is_denied: true }],
      ]),
    );
  });
});
