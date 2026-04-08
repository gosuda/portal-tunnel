import { act, renderHook, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { AdminLeaseData } from "@/hooks/useSSRData";
import { useAdmin } from "@/hooks/useAdmin";
import { API_PATHS, adminLeasePath } from "@/lib/apiPaths";
import { APIClientError, apiClient } from "@/lib/apiClient";

type DeferredAdminSnapshot = {
  leases: AdminLeaseData[];
  approval_mode: "auto" | "manual";
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
      delete: vi.fn(),
    },
  };
});

function buildLease(address: string, name: string = "relay-1"): AdminLeaseData {
  return {
    ExpiresAt: "2026-03-03T01:00:00Z",
    FirstSeenAt: "2026-03-02T00:00:00Z",
    LastSeenAt: "2026-03-03T00:00:00Z",
    identity_key: `${name.toLowerCase()}:${address.toLowerCase()}`,
    address,
    name,
    BPS: 1024,
    ClientIP: "203.0.113.10",
    ReportedIP: "",
    Hostname: "relay.example.com",
    Metadata: {
      description: "relay",
      tags: ["core"],
      thumbnail: "",
      owner: "ops",
      hide: false,
    },
    Ready: 1,
    IsApproved: true,
    IsBanned: address === "0x00000000000000000000000000000000000000A1",
    IsDenied: false,
    IsIPBanned: false,
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
  const mockDelete = vi.mocked(apiClient.delete);

  beforeEach(() => {
    vi.clearAllMocks();

    mockGet.mockImplementation(async (path: string) => {
      if (path === API_PATHS.admin.snapshot) {
        return {
          leases: [buildLease("0x00000000000000000000000000000000000000A1")],
          approval_mode: "not-a-mode",
        } as never;
      }
      throw new Error(`Unexpected GET path: ${path}`);
    });

    mockPost.mockResolvedValue({} as never);
    mockDelete.mockResolvedValue({} as never);
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
      if (path === API_PATHS.admin.snapshot) {
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

  it("encodes addresses for action routes", async () => {
    const { result } = renderHook(() => useAdmin());
    await waitForLoaded(result);
    const identityKey = "relay-1:0x00000000000000000000000000000000000000a1";

    await act(async () => {
      await result.current.handleApproveStatus(identityKey, true);
    });

    const calledPaths = mockPost.mock.calls.map(([path]) => path as string);
    expect(calledPaths).toContain(
      adminLeasePath(
        "relay-1",
        "0x00000000000000000000000000000000000000A1",
        "approve"
      ),
    );
  });

  it("posts bps updates to the lease action route", async () => {
    const { result } = renderHook(() => useAdmin());
    await waitForLoaded(result);

    await act(async () => {
      await result.current.handleBPSChange(
        "relay-1:0x00000000000000000000000000000000000000a1",
        4096
      );
    });

    expect(mockPost).toHaveBeenCalledWith(
      adminLeasePath(
        "relay-1",
        "0x00000000000000000000000000000000000000A1",
        "bps"
      ),
      { bps: 4096 },
    );
  });

  it("keeps loading false while refreshing bps in the background", async () => {
    let getCalls = 0;
    let resolveRefresh:
      | ((value: DeferredAdminSnapshot | PromiseLike<DeferredAdminSnapshot>) => void)
      | undefined;

    mockGet.mockImplementation((path: string) => {
      if (path !== API_PATHS.admin.snapshot) {
        throw new Error(`Unexpected GET path: ${path}`);
      }
      getCalls++;
      if (getCalls === 1) {
        return Promise.resolve({
          leases: [buildLease("0x00000000000000000000000000000000000000A1")],
          approval_mode: "auto",
        } as never);
      }
      return new Promise<DeferredAdminSnapshot>((resolve) => {
        resolveRefresh = resolve;
      }) as never;
    });

    const { result } = renderHook(() => useAdmin());
    await waitForLoaded(result);

    let pending: Promise<void> | undefined;
    await act(async () => {
      pending = result.current.handleBPSChange(
        "relay-1:0x00000000000000000000000000000000000000a1",
        2048
      );
      await waitFor(() => {
        expect(resolveRefresh).toBeDefined();
      });
      expect(result.current.loading).toBe(false);
      resolveRefresh?.({
        leases: [{ ...buildLease("0x00000000000000000000000000000000000000A1"), BPS: 2048 }],
        approval_mode: "auto",
      });
      await pending;
    });

    expect(result.current.servers[0]?.bps).toBe(2048);
  });

  it("bulk deny posts deduped addresses to action routes", async () => {
    mockGet.mockImplementation(async (path: string) => {
      if (path === API_PATHS.admin.snapshot) {
        return {
          leases: [
            buildLease("0x00000000000000000000000000000000000000A1", "relay-1"),
            buildLease("0x00000000000000000000000000000000000000B2", "relay-2"),
          ],
          approval_mode: "auto",
        } as never;
      }
      throw new Error(`Unexpected GET path: ${path}`);
    });

    const { result } = renderHook(() => useAdmin());
    await waitForLoaded(result);
    const addressA = "0x00000000000000000000000000000000000000A1";
    const addressB = "0x00000000000000000000000000000000000000B2";

    await act(async () => {
      await result.current.handleBulkDeny([
        "relay-1:0x00000000000000000000000000000000000000a1",
        "relay-1:0x00000000000000000000000000000000000000a1",
        "relay-2:0x00000000000000000000000000000000000000b2",
      ]);
    });

    const calledPaths = mockPost.mock.calls.map(([path]) => path as string);
    expect(calledPaths).toEqual(
      expect.arrayContaining([
        adminLeasePath("relay-1", addressA, "deny"),
        adminLeasePath("relay-2", addressB, "deny"),
      ]),
    );

    const denyCalls = calledPaths.filter((path) => path.endsWith("/deny"));
    expect(denyCalls).toHaveLength(2);
  });
});
