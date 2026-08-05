import { APIClientError, apiClient } from "@/lib/apiClient";
import { writeAdminAuthToken } from "@/lib/adminAuthToken";
import { beforeEach, describe, expect, it, vi } from "vitest";

function jsonResponse(payload: unknown, init?: ResponseInit): Response {
  return new Response(JSON.stringify(payload), {
    status: 200,
    headers: { "Content-Type": "application/json" },
    ...init,
  });
}

describe("apiClient", () => {
  const fetchMock = vi.fn();

  beforeEach(() => {
    vi.unstubAllEnvs();
    fetchMock.mockReset();
    vi.stubGlobal("fetch", fetchMock as unknown as typeof fetch);
    localStorage.clear();
  });

  it("returns data when API envelope is ok", async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse({ ok: true, data: { value: 42 } }),
    );

    const data = await apiClient.get<{ value: number }>("/api/test");

    expect(data).toEqual({ value: 42 });
    const init = fetchMock.mock.calls[0]?.[1] as RequestInit;
    expect(init.method).toBe("GET");
    expect(init.credentials).toBe("same-origin");
    expect(init.headers).toEqual({ Accept: "application/json" });
  });

  it("preserves non-API base URL subpaths", async () => {
    vi.stubEnv("VITE_PORTAL_API_BASE_URL", "https://portal.example.com/custom");
    fetchMock.mockResolvedValueOnce(
      jsonResponse({ ok: true, data: { status: "ok" } }),
    );

    await apiClient.get("/api/state");

    expect(fetchMock.mock.calls[0]?.[0]).toBe("https://portal.example.com/custom/api/state");
  });

  it("treats an API base URL suffix as the public edge root", async () => {
    vi.stubEnv("VITE_PORTAL_API_BASE_URL", "https://portal.example.com/api");
    fetchMock.mockResolvedValueOnce(
      jsonResponse({ ok: true, data: { status: "ok" } }),
    );

    await apiClient.get("/api/state");

    expect(fetchMock.mock.calls[0]?.[0]).toBe("https://portal.example.com/api/state");
  });

  it("rejects successful non-envelope JSON payloads", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ direct: true }));

    await expect(apiClient.get<{ direct: boolean }>("/api/test")).rejects.toMatchObject({
      name: "APIClientError",
      status: 200,
      code: "invalid_envelope",
    } satisfies Partial<APIClientError>);
  });

  it("throws APIClientError for server-side envelope failures", async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse(
        { ok: false, error: { code: "forbidden", message: "Denied" } },
        { status: 403, statusText: "Forbidden" },
      ),
    );

    await expect(apiClient.get("/api/test")).rejects.toMatchObject({
      name: "APIClientError",
      status: 403,
      code: "forbidden",
      message: "Denied",
    } satisfies Partial<APIClientError>);
  });

  it("rejects structured non-envelope errors as invalid envelopes", async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse(
        { code: "lease_rejected", message: "failed to register lease" },
        { status: 409, statusText: "Conflict" },
      ),
    );

    await expect(apiClient.get("/api/test")).rejects.toMatchObject({
      name: "APIClientError",
      status: 409,
      code: "invalid_envelope",
    } satisfies Partial<APIClientError>);
  });

  it("throws invalid_envelope when a failed response has no parseable error payload", async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse({ detail: "not wrapped" }, { status: 400 }),
    );

    await expect(apiClient.get("/api/test")).rejects.toMatchObject({
      name: "APIClientError",
      status: 400,
      code: "invalid_envelope",
    } satisfies Partial<APIClientError>);
  });

  it("treats empty responses as invalid envelopes", async () => {
    fetchMock.mockResolvedValueOnce(new Response("", { status: 200 }));

    await expect(apiClient.get("/api/test")).rejects.toMatchObject({
      name: "APIClientError",
      status: 200,
      code: "invalid_envelope",
    } satisfies Partial<APIClientError>);
  });

  it("throws invalid_json when response body is not parseable JSON", async () => {
    fetchMock.mockResolvedValueOnce(
      new Response("not-json", {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );

    await expect(apiClient.get("/api/test")).rejects.toMatchObject({
      name: "APIClientError",
      status: 200,
      code: "invalid_json",
    } satisfies Partial<APIClientError>);
  });

  it("maps fetch failures to network_error", async () => {
    fetchMock.mockRejectedValueOnce(new Error("network down"));

    await expect(apiClient.get("/api/test")).rejects.toMatchObject({
      name: "APIClientError",
      status: 0,
      code: "network_error",
      message: "Network request failed",
    } satisfies Partial<APIClientError>);
  });

  it("maps AbortError failures to aborted", async () => {
    fetchMock.mockRejectedValueOnce(new DOMException("Aborted", "AbortError"));

    await expect(apiClient.get("/api/test")).rejects.toMatchObject({
      name: "APIClientError",
      status: 0,
      code: "aborted",
      message: "Request was aborted",
    } satisfies Partial<APIClientError>);
  });

  it("sends JSON bodies for post", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ ok: true, data: {} }));
    await apiClient.post("/api/post", { id: 1 });

    const postInit = fetchMock.mock.calls[0]?.[1] as RequestInit;
    expect(postInit.method).toBe("POST");
    expect(postInit.body).toBe(JSON.stringify({ id: 1 }));
    expect(postInit.headers).toEqual({
      Accept: "application/json",
      "Content-Type": "application/json",
    });
  });

  it("sends bearer token for admin API calls", async () => {
    writeAdminAuthToken("admin-token");
    fetchMock.mockResolvedValueOnce(jsonResponse({ ok: true, data: {} }));

    await apiClient.post("/api/admin/auth/logout");

    const init = fetchMock.mock.calls[0]?.[1] as RequestInit;
    expect(init.credentials).toBe("same-origin");
    expect(init.headers).toEqual({
      Accept: "application/json",
      Authorization: "Bearer admin-token",
    });
  });

  it("sends bearer token for policy API calls", async () => {
    writeAdminAuthToken("admin-token");
    fetchMock.mockResolvedValueOnce(jsonResponse({ ok: true, data: {} }));

    await apiClient.post("/api/policy/leases", {
      identity_key: "relay:0x1",
      is_approved: true,
    });

    const init = fetchMock.mock.calls[0]?.[1] as RequestInit;
    expect(init.headers).toEqual({
      Accept: "application/json",
      Authorization: "Bearer admin-token",
      "Content-Type": "application/json",
    });
  });
});
