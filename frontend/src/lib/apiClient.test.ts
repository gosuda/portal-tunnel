import { APIClientError, apiClient } from "@/lib/apiClient";
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
    fetchMock.mockReset();
    vi.stubGlobal("fetch", fetchMock as unknown as typeof fetch);
  });

  it("returns data when API response is JSON", async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse({ value: 42 }),
    );

    const data = await apiClient.get<{ value: number }>("/api/test");

    expect(data).toEqual({ value: 42 });
    const init = fetchMock.mock.calls[0]?.[1] as RequestInit;
    expect(init.method).toBe("GET");
    expect(init.credentials).toBe("same-origin");
    expect(init.headers).toEqual({ Accept: "application/json" });
  });

  it("throws APIClientError for server-side errors", async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse(
        { code: "forbidden", message: "Denied" },
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

  it("accepts direct JSON error payloads", async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse(
        { code: "lease_rejected", message: "failed to register lease" },
        { status: 409, statusText: "Conflict" },
      ),
    );

    await expect(apiClient.get("/api/test")).rejects.toMatchObject({
      name: "APIClientError",
      status: 409,
      code: "lease_rejected",
    } satisfies Partial<APIClientError>);
  });

  it("uses fallback code when a failed response has no typed error payload", async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse({ detail: "not wrapped" }, { status: 400 }),
    );

    await expect(apiClient.get("/api/test")).rejects.toMatchObject({
      name: "APIClientError",
      status: 400,
      code: "request_failed",
    } satisfies Partial<APIClientError>);
  });

  it("treats empty responses as invalid_json", async () => {
    fetchMock.mockResolvedValueOnce(new Response("", { status: 200 }));

    await expect(apiClient.get("/api/test")).rejects.toMatchObject({
      name: "APIClientError",
      status: 200,
      code: "invalid_json",
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

  it("sends JSON bodies for post and omits content-type for delete without body", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({}));
    await apiClient.post("/api/post", { id: 1 });

    const postInit = fetchMock.mock.calls[0]?.[1] as RequestInit;
    expect(postInit.method).toBe("POST");
    expect(postInit.body).toBe(JSON.stringify({ id: 1 }));
    expect(postInit.headers).toEqual({
      Accept: "application/json",
      "Content-Type": "application/json",
    });

    fetchMock.mockResolvedValueOnce(jsonResponse({}));
    await apiClient.delete("/api/post");

    const deleteInit = fetchMock.mock.calls[1]?.[1] as RequestInit;
    expect(deleteInit.method).toBe("DELETE");
    expect(deleteInit.headers).toEqual({
      Accept: "application/json",
    });
  });
});
