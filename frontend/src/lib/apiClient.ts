export class APIClientError extends Error {
  readonly code: string;
  readonly details: unknown;
  readonly status: number;

  constructor(message: string, status: number, code = "request_failed", details?: unknown) {
    super(message);
    this.name = "APIClientError";
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function headersToObject(headers?: HeadersInit): Record<string, string> {
  if (!headers) {
    return {};
  }
  if (headers instanceof Headers) {
    return Object.fromEntries(headers.entries());
  }
  if (Array.isArray(headers)) {
    return Object.fromEntries(headers);
  }
  return { ...headers };
}

async function decodeJSON(path: string, response: Response): Promise<unknown> {
  const text = await response.text();
  if (!text.trim()) {
    throw new APIClientError(`Empty API response from ${path}`, response.status, "invalid_json", text);
  }

  try {
    return JSON.parse(text);
  } catch {
    throw new APIClientError(
      `API response from ${path} was not valid JSON`,
      response.status,
      "invalid_json",
      text
    );
  }
}

async function request<T>(path: string, init: RequestInit): Promise<T> {
  let response: Response;
  try {
    const requestHeaders = headersToObject(init.headers);
    response = await fetch(path, {
      credentials: "same-origin",
      ...init,
      headers: {
        Accept: "application/json",
        ...requestHeaders,
      },
    });
  } catch (error) {
    const isAbortError =
      error instanceof DOMException && error.name === "AbortError";
    throw new APIClientError(
      isAbortError ? "Request was aborted" : "Network request failed",
      0,
      isAbortError ? "aborted" : "network_error",
      error
    );
  }

  const payload = await decodeJSON(path, response);
  if (response.ok) {
    return payload as T;
  }
  if (isRecord(payload)) {
    const message =
      typeof payload.message === "string" && payload.message.trim()
        ? payload.message.trim()
        : response.statusText || "Request failed";
    const code =
      typeof payload.code === "string" && payload.code.trim()
        ? payload.code.trim()
        : "request_failed";
    throw new APIClientError(message, response.status, code, payload);
  }
  throw new APIClientError(
    response.statusText || "Request failed",
    response.status,
    "request_failed",
    payload
  );
}

function jsonRequestInit(method: "POST" | "DELETE", body?: unknown): RequestInit {
  if (body === undefined) {
    return { method, headers: {} };
  }

  return {
    method,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  };
}

export const apiClient = {
  get<T>(path: string): Promise<T> {
    return request<T>(path, { method: "GET" });
  },
  post<T>(path: string, body?: unknown): Promise<T> {
    return request<T>(path, jsonRequestInit("POST", body));
  },
  delete<T>(path: string): Promise<T> {
    return request<T>(path, jsonRequestInit("DELETE"));
  },
};
