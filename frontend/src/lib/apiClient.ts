import { readAdminAuthToken } from "@/lib/adminAuthToken";
import { BROWSER_API_PATHS, RELAY_API_PATHS } from "@/lib/apiPaths";
import type { APIEnvelope } from "@/types/api";

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

function resolveAPIURL(path: string): string {
  if (/^[a-z][a-z\d+\-.]*:/i.test(path)) {
    return path;
  }

  const baseURL = import.meta.env.VITE_PORTAL_API_BASE_URL?.trim();
  if (!baseURL) {
    return path;
  }
  const normalizedPath = path.startsWith("/") ? path : `/${path}`;
  const parsedBase = new URL(baseURL);
  const rawBasePath = parsedBase.pathname.replace(/\/$/, "");
  const basePath = rawBasePath.endsWith("/api")
    ? rawBasePath.slice(0, -"/api".length)
    : rawBasePath;
  if (
    basePath !== "" &&
    (normalizedPath === basePath || normalizedPath.startsWith(`${basePath}/`))
  ) {
    parsedBase.pathname = normalizedPath;
  } else {
    parsedBase.pathname = `${basePath}${normalizedPath}`;
  }
  parsedBase.search = "";
  parsedBase.hash = "";
  return parsedBase.toString();
}

function isPathOrChild(pathname: string, root: string): boolean {
  return pathname === root || pathname.startsWith(`${root}/`);
}

function ensureJsonEnvelope<T>(raw: unknown, path: string, status: number): APIEnvelope<T> {
  if (!isRecord(raw) || typeof raw.ok !== "boolean") {
    throw new APIClientError(`Invalid API response for ${path}`, status, "invalid_envelope", raw);
  }
  if (raw.ok) {
    return {
      ok: true,
      data: (raw as { data: T }).data,
    };
  }

  if (!isRecord(raw.error)) {
    throw new APIClientError(`Invalid error payload for ${path}`, status, "invalid_envelope", raw.error);
  }
  const errorValue = raw.error;
  if (typeof errorValue.code !== "string" || typeof errorValue.message !== "string") {
    throw new APIClientError(`Invalid error payload for ${path}`, status, "invalid_envelope", raw.error);
  }

  return {
    ok: false,
    data: raw.data,
    error: {
      code: errorValue.code,
      message: errorValue.message,
    },
  };
}

async function decodeEnvelope<T>(path: string, response: Response): Promise<APIEnvelope<T>> {
  const text = await response.text();
  if (!text.trim()) {
    throw new APIClientError(
      `Empty API response from ${path}`,
      response.status,
      "invalid_envelope",
      text
    );
  }

  let payload: unknown;
  try {
    payload = JSON.parse(text);
  } catch {
    throw new APIClientError(
      `API response from ${path} was not valid JSON`,
      response.status,
      "invalid_json",
      text
    );
  }

  return ensureJsonEnvelope<T>(payload, path, response.status);
}

async function request<T>(path: string, init: RequestInit): Promise<T> {
  let response: Response;
  try {
    const requestHeaders = {
      ...((init.headers as Record<string, string> | undefined) ?? {}),
    };
    const pathname = new URL(path, window.location.origin).pathname;
    const requiresAdminAuth =
      isPathOrChild(pathname, BROWSER_API_PATHS.policy.root) ||
      isPathOrChild(pathname, RELAY_API_PATHS.policy.root) ||
      isPathOrChild(pathname, RELAY_API_PATHS.admin.root);
    if (
      requiresAdminAuth &&
      pathname !== BROWSER_API_PATHS.admin.authChallenge &&
      pathname !== BROWSER_API_PATHS.admin.authLogin
    ) {
      const token = readAdminAuthToken();
      if (token) {
        requestHeaders.Authorization = `Bearer ${token}`;
      }
    }
    response = await fetch(resolveAPIURL(path), {
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

  const envelope = await decodeEnvelope<T>(path, response);
  if (envelope.ok) {
    return envelope.data as T;
  }

  const message =
    envelope.error?.message?.trim() || response.statusText || "Request failed";
  const code = envelope.error?.code?.trim() || "request_failed";
  throw new APIClientError(message, response.status, code, envelope.data);
}

function jsonRequestInit(body?: unknown): RequestInit {
  if (body === undefined) {
    return { method: "POST", headers: {} };
  }

  return {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  };
}

export const apiClient = {
  get<T>(path: string): Promise<T> {
    return request<T>(path, { method: "GET" });
  },
  post<T>(path: string, body?: unknown): Promise<T> {
    return request<T>(path, jsonRequestInit(body));
  },
};
