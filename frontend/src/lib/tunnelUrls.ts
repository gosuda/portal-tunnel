import { normalizeExposeName } from "@/lib/exposeName";
import { formatToken, type TunnelCommandOS } from "./tunnelShell";

export function buildTunnelPreviewURL(
  origin: string,
  name: string
): string {
  const normalized = normalizeExposeName(name);
  if (normalized === "") {
    return "";
  }
  const baseHost = getRelayOriginHost(origin);
  if (baseHost === "") {
    return "";
  }
  const port = new URL(origin).port;
  const portSuffix = port === "" || port === "443" ? "" : `:${port}`;
  return `https://${normalized}.${baseHost}${portSuffix}`;
}

export function buildServiceStatusHostname(
  origin: string,
  name: string
): string {
  const relayHost = getRelayOriginHost(origin);
  if (relayHost === "") {
    return "";
  }
  const normalized = normalizeExposeName(name);
  if (normalized === "") {
    return "";
  }
  return `${normalized}.${relayHost}`;
}

export function buildAuthRedirectURLs(
  relayUrls: string[],
  name: string,
  path: string
): string[] {
  const shortURLs = relayUrls
    .map((relayURL) => buildTunnelPreviewURL(relayURL, name))
    .filter((url) => url !== "");
  return [...new Set(shortURLs)].map((url) => `${url}${path}`);
}

export function applicationAuthHost(address: string): string {
  const raw = address.trim();
  if (raw === "") {
    return "";
  }
  try {
    const parsed = new URL(raw.includes("://") ? raw : `https://${raw}`);
    const usable =
      parsed.protocol === "https:" &&
      parsed.hostname !== "" &&
      parsed.username === "" &&
      parsed.password === "" &&
      parsed.pathname === "/" &&
      parsed.search === "" &&
      parsed.hash === "";
    return usable ? parsed.host.replace(/\.$/, "") : "";
  } catch {
    return "";
  }
}

export function buildAuthIssueCommand({
  address,
  subject,
  expires,
  os,
}: {
  address: string;
  subject: string;
  expires: string;
  os: TunnelCommandOS;
}): string {
  const host = applicationAuthHost(address);
  const trimmed = subject.trim();
  if (host === "" || trimmed === "") {
    return "";
  }
  return `portal auth issue ${formatToken(host, os)} --subject ${formatToken(trimmed, os)} --expires ${expires}`;
}

export function normalizeAbsoluteHTTPURL(raw: string): string {
  const trimmed = raw.trim();
  if (trimmed === "") {
    return "";
  }

  try {
    const parsed = new URL(trimmed);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return "";
    }
    return parsed.toString();
  } catch {
    return "";
  }
}

function getRelayOriginHost(origin: string): string {
  try {
    const parsed = new URL(origin);
    return parsed.hostname.trim().toLowerCase();
  } catch {
    return "";
  }
}

export function isLocalRelayOrigin(origin: string): boolean {
  try {
    const parsed = new URL(origin);
    return isLocalRelayHostname(parsed.hostname.trim().toLowerCase());
  } catch {
    return false;
  }
}

function isLocalRelayHostname(hostname: string): boolean {
  return (
    hostname === "localhost" ||
    hostname === "127.0.0.1" ||
    hostname === "::1" ||
    hostname.endsWith(".localhost")
  );
}
