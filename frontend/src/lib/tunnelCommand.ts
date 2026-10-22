import { RELAY_API_PATHS } from "@/lib/apiPaths";
import { normalizeExposeName } from "@/lib/exposeName";
import type { ShareKind } from "@/lib/shareLink";

export type TunnelCommandOS = "unix" | "windows";

export type TunnelAuthMethod = "none" | "credential" | "siwe" | "oidc";

export const GOOGLE_OIDC_ISSUER = "https://accounts.google.com";

export interface TunnelAuthOptions {
  method: TunnelAuthMethod;
  /** `--auth-allow` entries as typed; classifyAuthAllow says what each one is. */
  allow: string[];
  identityHeaders: boolean;
  oidcIssuer: string;
  oidcClientId: string;
}

const NO_TUNNEL_AUTH: TunnelAuthOptions = {
  method: "none",
  allow: [],
  identityHeaders: false,
  oidcIssuer: "",
  oidcClientId: "",
};

export interface TunnelCommandOptions {
  currentOrigin: string;
  target: string;
  name: string;
  relayUrls: string[];
  discovery: boolean;
  thumbnailURL: string;
  enableUDP?: boolean;
  udpPort?: string;
  os: TunnelCommandOS;
  /** How the share input was classified; defaults to "port". */
  shareKind?: ShareKind;
  /** Local path passed to `--serve` when shareKind is "file". */
  servePath?: string;
  /** Who may open the public URL; defaults to anyone. */
  auth?: TunnelAuthOptions;
}

export function buildTunnelCommand(options: TunnelCommandOptions): string {
  const { installLine, secretLine, exposeHead, exposeOptions } =
    buildTunnelCommandParts(options);

  return joinTunnelCommand(installLine, secretLine, exposeHead, exposeOptions);
}

function buildTunnelCommandParts({
  currentOrigin,
  discovery,
  enableUDP = false,
  name,
  os,
  relayUrls,
  target,
  thumbnailURL,
  udpPort = "",
  shareKind = "port",
  servePath = "",
  auth = NO_TUNNEL_AUTH,
}: TunnelCommandOptions): {
  installLine: string;
  /** Sets the OIDC client secret for the shell; empty for other methods. */
  secretLine: string;
  exposeHead: string;
  exposeOptions: string[];
} {
  const isFile = shareKind === "file";
  const targetValue = target.trim() === "" ? "3000" : target.trim();
  const normalizedName = normalizeExposeName(name);
  const relayURLValue =
    relayUrls.length > 0 ? relayUrls.join(",") : currentOrigin;
  const leadingArgs = isFile
    ? ["--serve", formatToken(servePath, os)]
    : [formatToken(targetValue, os)];
  const installScriptURL = new URL(
    RELAY_API_PATHS.install.shell,
    currentOrigin
  ).toString();
  const installPowerShellURL = new URL(
    RELAY_API_PATHS.install.powershell,
    currentOrigin
  ).toString();

  const exposeArgs: string[] = [];

  if (normalizedName !== "") {
    exposeArgs.push(`--name ${formatToken(normalizedName, os)}`);
  }
  if (relayUrls.length > 0) {
    exposeArgs.push(`--relays ${formatToken(relayURLValue, os)}`);
  }
  if (!discovery) {
    exposeArgs.push("--discovery=false");
  }

  const normalizedThumbnailURL = normalizeAbsoluteHTTPURL(thumbnailURL);
  if (normalizedThumbnailURL !== "") {
    exposeArgs.push(`--thumbnail ${formatToken(normalizedThumbnailURL, os)}`);
  }
  // Sign-in covers HTTP only, so the tunnel refuses to combine it with UDP.
  const authenticated = auth.method !== "none";
  if (enableUDP && !authenticated) {
    exposeArgs.push("--udp");
    const normalizedUDPPort = udpPort.trim();
    if (normalizedUDPPort !== "") {
      exposeArgs.push(`--udp-addr ${formatToken(normalizedUDPPort, os)}`);
    }
  }

  if (authenticated) {
    exposeArgs.push(...buildAuthArgs(auth, os));
  }
  const secretLine = auth.method === "oidc" ? buildOIDCSecretLine(os) : "";

  if (os === "windows") {
    return {
      installLine: [
        `$ProgressPreference = 'SilentlyContinue'`,
        `irm ${formatToken(installPowerShellURL, os)} | iex`,
      ].join("\n"),
      secretLine,
      exposeHead: "portal expose",
      exposeOptions: [...leadingArgs, ...exposeArgs],
    };
  }

  const curlFlags = isLocalRelayOrigin(currentOrigin) ? "-ksSL" : "-sSL";
  return {
    // bash runs the installer in a subshell, so add its install dirs to this shell's PATH.
    installLine: `curl ${curlFlags} ${formatToken(installScriptURL, os)} | bash && export PATH="$HOME/.local/bin:$HOME/bin:$PATH"`,
    secretLine,
    exposeHead: "portal expose",
    exposeOptions: [...leadingArgs, ...exposeArgs],
  };
}

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
  return `https://${normalized}.${baseHost}`;
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

function buildAuthArgs(auth: TunnelAuthOptions, os: TunnelCommandOS): string[] {
  const args = [`--auth ${auth.method}`];
  if (auth.method === "oidc") {
    args.push(
      `--auth-oidc-issuer ${valueOrPlaceholder(auth.oidcIssuer, "<issuer>", os)}`,
      `--auth-oidc-client-id ${valueOrPlaceholder(auth.oidcClientId, "<client-id>", os)}`
    );
    if (auth.allow.length === 0) {
      args.push("--auth-allow <email, @domain or sub:id>");
    }
  }
  for (const entry of auth.allow) {
    args.push(`--auth-allow ${formatToken(entry, os)}`);
  }
  if (auth.identityHeaders) {
    args.push("--auth-identity-headers");
  }
  return args;
}

// The OIDC client secret travels in the environment, never in the command
// line where `ps` and shell history would show it.
function buildOIDCSecretLine(os: TunnelCommandOS): string {
  return os === "windows"
    ? "$env:AUTH_OIDC_CLIENT_SECRET = '<paste secret here>'"
    : "export AUTH_OIDC_CLIENT_SECRET='<paste secret here>'";
}

function valueOrPlaceholder(
  value: string,
  placeholder: string,
  os: TunnelCommandOS
): string {
  const trimmed = value.trim();
  return trimmed === "" ? placeholder : formatToken(trimmed, os);
}

export type AuthAllowKind =
  | "link name"
  | "wallet"
  | "person"
  | "domain"
  | "account id";

export type AuthAllowCheck =
  | { ok: true; kind: AuthAllowKind }
  | { ok: false; error: string };

/** Mirrors what `portal expose --auth-allow` accepts for each method. */
export function classifyAuthAllow(
  method: TunnelAuthMethod,
  entry: string
): AuthAllowCheck {
  if (method === "credential") {
    return isPrintableSubject(entry)
      ? { ok: true, kind: "link name" }
      : { ok: false, error: "A link name is 1 to 256 printable characters." };
  }
  if (method === "siwe") {
    return /^0[xX][0-9a-fA-F]{40}$/.test(entry)
      ? { ok: true, kind: "wallet" }
      : {
          ok: false,
          error: `${entry} is not a wallet address: 0x followed by 40 hex characters.`,
        };
  }

  if (/^sub:/i.test(entry)) {
    return isPrintableSubject(entry.slice("sub:".length))
      ? { ok: true, kind: "account id" }
      : { ok: false, error: `${entry} needs an id after sub:.` };
  }
  if ([...entry].some((char) => (char.codePointAt(0) ?? 0) > 127)) {
    return {
      ok: false,
      error: `${entry} must be ASCII; write an internationalized domain in punycode.`,
    };
  }
  const at = entry.indexOf("@");
  const domain = entry.slice(at + 1);
  if (at < 0 || domain === "" || /[@\s]/.test(domain)) {
    return {
      ok: false,
      error: `${entry} is not an email, an @domain or sub:<id>.`,
    };
  }
  return { ok: true, kind: at === 0 ? "domain" : "person" };
}

function isPrintableSubject(value: string): boolean {
  const subject = value.trim();
  if (subject === "" || subject.length > 256) {
    return false;
  }
  return ![...subject].some((char) => {
    const code = char.codePointAt(0) ?? 0;
    return code < 32 || (code >= 127 && code < 160);
  });
}

export function isHTTPSIssuer(raw: string): boolean {
  try {
    const parsed = new URL(raw.trim());
    return parsed.protocol === "https:" && parsed.hostname !== "";
  } catch {
    return false;
  }
}

/** What stops the generated command from being run as shown; empty when ready. */
export function validateTunnelAuth(
  auth: TunnelAuthOptions,
  name: string
): string[] {
  if (auth.method === "none") {
    return [];
  }
  const issues: string[] = [];
  if (auth.method === "oidc") {
    if (auth.allow.length === 0) {
      issues.push("Add who may sign in");
    }
    if (!isHTTPSIssuer(auth.oidcIssuer)) {
      issues.push("The issuer must be an https:// address");
    }
    if (auth.oidcClientId.trim() === "") {
      issues.push("Add the client ID");
    }
    if (normalizeExposeName(name) === "") {
      issues.push("Add a Name: the provider needs the exact redirect address");
    }
  }
  if (auth.allow.some((entry) => !classifyAuthAllow(auth.method, entry).ok)) {
    issues.push("Fix the highlighted entries");
  }
  return issues;
}

/** The address to register at an OIDC provider; empty until the name is known. */
export function buildAuthRedirectURL(origin: string, name: string): string {
  const hostname = buildServiceStatusHostname(origin, name);
  return hostname === "" ? "" : `https://${hostname}/_portal/auth/callback`;
}

/** The command that mints one private link; empty until it has a host and a subject. */
export function buildAuthIssueCommand({
  origin,
  name,
  subject,
  expires,
  os,
}: {
  origin: string;
  name: string;
  subject: string;
  expires: string;
  os: TunnelCommandOS;
}): string {
  const hostname = buildServiceStatusHostname(origin, name);
  const trimmed = subject.trim();
  if (hostname === "" || trimmed === "") {
    return "";
  }
  return `portal auth issue ${hostname} --subject ${formatToken(trimmed, os)} --expires ${expires}`;
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

function isLocalRelayOrigin(origin: string): boolean {
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

function quoteShellValue(value: string): string {
  return "'" + value.replace(/'/g, `'"'"'`) + "'";
}

function quotePowerShellValue(value: string): string {
  return `'${value.replace(/'/g, "''")}'`;
}

function formatToken(value: string, os: TunnelCommandOS): string {
  if (/^[A-Za-z0-9:/.=_-]+$/.test(value)) {
    return value;
  }
  return os === "windows" ? quotePowerShellValue(value) : quoteShellValue(value);
}

function joinTunnelCommand(
  installLine: string,
  secretLine: string,
  exposeHead: string,
  exposeOptions: string[]
): string {
  return [installLine, secretLine, [exposeHead, ...exposeOptions].join(" ")]
    .filter((line) => line !== "")
    .join("\n");
}
