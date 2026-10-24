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

export const DEFAULT_TUNNEL_AUTH: TunnelAuthOptions = {
  method: "none",
  allow: [],
  identityHeaders: false,
  oidcIssuer: GOOGLE_OIDC_ISSUER,
  oidcClientId: "",
};

/** Sign-in covers HTTP only, so the tunnel refuses to combine it with UDP. */
export function authBlocksUDP(auth: TunnelAuthOptions): boolean {
  return auth.method !== "none";
}

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
  const { installLine, exposeHead, exposeOptions } =
    buildTunnelCommandParts(options);

  return joinTunnelCommand(installLine, exposeHead, exposeOptions);
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
  auth = DEFAULT_TUNNEL_AUTH,
}: TunnelCommandOptions): {
  installLine: string;
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
  if (enableUDP && !authBlocksUDP(auth)) {
    exposeArgs.push("--udp");
    const normalizedUDPPort = udpPort.trim();
    if (normalizedUDPPort !== "") {
      exposeArgs.push(`--udp-addr ${formatToken(normalizedUDPPort, os)}`);
    }
  }

  if (auth.method !== "none") {
    exposeArgs.push(...buildAuthArgs(auth, os));
  }

  if (os === "windows") {
    return {
      installLine: [
        `$ProgressPreference = 'SilentlyContinue'`,
        `irm ${formatToken(installPowerShellURL, os)} | iex`,
      ].join("\n"),
      exposeHead: "portal expose",
      exposeOptions: [...leadingArgs, ...exposeArgs],
    };
  }

  const curlFlags = isLocalRelayOrigin(currentOrigin) ? "-ksSL" : "-sSL";
  return {
    // bash runs the installer in a subshell, so add its install dirs to this shell's PATH.
    installLine: `curl ${curlFlags} ${formatToken(installScriptURL, os)} | bash && export PATH="$HOME/.local/bin:$HOME/bin:$PATH"`,
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

/**
 * Reads the OIDC client secret at a prompt and exports it for the next
 * `portal expose` in the same shell. The secret never appears in the command
 * line (`ps`), in shell history (typed at a prompt, not after `export`) or in
 * the text that gets copied, so there is no placeholder to forget.
 */
export function buildOIDCSecretCommand(os: TunnelCommandOS): string {
  return os === "windows"
    ? "$secret = Read-Host 'OIDC client secret' -AsSecureString; $env:AUTH_OIDC_CLIENT_SECRET = [System.Net.NetworkCredential]::new('', $secret).Password"
    : "printf 'OIDC client secret: '; stty -echo; read -r AUTH_OIDC_CLIENT_SECRET; stty echo; echo; export AUTH_OIDC_CLIENT_SECRET";
}

function valueOrPlaceholder(
  value: string,
  placeholder: string,
  os: TunnelCommandOS
): string {
  const trimmed = value.trim();
  return trimmed === "" ? placeholder : formatToken(trimmed, os);
}

type AuthAllowKind =
  | "link name"
  | "wallet"
  | "person"
  | "domain"
  | "account id";

type AuthAllowCheck =
  | { ok: true; kind: AuthAllowKind }
  | { ok: false; error: string };

/**
 * Mirrors what `portal expose --auth-allow` accepts for each method. The Go
 * owners are normalizeApplicationAuthSubject (access_credential.go),
 * normalizeOIDCPrincipal (access_auth.go) and identity.NormalizeEVMAddress.
 * The browser has no Keccak, so a mixed-case wallet address is not checked
 * against its EIP-55 checksum here; the tunnel rejects a bad one at start.
 */
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
      : { ok: false, error: `${entry} needs an id of 1 to 256 printable characters after sub:.` };
  }
  if (!isPrintableSubject(entry)) {
    return {
      ok: false,
      error: `${entry} must be 1 to 256 printable characters.`,
    };
  }
  if (!isASCII(entry)) {
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

function isASCII(value: string): boolean {
  return ![...value].some((char) => (char.codePointAt(0) ?? 0) > 127);
}

// The tunnel limits a subject to 256 bytes, not characters.
function isPrintableSubject(value: string): boolean {
  const subject = value.trim();
  if (subject === "" || new TextEncoder().encode(subject).length > 256) {
    return false;
  }
  return ![...subject].some((char) => {
    const code = char.codePointAt(0) ?? 0;
    return code < 32 || (code >= 127 && code < 160);
  });
}

// normalizeOIDCIssuerURL also accepts http on a loopback host, which the
// builder does not offer.
function isOIDCIssuer(raw: string): boolean {
  try {
    const parsed = new URL(raw.trim());
    return (
      parsed.protocol === "https:" &&
      parsed.hostname !== "" &&
      parsed.username === "" &&
      parsed.password === "" &&
      parsed.search === "" &&
      parsed.hash === ""
    );
  } catch {
    return false;
  }
}

export type TunnelAuthField =
  | "allow"
  | "entries"
  | "issuer"
  | "clientId"
  | "name";

export interface TunnelAuthIssue {
  field: TunnelAuthField;
  message: string;
}

/**
 * What stops the generated command from being run as shown; empty when ready.
 * The one owner of these rules: the copy gate and the notices next to each
 * field both render from it.
 */
export function validateTunnelAuth(
  auth: TunnelAuthOptions,
  name: string
): TunnelAuthIssue[] {
  if (auth.method === "none") {
    return [];
  }
  const issues: TunnelAuthIssue[] = [];
  if (auth.method === "oidc") {
    if (auth.allow.length === 0) {
      issues.push({ field: "allow", message: "Add who may sign in" });
    }
    if (auth.oidcIssuer.trim() === "") {
      issues.push({ field: "issuer", message: "Add the issuer address" });
    } else if (!isOIDCIssuer(auth.oidcIssuer)) {
      issues.push({
        field: "issuer",
        message: "The issuer must be an https:// address without a query or fragment",
      });
    }
    if (auth.oidcClientId.trim() === "") {
      issues.push({ field: "clientId", message: "Add the client ID" });
    }
    if (normalizeExposeName(name) === "") {
      issues.push({
        field: "name",
        message: "Add a Name: the provider needs the exact redirect address",
      });
    }
  }
  if (auth.allow.some((entry) => !classifyAuthAllow(auth.method, entry).ok)) {
    issues.push({ field: "entries", message: "Fix the highlighted entries" });
  }
  return issues;
}

/**
 * Adds typed entries to an allowlist the way the tunnel reads it: emails are
 * lowercased, the `sub:` prefix is normalized, and entries that name the same
 * principal are kept once (wallet addresses compare without regard to case).
 */
export function addAuthAllow(
  method: TunnelAuthMethod,
  current: string[],
  draft: string
): string[] {
  const keyOf = (entry: string) => (method === "siwe" ? entry.toLowerCase() : entry);
  const next = [...current];
  const seen = new Set(next.map(keyOf));
  // A link name may contain spaces; the other entries never do.
  const separator = method === "credential" ? /,/ : /[,\s]+/;
  for (const typed of draft.split(separator).map((part) => part.trim())) {
    if (typed === "") {
      continue;
    }
    const entry = canonicalAuthAllow(method, typed);
    if (!seen.has(keyOf(entry))) {
      seen.add(keyOf(entry));
      next.push(entry);
    }
  }
  return next;
}

function canonicalAuthAllow(method: TunnelAuthMethod, entry: string): string {
  if (method !== "oidc") {
    return entry;
  }
  if (/^sub:/i.test(entry)) {
    return `sub:${entry.slice("sub:".length)}`;
  }
  // Lowercasing maps some non-ASCII letters onto ASCII ones (the Kelvin sign
  // onto "k"), which would turn a typed lookalike into a different, valid
  // address; the tunnel refuses such input, so it is kept as typed and flagged.
  return entry.includes("@") && isASCII(entry) ? entry.toLowerCase() : entry;
}

/** With names listed, the tunnel lets in only those subjects; with none, any valid one. */
export function isListedSubject(allow: string[], subject: string): boolean {
  return allow.length === 0 || allow.includes(subject.trim());
}

/** The address to register at an OIDC provider; empty until the name is known. */
export function buildAuthRedirectURL(origin: string, name: string): string {
  const publicURL = buildTunnelPreviewURL(origin, name);
  // applicationAuthCallbackPath in cmd/portal-tunnel/gateway/access_auth.go
  return publicURL === "" ? "" : `${publicURL}/_portal/auth/callback`;
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

// PowerShell also reads the typographic quotes U+2018 to U+201B as a single
// quote, so each of them is doubled like the ASCII one.
function quotePowerShellValue(value: string): string {
  return `'${value.replace(/['‘-‛]/g, "$&$&")}'`;
}

function formatToken(value: string, os: TunnelCommandOS): string {
  if (/^[A-Za-z0-9:/.=_-]+$/.test(value)) {
    return value;
  }
  return os === "windows" ? quotePowerShellValue(value) : quoteShellValue(value);
}

function joinTunnelCommand(
  installLine: string,
  exposeHead: string,
  exposeOptions: string[]
): string {
  return [installLine, [exposeHead, ...exposeOptions].join(" ")].join("\n");
}
