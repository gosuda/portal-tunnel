import { RELAY_API_PATHS } from "@/lib/apiPaths";
import { normalizeExposeName } from "@/lib/exposeName";
import type { ShareKind } from "@/lib/shareLink";

export type TunnelCommandOS = "unix" | "windows";

export type TunnelAuthMethod =
  | "none"
  | "credential"
  | "siwe"
  | "oidc"
  | "saml"
  | "email";

export const GOOGLE_OIDC_ISSUER = "https://accounts.google.com";

export interface TunnelAuthOptions {
  method: TunnelAuthMethod;
  allow: string[];
  identityHeaders: boolean;
  oidcIssuer: string;
  oidcClientId: string;
  samlMetadataURL: string;
  samlEntityId: string;
  samlSubjectAttribute: string;
  emailSMTPAddr: string;
  emailSMTPUsername: string;
  emailFrom: string;
}

export const DEFAULT_TUNNEL_AUTH: TunnelAuthOptions = {
  method: "none",
  allow: [],
  identityHeaders: false,
  oidcIssuer: GOOGLE_OIDC_ISSUER,
  oidcClientId: "",
  samlMetadataURL: "",
  samlEntityId: "",
  samlSubjectAttribute: "",
  emailSMTPAddr: "",
  emailSMTPUsername: "",
  emailFrom: "",
};

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
  shareKind?: ShareKind;
  servePath?: string;
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

  const exposeOptions = [...leadingArgs, ...exposeArgs];
  if (os === "windows") {
    return {
      installLine: [
        `$ProgressPreference = 'SilentlyContinue'`,
        `irm ${formatToken(installPowerShellURL, os)} | iex`,
      ].join("\n"),
      exposeHead: "portal expose",
      exposeOptions,
    };
  }

  const curlFlags = isLocalRelayOrigin(currentOrigin) ? "-ksSL" : "-sSL";
  return {
    installLine: `curl ${curlFlags} ${formatToken(installScriptURL, os)} | bash && export PATH="$HOME/.local/bin:$HOME/bin:$PATH"`,
    exposeHead: "portal expose",
    exposeOptions,
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

function buildAuthArgs(auth: TunnelAuthOptions, os: TunnelCommandOS): string[] {
  const args = [`--auth ${auth.method}`];
  if (auth.method === "oidc") {
    args.push(
      `--auth-oidc-issuer ${valueOrPlaceholder(auth.oidcIssuer, "<issuer>", os)}`,
      `--auth-oidc-client-id ${valueOrPlaceholder(auth.oidcClientId, "<client-id>", os)}`
    );
  }
  if (auth.method === "saml") {
    args.push(
      `--auth-saml-metadata-url ${valueOrPlaceholder(auth.samlMetadataURL, "<metadata-url>", os)}`
    );
    if (auth.samlEntityId.trim() !== "") {
      args.push(`--auth-saml-entity-id ${formatToken(auth.samlEntityId.trim(), os)}`);
    }
    if (auth.samlSubjectAttribute.trim() !== "") {
      args.push(
        `--auth-saml-subject-attribute ${formatToken(auth.samlSubjectAttribute.trim(), os)}`
      );
    }
  }
  if (auth.method === "email") {
    args.push(
      `--auth-smtp-addr ${valueOrPlaceholder(auth.emailSMTPAddr, "<host:port>", os)}`,
      `--auth-smtp-from ${valueOrPlaceholder(auth.emailFrom, "<sender>", os)}`
    );
    if (auth.emailSMTPUsername.trim() !== "") {
      args.push(
        `--auth-smtp-username ${formatToken(auth.emailSMTPUsername.trim(), os)}`
      );
    }
  }
  const emailList = needsAllowlist(auth.method);
  const allowFlag = emailList ? "--auth-email-list" : "--auth-allow";
  if (emailList && auth.allow.length === 0) {
    args.push(
      auth.method === "email"
        ? `${allowFlag} <email or @domain>`
        : `${allowFlag} <email, @domain or sub:id>`
    );
  }
  for (const entry of auth.allow) {
    args.push(`${allowFlag} ${formatToken(entry, os)}`);
  }
  if (auth.identityHeaders) {
    args.push("--auth-identity-headers");
  }
  return args;
}

const SECRETS = {
  oidc: { prompt: "OIDC client secret", variable: "AUTH_OIDC_CLIENT_SECRET" },
  email: { prompt: "SMTP password", variable: "AUTH_SMTP_PASSWORD" },
} as const;

export function buildSecretCommand(
  secret: keyof typeof SECRETS,
  os: TunnelCommandOS
): string {
  const { prompt, variable } = SECRETS[secret];
  return os === "windows"
    ? `$secret = Read-Host '${prompt}' -AsSecureString; $env:${variable} = [System.Net.NetworkCredential]::new('', $secret).Password`
    : `printf '${prompt}: '; stty -echo; read -r ${variable}; stty echo; echo; export ${variable}`;
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

function needsAllowlist(method: TunnelAuthMethod): boolean {
  return method === "oidc" || method === "saml" || method === "email";
}

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
    if (method === "email") {
      return {
        ok: false,
        error: `${entry}: email sign-in takes an email or an @domain, not sub:<id>.`,
      };
    }
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
  if (method === "email" && !isVisitorEmail(at === 0 ? `a${entry}` : entry)) {
    return { ok: false, error: `${entry} is not an address a visitor can sign in with.` };
  }
  return { ok: true, kind: at === 0 ? "domain" : "person" };
}

const mailAtom = "[a-zA-Z0-9#$&'*+/=?^_`{|}~-]+";
const mailAddress = `${mailAtom}(\\.${mailAtom})*@${mailAtom}(\\.${mailAtom})*`;
const visitorEmail = new RegExp(`^${mailAddress}$`);

const senderName = `(?:"[^"\\\\]*"|[^"<>@,;:()\\[\\]\\\\]+)`;
const emailSender = new RegExp(`^(?:${mailAddress}|(?:${senderName}\\s*)?<${mailAddress}>)$`);

function isEmailSender(raw: string): boolean {
  const sender = raw.trim();
  return !/[\u0000-\u001f\u007f-\u009f]/.test(sender) && emailSender.test(sender);
}

function isVisitorEmail(entry: string): boolean {
  return entry.length <= 254 && visitorEmail.test(entry);
}

function isASCII(value: string): boolean {
  return ![...value].some((char) => (char.codePointAt(0) ?? 0) > 127);
}

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

function isSAMLMetadataURL(raw: string): boolean {
  try {
    const parsed = new URL(raw.trim());
    return (
      parsed.protocol === "https:" &&
      parsed.hostname !== "" &&
      parsed.username === "" &&
      parsed.password === "" &&
      parsed.hash === ""
    );
  } catch {
    return false;
  }
}

function isEmailSMTPAddr(raw: string): boolean {
  const match = /^(?:\[([^[\]]*)\]|([^[\]:]*)):([+-]?\d+)$/.exec(raw.trim());
  if (match === null) {
    return false;
  }
  const host = match[1] ?? match[2] ?? "";
  const port = Number(match[3]);
  return (
    host !== "" &&
    !/[\u0000-\u001f\u007f-\u009f]/.test(host) &&
    port >= 1 &&
    port <= 65535
  );
}

export type TunnelAuthField =
  | "allow"
  | "entries"
  | "issuer"
  | "clientId"
  | "metadataURL"
  | "smtpAddr"
  | "from";

export interface TunnelAuthIssue {
  field: TunnelAuthField;
  message: string;
}

export function validateTunnelAuth(auth: TunnelAuthOptions): TunnelAuthIssue[] {
  if (auth.method === "none") {
    return [];
  }
  const issues: TunnelAuthIssue[] = [];
  if (needsAllowlist(auth.method) && auth.allow.length === 0) {
    issues.push({ field: "allow", message: "Add who may sign in" });
  }
  if (auth.method === "oidc") {
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
  }
  if (auth.method === "saml") {
    if (auth.samlMetadataURL.trim() === "") {
      issues.push({ field: "metadataURL", message: "Add the metadata address" });
    } else if (!isSAMLMetadataURL(auth.samlMetadataURL)) {
      issues.push({
        field: "metadataURL",
        message: "The metadata address must be an https:// address without a fragment",
      });
    }
  }
  if (auth.method === "email") {
    if (auth.emailSMTPAddr.trim() === "") {
      issues.push({ field: "smtpAddr", message: "Add the SMTP server" });
    } else if (!isEmailSMTPAddr(auth.emailSMTPAddr)) {
      issues.push({
        field: "smtpAddr",
        message: "The SMTP server must be host:port, with a port from 1 to 65535",
      });
    }
    if (auth.emailFrom.trim() === "") {
      issues.push({ field: "from", message: "Add the sender address" });
    } else if (!isEmailSender(auth.emailFrom)) {
      issues.push({
        field: "from",
        message: "The sender must be one address, such as Portal <login@example.com>",
      });
    }
  }
  if (auth.allow.some((entry) => !classifyAuthAllow(auth.method, entry).ok)) {
    issues.push({ field: "entries", message: "Fix the highlighted entries" });
  }
  return issues;
}

export function addAuthAllow(
  method: TunnelAuthMethod,
  current: string[],
  draft: string
): string[] {
  const keyOf = (entry: string) => (method === "siwe" ? entry.toLowerCase() : entry);
  const next = [...current];
  const seen = new Set(next.map(keyOf));
  const separator = method === "siwe" ? /[,\s]+/ : /,/;
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
  if (!needsAllowlist(method)) {
    return entry;
  }
  if (/^sub:/i.test(entry)) {
    return `sub:${entry.slice("sub:".length)}`;
  }
  return entry.includes("@") && isASCII(entry) ? entry.toLowerCase() : entry;
}

export function isListedSubject(allow: string[], subject: string): boolean {
  return allow.length === 0 || allow.includes(subject.trim());
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
