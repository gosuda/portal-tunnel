import { isIP } from "node:net";

type ShellTarget = "unix" | "windows";

export const defaultRelayRegistryURL = "https://raw.githubusercontent.com/gosuda/portal-tunnel/main/registry.json";
export const defaultTunnelDownloadBaseURL = "https://github.com/gosuda/portal-tunnel/releases/latest/download";

export interface TunnelCommandOptions {
  readonly host: string;
  readonly name: string;
  readonly relayList: string;
  readonly thumbnail: string;
}

export interface TunnelCommandRuntime {
  readonly platform: NodeJS.Platform;
  readonly arch: string;
}

const invalidHostMessage = "Enter a port, host[:port], IP address, or HTTP(S) URL";

export function validateHost(value: string): string | undefined {
  const target = value.trim();
  if (!target) { return "Required"; }
  if (target.startsWith("-") || /[\s\\]/.test(target)) {
    return invalidHostMessage;
  }
  if (/^\d+$/.test(target)) {
    const port = Number(target);
    return Number.isInteger(port) && port >= 1 && port <= 65535
      ? undefined
      : invalidHostMessage;
  }
  if (isIP(target) === 6) { return undefined; }

  const hasScheme = target.includes("://");
  let parsed: URL;
  try {
    parsed = new URL(hasScheme ? target : "http://" + target);
  } catch {
    return invalidHostMessage;
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return invalidHostMessage;
  }
  if (!parsed.hostname || parsed.username || parsed.password ||
      parsed.pathname !== "/" || parsed.search || parsed.hash) {
    return invalidHostMessage;
  }

  const authority = hasScheme
    ? target.slice(target.indexOf("://") + 3).replace(/\/$/, "")
    : target;
  if (!authority || authority.startsWith("-") ||
      /[\/?#@%]/.test(authority) || authority.endsWith(":")) {
    return invalidHostMessage;
  }
  const hostname = parsed.hostname.startsWith("[")
    ? parsed.hostname.slice(1, -1)
    : parsed.hostname;
  if (isIP(hostname) === 0 &&
      hostname.replace(/\.$/, "").split(".").some((label) =>
        !/^[A-Za-z0-9_](?:[A-Za-z0-9_-]*[A-Za-z0-9_])?$/.test(label))) {
    return invalidHostMessage;
  }
  const portText = authority.match(/:(\d+)$/)?.[1];
  if (portText && (Number(portText) < 1 || Number(portText) > 65535)) {
    return invalidHostMessage;
  }
  return undefined;
}

export function validateRelayUrl(value: string): string | undefined {
  const trimmed = value.trim();
  if (!trimmed) {
    return "Required";
  }
  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    return "Enter a valid https:// URL";
  }
  if (parsed.protocol !== "https:") {
    return "Portal relay URLs must use https://";
  }
  return undefined;
}

export function resolveTunnelInstallerURL(
  platform: NodeJS.Platform = process.platform,
  arch: string = process.arch
): string | undefined {
  if (arch !== "x64" && arch !== "arm64") {
    return undefined;
  }
  if (platform === "darwin" || platform === "linux") {
    return `${defaultTunnelDownloadBaseURL}/install.sh`;
  }
  if (platform === "win32") {
    return `${defaultTunnelDownloadBaseURL}/install.ps1`;
  }
  return undefined;
}

export function buildCommand(
  opts: TunnelCommandOptions,
  runtime: TunnelCommandRuntime = process
): string {
  const { host, name, relayList, thumbnail } = opts;
  const hostError = validateHost(host);
  if (hostError !== undefined) {
    throw new Error("Invalid tunnel host: " + hostError);
  }
  const target: ShellTarget = runtime.platform === "win32" ? "windows" : "unix";
  const tunnelInstallerURL = resolveTunnelInstallerURL(runtime.platform, runtime.arch);
  if (!tunnelInstallerURL) {
    throw new Error(
      `Unsupported platform ${runtime.platform}/${runtime.arch}. Portal supports macOS, Linux, and Windows on x64 or arm64.`
    );
  }
  const exposeArgs: string[] = [];

  const trimmedName = name.trim();
  if (trimmedName) {
    exposeArgs.push(`--name ${formatToken(trimmedName, target)}`);
  }
  if (relayList.trim()) {
    exposeArgs.push(`--relays ${formatToken(relayList, target)}`);
  }
  if (thumbnail.trim()) {
    exposeArgs.push(`--thumbnail ${formatToken(thumbnail.trim(), target)}`);
  }

  const exposeCommand = `expose ${[...exposeArgs, "--", formatToken(host.trim(), target)].join(" ")}`;

  if (target === "windows") {
    return [
      `$ProgressPreference = 'SilentlyContinue'`,
      `irm ${formatToken(tunnelInstallerURL, target)} | iex`,
      `$PortalBin = Join-Path $env:LOCALAPPDATA 'portal\\bin\\portal.exe'`,
      `if (-not (Test-Path $PortalBin)) { throw 'Portal install failed: portal.exe not found.' }`,
      `& $PortalBin ${exposeCommand}`,
    ].join("\n");
  }

  return [
    `set -e`,
    `PORTAL_INSTALLER="$(mktemp "\${TMPDIR:-/tmp}/portal-install.XXXXXX" 2>/dev/null || mktemp -t portal-install)"`,
    `curl -fsSL ${formatToken(tunnelInstallerURL, target)} -o "$PORTAL_INSTALLER"`,
    `sh "$PORTAL_INSTALLER"`,
    `rm -f "$PORTAL_INSTALLER"`,
    `PORTAL_BIN="$(command -v portal 2>/dev/null || true)"`,
    `if [ -z "$PORTAL_BIN" ] && [ -x "$HOME/.local/bin/portal" ]; then PORTAL_BIN="$HOME/.local/bin/portal"; fi`,
    `if [ -z "$PORTAL_BIN" ] && [ -x "$HOME/bin/portal" ]; then PORTAL_BIN="$HOME/bin/portal"; fi`,
    `if [ -z "$PORTAL_BIN" ]; then echo "Portal install failed: portal executable not found." >&2; exit 1; fi`,
    `"$PORTAL_BIN" ${exposeCommand}`,
  ].join("\n");
}

function quoteShellValue(value: string): string {
  return "'" + value.replace(/'/g, `'\"'\"'`) + "'";
}

function quotePowerShellValue(value: string): string {
  return `'${value.replace(/'/g, "''")}'`;
}

function formatToken(value: string, target: ShellTarget): string {
  if (/^[A-Za-z0-9:/.=_,-]+$/.test(value)) {
    return value;
  }
  return target === "windows" ? quotePowerShellValue(value) : quoteShellValue(value);
}
