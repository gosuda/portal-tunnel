import * as os from "os";

export type ShellTarget = "unix" | "windows";

export const defaultTunnelDownloadBaseURL = "https://github.com/gosuda/portal-tunnel/releases/latest/download";

export interface TunnelCommandOptions {
  host: string;
  name: string;
  relayList: string;
  thumbnail: string;
  tunnelInstallerURL?: string;
}

export interface TunnelCommandRuntime {
  shellTarget: ShellTarget;
  platform: NodeJS.Platform;
  arch: string;
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

export function shellTargetForPlatform(platform = os.platform()): ShellTarget {
  return platform === "win32" ? "windows" : "unix";
}

export function defaultTunnelCommandRuntime(
  platform = os.platform(),
  arch = os.arch()
): TunnelCommandRuntime {
  return {
    shellTarget: shellTargetForPlatform(platform),
    platform,
    arch,
  };
}

export function resolveTunnelInstallerURL(
  platform = os.platform(),
  arch = os.arch()
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
  runtime = defaultTunnelCommandRuntime()
): string {
  const { host, name, relayList, thumbnail } = opts;
  const target = runtime.shellTarget;
  const tunnelInstallerURL =
    opts.tunnelInstallerURL?.trim() ||
    resolveTunnelInstallerURL(runtime.platform, runtime.arch);
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

  const exposeCommand = `expose ${[formatToken(host, target), ...exposeArgs].join(" ")}`;

  if (target === "windows") {
    const commandLines = [
      `$ProgressPreference = 'SilentlyContinue'`,
      `irm ${formatToken(tunnelInstallerURL, target)} | iex`,
      `$PortalBin = Join-Path $env:LOCALAPPDATA 'portal\\bin\\portal.exe'`,
      `if (-not (Test-Path $PortalBin)) { throw 'Portal install failed: portal.exe not found.' }`,
    ];
    commandLines.push(`& $PortalBin ${exposeCommand}`);
    return commandLines.join("\n");
  }

  const commandLines = [
    `set -e`,
    `PORTAL_INSTALLER="$(mktemp "${"$"}{TMPDIR:-/tmp}/portal-install.XXXXXX" 2>/dev/null || mktemp -t portal-install)"`,
    `curl -fsSL ${formatToken(tunnelInstallerURL, target)} -o "$PORTAL_INSTALLER"`,
    `sh "$PORTAL_INSTALLER"`,
    `rm -f "$PORTAL_INSTALLER"`,
    `PORTAL_BIN="$(command -v portal 2>/dev/null || true)"`,
    `if [ -z "$PORTAL_BIN" ] && [ -x "$HOME/.local/bin/portal" ]; then PORTAL_BIN="$HOME/.local/bin/portal"; fi`,
    `if [ -z "$PORTAL_BIN" ] && [ -x "$HOME/bin/portal" ]; then PORTAL_BIN="$HOME/bin/portal"; fi`,
    `if [ -z "$PORTAL_BIN" ]; then echo "Portal install failed: portal executable not found." >&2; exit 1; fi`,
    `"${"$"}PORTAL_BIN" ${exposeCommand}`,
  ];
  return commandLines.join("\n");
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
