import { RELAY_API_PATHS } from "@/lib/apiPaths";
import { normalizeExposeName } from "@/lib/exposeName";
import type { ShareKind } from "@/lib/shareLink";
import {
  authBlocksUDP,
  buildAuthArgs,
  DEFAULT_TUNNEL_AUTH,
  type TunnelAuthOptions,
} from "./tunnelAuth";
import { isLocalRelayOrigin, normalizeAbsoluteHTTPURL } from "./tunnelUrls";
import type { TunnelCommandOS } from "./tunnelShell";
import { formatToken } from "./tunnelShell";

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

function udpExposeArgs(
  auth: TunnelAuthOptions,
  enableUDP: boolean,
  udpPort: string,
  os: TunnelCommandOS
): string[] {
  if (!enableUDP || authBlocksUDP(auth)) {
    return [];
  }
  const args = ["--udp"];
  const normalizedUDPPort = udpPort.trim();
  if (normalizedUDPPort !== "") {
    args.push(`--udp-addr ${formatToken(normalizedUDPPort, os)}`);
  }
  return args;
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
  exposeArgs.push(...udpExposeArgs(auth, enableUDP, udpPort, os));

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

function joinTunnelCommand(
  installLine: string,
  exposeHead: string,
  exposeOptions: string[]
): string {
  return [installLine, [exposeHead, ...exposeOptions].join(" ")].join("\n");
}

export type { TunnelCommandOS } from "./tunnelShell";
export {
  authBlocksUDP,
  buildSecretCommand,
  classifyAuthAllow,
  validateTunnelAuth,
  addAuthAllow,
  isListedSubject,
  DEFAULT_TUNNEL_AUTH,
  GOOGLE_OIDC_ISSUER,
} from "./tunnelAuth";
export type {
  TunnelAuthMethod,
  TunnelAuthOptions,
  TunnelAuthField,
  TunnelAuthIssue,
} from "./tunnelAuth";
export {
  buildTunnelPreviewURL,
  buildServiceStatusHostname,
  buildAuthRedirectURLs,
  applicationAuthHost,
  buildAuthIssueCommand,
  normalizeAbsoluteHTTPURL,
} from "./tunnelUrls";
