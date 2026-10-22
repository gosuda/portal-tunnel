import { useEffect, useMemo, useState, type ChangeEvent } from "react";
import { normalizeExposeName } from "@/lib/exposeName";
import { classifyShareInput } from "@/lib/shareLink";
import {
  GOOGLE_OIDC_ISSUER,
  buildTunnelCommand,
  validateTunnelAuth,
  type TunnelAuthMethod,
  type TunnelCommandOS,
} from "@/lib/tunnelCommand";

export const DEFAULT_HOST = "3000";

const FALLBACK_ORIGIN = "https://localhost";

export function readCurrentOrigin(): string {
  if (typeof window !== "undefined") {
    return window.location.origin;
  }

  return FALLBACK_ORIGIN;
}

export interface TunnelAuthState {
  method: TunnelAuthMethod;
  /** Each method keeps its own list, so switching back loses nothing. */
  allow: Record<TunnelAuthMethod, string[]>;
  identityHeaders: boolean;
  oidcIssuer: string;
  oidcClientId: string;
}

const INITIAL_AUTH: TunnelAuthState = {
  method: "none",
  allow: { none: [], credential: [], siwe: [], oidc: [] },
  identityHeaders: false,
  oidcIssuer: GOOGLE_OIDC_ISSUER,
  oidcClientId: "",
};

interface TunnelCommandExtras {
  relayUrls?: string[];
  discovery?: boolean;
  thumbnailURL?: string;
  enableUDP?: boolean;
  udpPort?: string;
  os?: TunnelCommandOS;
}

export function useTunnelCommand(extras: TunnelCommandExtras = {}) {
  const currentOrigin = useMemo(() => readCurrentOrigin(), []);

  // Empty by default so the field reads as "paste a link here" instead of
  // pre-committing the user to a local port.
  const [target, setTarget] = useState("");
  const [name, setName] = useState("");
  const [copied, setCopied] = useState(false);
  const [auth, setAuth] = useState(INITIAL_AUTH);
  const os = extras.os ?? "unix";

  const share = useMemo(() => classifyShareInput(target), [target]);
  const effectiveName = normalizeExposeName(name);
  const authOptions = useMemo(
    () => ({
      method: auth.method,
      allow: auth.allow[auth.method],
      identityHeaders: auth.identityHeaders,
      oidcIssuer: auth.oidcIssuer,
      oidcClientId: auth.oidcClientId,
    }),
    [auth]
  );
  const authIssues = useMemo(
    () => validateTunnelAuth(authOptions, effectiveName),
    [authOptions, effectiveName]
  );
  const commandOptions = useMemo(
    () => ({
      currentOrigin,
      target: share.target,
      name: effectiveName,
      relayUrls: extras.relayUrls ?? [currentOrigin],
      discovery: extras.discovery ?? true,
      thumbnailURL: extras.thumbnailURL ?? "",
      enableUDP: extras.enableUDP ?? false,
      udpPort: extras.udpPort ?? "",
      os,
      shareKind: share.kind,
      servePath: share.path,
      auth: authOptions,
    }),
    [
      authOptions,
      currentOrigin,
      effectiveName,
      extras.discovery,
      extras.enableUDP,
      extras.relayUrls,
      extras.thumbnailURL,
      extras.udpPort,
      os,
      share.kind,
      share.path,
      share.target,
    ]
  );
  const command = useMemo(
    () => buildTunnelCommand(commandOptions),
    [commandOptions]
  );
  const { installBlock, runBlock } = useMemo(
    () => {
      const lines = command.split("\n");
      const installLineCount = os === "windows" ? 2 : 1;

      return {
        installBlock: lines.slice(0, installLineCount).join("\n"),
        runBlock: lines.slice(installLineCount).join("\n"),
      };
    },
    [command, os]
  );

  useEffect(() => {
    if (!copied) {
      return;
    }

    const timer = window.setTimeout(() => {
      setCopied(false);
    }, 2000);

    return () => {
      window.clearTimeout(timer);
    };
  }, [copied]);

  const handleCopy = async () => {
    if (authIssues.length > 0) {
      return;
    }
    try {
      await navigator.clipboard.writeText(command);
      setCopied(true);
    } catch (error) {
      console.error("Failed to copy tunnel command", error);
    }
  };

  const handleNameChange = (event: ChangeEvent<HTMLInputElement>) => {
    setName(event.target.value);
  };

  return {
    currentOrigin,
    target,
    setTarget,
    name,
    copied,
    os,
    effectiveName,
    auth,
    setAuth,
    authIssues,
    shareKind: share.kind,
    installBlock,
    runBlock,
    handleCopy,
    handleNameChange,
  };
}
