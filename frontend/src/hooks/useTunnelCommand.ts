import { useMemo, useState, type ChangeEvent } from "react";
import { useCopy } from "@/hooks/useCopy";
import { normalizeExposeName } from "@/lib/exposeName";
import { classifyShareInput } from "@/lib/shareLink";
import {
  DEFAULT_TUNNEL_AUTH,
  buildTunnelCommand,
  validateTunnelAuth,
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
  const { copiedKey, copy } = useCopy();
  const [auth, setAuth] = useState(DEFAULT_TUNNEL_AUTH);
  const os = extras.os ?? "unix";

  const share = useMemo(() => classifyShareInput(target), [target]);
  const effectiveName = normalizeExposeName(name);
  const authIssues = useMemo(
    () => validateTunnelAuth(auth, effectiveName),
    [auth, effectiveName]
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
      auth,
    }),
    [
      auth,
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

  const handleCopy = () => {
    if (authIssues.length > 0) {
      return;
    }
    return copy(command);
  };

  const handleNameChange = (event: ChangeEvent<HTMLInputElement>) => {
    setName(event.target.value);
  };

  return {
    currentOrigin,
    target,
    setTarget,
    name,
    copied: copiedKey !== null,
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
