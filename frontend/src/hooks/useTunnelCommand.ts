import { useMemo, useState, type ChangeEvent, type Dispatch, type SetStateAction } from "react";
import { useCopy } from "@/hooks/useCopy";
import { readCurrentOrigin } from "@/lib/origin";
import { normalizeExposeName } from "@/lib/exposeName";
import { classifyShareInput, type ShareKind } from "@/lib/shareLink";
import {
  DEFAULT_TUNNEL_AUTH,
  buildTunnelCommand,
  validateTunnelAuth,
  type TunnelAuthIssue,
  type TunnelAuthOptions,
  type TunnelCommandOS,
} from "@/lib/tunnelCommand";

export const DEFAULT_HOST = "3000";

interface TunnelCommandExtras {
  relayUrls?: string[];
  discovery?: boolean;
  thumbnailURL?: string;
  enableUDP?: boolean;
  udpPort?: string;
  os?: TunnelCommandOS;
}

export function useTunnelCommand(extras: TunnelCommandExtras = {}): { target: string; setTarget: Dispatch<SetStateAction<string>>; name: string; copied: boolean; effectiveName: string; auth: TunnelAuthOptions; setAuth: Dispatch<SetStateAction<TunnelAuthOptions>>; authIssues: TunnelAuthIssue[]; shareKind: ShareKind; installBlock: string; runBlock: string; handleCopy: () => Promise<void> | undefined; handleNameChange: (event: ChangeEvent<HTMLInputElement>) => void } {
  const currentOrigin = useMemo(() => readCurrentOrigin(), []);

  const [target, setTarget] = useState("");
  const [name, setName] = useState("");
  const { copiedKey, copy } = useCopy();
  const [auth, setAuth] = useState(DEFAULT_TUNNEL_AUTH);
  const os = extras.os ?? "unix";

  const share = useMemo(() => classifyShareInput(target), [target]);
  const effectiveName = normalizeExposeName(name);
  const authIssues = useMemo(() => validateTunnelAuth(auth), [auth]);
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
    target,
    setTarget,
    name,
    copied: copiedKey !== null,
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
