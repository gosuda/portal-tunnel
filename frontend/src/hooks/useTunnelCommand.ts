import { useEffect, useMemo, useState, type ChangeEvent } from "react";
import {
  buildDefaultExposeName,
  normalizeExposeName,
} from "@/lib/exposeName";
import {
  buildTunnelCommand,
  buildTunnelDisplayCommand,
  type TunnelCommandOS,
} from "@/lib/tunnelCommand";

export const DEFAULT_HOST = "3000";

const FALLBACK_ORIGIN = "https://localhost:4017";
const TUNNEL_NAME_SEED_STORAGE_KEY = "portal:tunnel-name-seed";

export function readCurrentOrigin(): string {
  if (typeof window !== "undefined") {
    return window.location.origin;
  }

  return FALLBACK_ORIGIN;
}

function readTunnelNameSeed(): string {
  if (typeof window === "undefined") {
    return "web_portal";
  }

  try {
    const existing = window.localStorage.getItem(TUNNEL_NAME_SEED_STORAGE_KEY);
    if (existing && existing.trim() !== "") {
      return existing;
    }

    const next =
      typeof window.crypto?.randomUUID === "function"
        ? `web_${window.crypto.randomUUID()}`
        : `web_${Math.random().toString(36).slice(2)}${Date.now().toString(36)}`;

    window.localStorage.setItem(TUNNEL_NAME_SEED_STORAGE_KEY, next);
    return next;
  } catch {
    return "web_portal";
  }
}

function nextTunnelNameShuffleKey(): string {
  if (
    typeof window !== "undefined" &&
    typeof window.crypto?.randomUUID === "function"
  ) {
    return window.crypto.randomUUID();
  }

  return `${Date.now().toString(36)}${Math.random().toString(36).slice(2)}`;
}

interface TunnelCommandExtras {
  relayUrls?: string[];
  discovery?: boolean;
  thumbnailURL?: string;
  enableUDP?: boolean;
  udpPort?: string;
}

export function useTunnelCommand(extras: TunnelCommandExtras = {}) {
  const currentOrigin = useMemo(() => readCurrentOrigin(), []);
  const [nameSeed] = useState(readTunnelNameSeed);

  const [target, setTarget] = useState(DEFAULT_HOST);
  const [name, setName] = useState("");
  const [nameShuffleKey, setNameShuffleKey] = useState("default");
  const [copied, setCopied] = useState(false);
  const [os, setOs] = useState<TunnelCommandOS>("unix");

  const resolvedNameSeed = `${nameSeed}:${nameShuffleKey}`;
  const generatedName = buildDefaultExposeName(target, resolvedNameSeed);
  const normalizedName = normalizeExposeName(name);
  const effectiveName = normalizedName === "" ? generatedName : normalizedName;
  const commandOptions = useMemo(
    () => ({
      currentOrigin,
      target,
      name: effectiveName,
      nameSeed,
      relayUrls: extras.relayUrls ?? [currentOrigin],
      discovery: extras.discovery ?? true,
      thumbnailURL: extras.thumbnailURL ?? "",
      enableUDP: extras.enableUDP ?? false,
      udpPort: extras.udpPort ?? "",
      os,
    }),
    [
      currentOrigin,
      effectiveName,
      extras.discovery,
      extras.enableUDP,
      extras.relayUrls,
      extras.thumbnailURL,
      extras.udpPort,
      nameSeed,
      os,
      target,
    ]
  );
  const copyCommand = useMemo(
    () => buildTunnelCommand(commandOptions),
    [commandOptions]
  );
  const displayCommand = useMemo(
    () => buildTunnelDisplayCommand(commandOptions),
    [commandOptions]
  );
  const { installBlock, runBlock } = useMemo(
    () => {
      const lines = displayCommand.split("\n");
      const installLineCount = os === "windows" ? 2 : 1;

      return {
        installBlock: lines.slice(0, installLineCount).join("\n"),
        runBlock: lines.slice(installLineCount).join("\n"),
      };
    },
    [displayCommand, os]
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
    try {
      await navigator.clipboard.writeText(copyCommand);
      setCopied(true);
    } catch (error) {
      console.error("Failed to copy tunnel command", error);
    }
  };

  const handleNameChange = (event: ChangeEvent<HTMLInputElement>) => {
    setName(event.target.value);
  };

  const handleShuffleName = () => {
    setName("");
    setNameShuffleKey(nextTunnelNameShuffleKey());
  };

  return {
    currentOrigin,
    nameSeed,
    target,
    setTarget,
    name,
    copied,
    os,
    setOs,
    generatedName,
    effectiveName,
    installBlock,
    runBlock,
    handleCopy,
    handleNameChange,
    handleShuffleName,
  };
}
