import { useEffect, useState } from "react";
import { readCurrentOrigin } from "@/hooks/useTunnelCommand";
import { apiClient } from "@/lib/apiClient";
import { RELAY_API_PATHS } from "@/lib/apiPaths";
import {
  mergeIncompatibleRelays,
  normalizeKnownRelays,
  normalizeRelayURL,
  type KnownRelay,
  type RelayReleases,
} from "@/lib/relays";
import type { DiscoveryResponse, DomainResponse } from "@/types/api";

interface RelayDiscoveryState {
  knownRelays: KnownRelay[];
  relayReleases: RelayReleases;
  /** The serving relay's release; empty until the relay reports one. */
  releaseVersion: string;
  loading: boolean;
}

function trimmedString(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

async function loadRelayDiscovery(
  currentRelayURL: string
): Promise<Omit<RelayDiscoveryState, "loading">> {
  const [domain, discovery] = await Promise.all([
    apiClient.get<DomainResponse>(RELAY_API_PATHS.sdk.domain).catch(() => null),
    apiClient.get<DiscoveryResponse>(RELAY_API_PATHS.discovery).catch(() => null),
  ]);

  const versions: Record<string, string> = {};
  for (const [url, version] of Object.entries(discovery?.relay_release_versions ?? {})) {
    const relayURL = normalizeRelayURL(url);
    const trimmedVersion = trimmedString(version);
    if (relayURL !== "" && trimmedVersion !== "") {
      versions[relayURL] = trimmedVersion;
    }
  }

  return {
    knownRelays: mergeIncompatibleRelays(
      normalizeKnownRelays(discovery?.relays, currentRelayURL),
      discovery?.incompatible_relays,
      currentRelayURL
    ),
    relayReleases: {
      versions,
      discovery: {
        release_version: discovery?.release_version,
        protocol_version: discovery?.protocol_version,
      },
    },
    releaseVersion:
      trimmedString(domain?.release_version) || trimmedString(discovery?.release_version),
  };
}

/**
 * The relays this relay knows of and their releases, read once per page. An
 * unreachable discovery endpoint leaves only the serving relay.
 */
export function useRelayDiscovery(): RelayDiscoveryState {
  const [state, setState] = useState<RelayDiscoveryState>({
    knownRelays: [],
    relayReleases: { versions: {} },
    releaseVersion: "",
    loading: true,
  });

  useEffect(() => {
    let cancelled = false;
    const currentRelayURL = readCurrentOrigin();
    loadRelayDiscovery(currentRelayURL)
      .catch(() => ({
        knownRelays: normalizeKnownRelays(undefined, currentRelayURL),
        relayReleases: { versions: {} },
        releaseVersion: "",
      }))
      .then((next) => {
        if (!cancelled) {
          setState({ ...next, loading: false });
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  return state;
}
