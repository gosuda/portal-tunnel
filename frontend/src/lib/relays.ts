import type { DiscoveryResponse, RelayDescriptor, IncompatibleRelayEntry } from "@/types/api";

export interface RelayReleases {
  versions: Record<string, string>;
  discovery?: DiscoveryResponse;
}

export interface KnownRelay {
  relayURL: string;
  isCurrent: boolean;
  protocolVersion?: string;
}

export function normalizeRelayURL(relayURL: string | undefined): string {
  return typeof relayURL === "string" ? relayURL.trim() : "";
}

export function normalizeKnownRelays(
  relays: RelayDescriptor[] | undefined,
  currentRelayURL: string
): KnownRelay[] {
  const seen = new Set<string>();
  const knownRelays: KnownRelay[] = [];

  relays?.forEach((relay) => {
    const relayURL = normalizeRelayURL(relay.api_https_addr);
    if (relayURL === "" || seen.has(relayURL)) {
      return;
    }

    seen.add(relayURL);
    knownRelays.push({
      relayURL,
      isCurrent: relayURL === currentRelayURL,
    });
  });

  if (currentRelayURL !== "" && !seen.has(currentRelayURL)) {
    knownRelays.push({
      relayURL: currentRelayURL,
      isCurrent: true,
    });
  }

  knownRelays.sort((a, b) => {
    if (a.isCurrent !== b.isCurrent) {
      return a.isCurrent ? -1 : 1;
    }
    return a.relayURL.localeCompare(b.relayURL);
  });

  return knownRelays;
}

export function mergeIncompatibleRelays(
  knownRelays: KnownRelay[],
  incompatible: IncompatibleRelayEntry[] | undefined,
  currentRelayURL: string
): KnownRelay[] {
  if (!incompatible?.length) {
    return knownRelays;
  }

  const seen = new Set(knownRelays.map((relay) => relay.relayURL));
  const merged = [...knownRelays];

  incompatible.forEach((entry) => {
    const relayURL = normalizeRelayURL(entry.url);
    if (relayURL === "" || seen.has(relayURL)) {
      return;
    }
    seen.add(relayURL);
    merged.push({
      relayURL,
      isCurrent: relayURL === currentRelayURL,
      protocolVersion: entry.protocol_version?.trim() || undefined,
    });
  });

  return merged;
}

export function relayReleaseLabel(
  versions: Record<string, string>,
  relay: KnownRelay,
  discovery?: DiscoveryResponse
): string | null {
  const observed =
    versions[normalizeRelayURL(relay.relayURL)]?.trim() ?? "";
  if (observed !== "") {
    return observed;
  }

  if (relay.isCurrent) {
    const selfRelease =
      typeof discovery?.release_version === "string"
        ? discovery.release_version.trim()
        : "";
    if (selfRelease !== "") {
      return selfRelease;
    }
  }

  const protocolVersion =
    relay.protocolVersion?.trim() ||
    (relay.isCurrent && typeof discovery?.protocol_version === "string"
      ? discovery.protocol_version.trim()
      : "");
  if (protocolVersion !== "") {
    return `discovery ${protocolVersion}`;
  }

  return null;
}
