import {
  parseLeaseMetadata,
  resolveLeasePayment,
  resolveLeaseThumbnail,
} from "@/lib/metadata";
import type { DiscoveredService, Lease, ObservedReputation, ReputationSummary, ServiceLocation } from "@/types/api";

export interface BaseServer {
  id: string;
  name: string;
  description: string;
  tags: string[];
  thumbnail: string;
  owner: string;
  online: boolean;
  dns: string;
  link: string;
  address?: string;
  serviceName?: string;
  locations?: ServiceLocation[];
  remoteOnly?: boolean;
  tcpAddr?: string;
  udpAddr?: string;
  lastUpdated?: string;
  firstSeen?: string;
  paymentEnabled?: boolean;
  paymentLabel?: string;
  reputation?: ReputationSummary;
  // Display-only totals; local moderation and viewer votes use reputation.
  observedReputation?: ObservedReputation;
}

// A service identity address is a 0x-prefixed 20-byte hex string.
export function isIdentityAddress(value: string): boolean {
  return /^0x[0-9a-f]{40}$/i.test(value);
}

// A newer observation from a relay replaces its older one; other relays stay.
export function mergeLocations(
  existing: ServiceLocation[],
  incoming: ServiceLocation[],
): ServiceLocation[] {
  const byRelay = new Map(existing.map((location) => [location.relay_url, location]));
  for (const location of incoming) byRelay.set(location.relay_url, location);
  return [...byRelay.values()];
}

// A live location is reported ready by its relay and its observation has not expired.
export function isLocationLive(location: ServiceLocation, now: number = Date.now()): boolean {
  const expires = Date.parse(location.expires_at);
  return location.reported_ready === true && Number.isFinite(expires) && expires > now;
}

// An available location is live and has an HTTPS URL, so it is a navigation target.
export function isLocationAvailable(location: ServiceLocation, now: number = Date.now()): boolean {
  if (!isLocationLive(location, now) || !location.url) return false;
  try {
    return new URL(location.url).protocol === "https:";
  } catch {
    return false;
  }
}

// The directory groups observations by name and owner. Prefer local card data
// when available so its link, thumbnail, community actions, and status stay intact.
export function mergeDiscoveredServices(
  local: BaseServer[],
  services: DiscoveredService[],
  address: string = "",
): BaseServer[] {
  const wantedAddress = address.trim().toLowerCase();
  const matchesAddress = (candidate?: string) =>
    !wantedAddress || candidate?.trim().toLowerCase() === wantedAddress;
  const identityKey = (name: string | undefined, owner: string) =>
    `${(name ?? "").trim().toLowerCase()}:${owner.trim().toLowerCase()}`;
  const byIdentity = new Map<string, BaseServer>();
  for (const server of local) {
    if (!matchesAddress(server.address)) continue;
    const key = server.address
      ? identityKey(server.serviceName, server.address)
      : `local:${server.id}`;
    if (!byIdentity.has(key)) byIdentity.set(key, server);
  }
  for (const service of services) {
    if (!matchesAddress(service.address)) continue;
    const key = identityKey(service.name, service.address);
    const existing = byIdentity.get(key);
    if (existing) {
      // tcpAddr/udpAddr of a local card stay the local lease's own endpoints;
      // the card reads remote endpoints from these locations.
      byIdentity.set(key, { ...existing, locations: mergeLocations(existing.locations ?? [], service.locations) });
      continue;
    }
    // A local-only snapshot is not a substitute for the live local card list.
    const locations = service.locations.filter((location) => !location.current_relay);
    if (!locations.length) continue;
    const metadata = parseLeaseMetadata(service.metadata);
    const reportedLocations = locations.filter((loc) => loc.reputation !== undefined);
    const totals = reportedLocations.reduce(
      (acc, loc) => {
        if (loc.reputation) {
          acc.up += loc.reputation.up;
          acc.down += loc.reputation.down;
        }
        return acc;
      },
      { up: 0, down: 0 }
    );
    const live = locations.filter((location) => isLocationLive(location));
    byIdentity.set(key, {
      id: `service:${key}`,
      serviceName: service.name,
      name: service.name || "(unnamed)",
      address: service.address,
      description: metadata.description,
      tags: metadata.tags,
      owner: metadata.owner,
      thumbnail: "",
      online: live.length > 0,
      dns: "",
      link: "",
      remoteOnly: true,
      locations,
      // Only a live relay is a connect target. When every relay is offline the
      // card shows no endpoint instead of an address that cannot answer.
      tcpAddr: live.find((location) => location.tcp_addr)?.tcp_addr,
      udpAddr: live.find((location) => location.udp_addr)?.udp_addr,
      observedReputation: reportedLocations.length ? totals : undefined,
    });
  }
  return [...byIdentity.values()];
}

export function leaseToServer(row: Lease): BaseServer {
  const metadata = parseLeaseMetadata(row.metadata);
  const payment = resolveLeasePayment(metadata);
  const hostname = row.hostname || "";
  const routeHostname = row.canonical_hostname || hostname;
  const canonicalAvailable =
    row.namespace === "local-tls-v1" && row.canonical_ready === true;
  const publicHostname =
    hostname ||
    (canonicalAvailable ? routeHostname : "");
  const tcpAddr = row.tcp_addr?.trim() || "";
  const udpAddr = row.udp_addr?.trim() || "";

  return {
    id: routeHostname,
    name: row.name || routeHostname || "(unnamed)",
    description: metadata.description,
    tags: metadata.tags,
    thumbnail: resolveLeaseThumbnail(metadata),
    owner: metadata.owner,
    online:
      (row.ready || 0) > 0 &&
      Boolean(publicHostname || tcpAddr || udpAddr),
    dns: publicHostname,
    link: !tcpAddr && !udpAddr && publicHostname ? `https://${publicHostname}/` : "",
    address: row.address,
    serviceName: row.name || "",
    tcpAddr: tcpAddr || undefined,
    udpAddr: udpAddr || undefined,
    lastUpdated: row.last_seen_at || undefined,
    firstSeen: row.first_seen_at || undefined,
    paymentEnabled: payment.enabled,
    paymentLabel: payment.label,
  };
}
