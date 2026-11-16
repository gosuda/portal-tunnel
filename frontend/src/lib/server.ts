import {
  parseLeaseMetadata,
  resolveLeasePayment,
  resolveLeaseThumbnail,
} from "@/lib/metadata";
import type { DiscoveredService, Lease, ReputationSummary, ServiceLocation } from "@/types/api";

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
}

// Identity results share one card per service. A local card retains its URL;
// remote-only cards require an explicit location choice.
export function mergeDiscoveredServices(local: BaseServer[], services: DiscoveredService[], address: string): BaseServer[] {
  const selected = local.filter((server) => server.address?.toLowerCase() === address.toLowerCase());
  const byName = new Map(selected.map((server) => [server.serviceName ?? "", server]));
  for (const service of services) {
    if (service.address.toLowerCase() !== address.toLowerCase()) continue;
    const existing = byName.get(service.name);
    if (existing) {
      byName.set(service.name, { ...existing, locations: service.locations });
    } else {
      const metadata = parseLeaseMetadata(service.metadata);
      byName.set(service.name, {
        id: `service:${service.name}:${service.address.toLowerCase()}`,
        serviceName: service.name,
        name: service.name || "(unnamed)",
        address: service.address,
        description: metadata.description,
        tags: metadata.tags,
        owner: metadata.owner,
        thumbnail: "",
        online: service.locations.some((location) => location.reported_ready),
        dns: "",
        link: "",
        remoteOnly: true,
        locations: service.locations,
      });
    }
  }
  return [...byName.values()];
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
