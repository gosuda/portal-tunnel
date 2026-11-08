import {
  parseLeaseMetadata,
  resolveLeasePayment,
  resolveLeaseThumbnail,
} from "@/lib/metadata";
import type { Lease, ReputationSummary } from "@/types/api";

/** One app in the directory, built from a relay lease. */
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
  tcpAddr?: string;
  udpAddr?: string;
  lastUpdated?: string;
  firstSeen?: string;
  paymentEnabled?: boolean;
  paymentLabel?: string;
  reputation?: ReputationSummary;
}

/**
 * The directory entry for a lease. The id is the canonical hostname, so it
 * stays stable when the short name changes. A raw TCP or UDP app has no web
 * page, so it gets no link.
 */
export function leaseToServer(row: Lease): BaseServer {
  const metadata = parseLeaseMetadata(row.metadata);
  const payment = resolveLeasePayment(metadata);
  const hostname = row.hostname || "";
  const routeHostname = row.canonical_hostname || hostname;
  const publicHostname = hostname || routeHostname;
  const tcpAddr = row.tcp_addr?.trim() || "";
  const udpAddr = row.udp_addr?.trim() || "";

  return {
    id: routeHostname,
    name: row.name || routeHostname || "(unnamed)",
    description: metadata.description,
    tags: metadata.tags,
    thumbnail: resolveLeaseThumbnail(metadata),
    owner: metadata.owner,
    online: (row.ready || 0) > 0,
    dns: publicHostname,
    link: !tcpAddr && !udpAddr && publicHostname ? `https://${publicHostname}/` : "",
    address: row.address,
    tcpAddr: tcpAddr || undefined,
    udpAddr: udpAddr || undefined,
    lastUpdated: row.last_seen_at || undefined,
    firstSeen: row.first_seen_at || undefined,
    paymentEnabled: payment.enabled,
    paymentLabel: payment.label,
  };
}
