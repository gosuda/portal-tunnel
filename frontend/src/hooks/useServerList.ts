import { useEffect, useMemo, useState } from "react";
import { useList, type BaseServer } from "@/hooks/useList";
import { normalizeHostname, useReputation } from "@/hooks/useReputation";
import { apiClient } from "@/lib/apiClient";
import { BROWSER_API_PATHS } from "@/lib/apiPaths";
import {
  parseLeaseMetadata,
  resolveLeasePayment,
  resolveLeaseThumbnail,
} from "@/lib/metadata";
import type { Lease, PublicStateResponse } from "@/types/api";

type PublicState = {
  leases: Lease[];
  landingPageEnabled: boolean;
};

function convertPublicLeasesToServers(leases: Lease[]): BaseServer[] {
  return leases.map((row) => {
    const metadata = parseLeaseMetadata(row.metadata);
    const payment = resolveLeasePayment(metadata);
    const hostname = row.hostname || "";
    const serviceName = row.name || "";
    const tcpAddr = row.tcp_addr?.trim() || "";
    const udpAddr = row.udp_addr?.trim() || "";

    return {
      id: hostname,
      name: serviceName || hostname || "(unnamed)",
      description: metadata.description || "",
      tags: metadata.tags,
      thumbnail: resolveLeaseThumbnail(metadata),
      owner: metadata.owner || "",
      online: (row.ready || 0) > 0,
      dns: hostname,
      link: !tcpAddr && !udpAddr && hostname ? `https://${hostname}/` : "",
      tcpAddr: tcpAddr || undefined,
      udpAddr: udpAddr || undefined,
      lastUpdated: row.last_seen_at || undefined,
      firstSeen: row.first_seen_at || undefined,
      paymentEnabled: payment.enabled,
      paymentLabel: payment.label,
    };
  });
}

export function useServerList() {
  const [publicState, setPublicState] = useState<PublicState>({
    leases: [],
    landingPageEnabled: false,
  });
  const reputation = useReputation();

  useEffect(() => {
    let cancelled = false;

    void (async () => {
      try {
        const data = await apiClient.get<PublicStateResponse>(
          BROWSER_API_PATHS.public.state
        );
        if (cancelled) {
          return;
        }
        setPublicState({
          leases: Array.isArray(data?.leases) ? data.leases : [],
          landingPageEnabled: data?.landing_page_enabled ?? false,
        });
      } catch (error) {
        console.error("Failed to load public relay state", error);
        if (!cancelled) {
          setPublicState({ leases: [], landingPageEnabled: false });
        }
      }
    })();

    return () => {
      cancelled = true;
    };
  }, []);

  // Join the relay's vote aggregate onto each card by hostname.
  // Deps are plain state (array + record), so the compiler can preserve
  // this memo — a function identity dep would bail compilation out.
  const servers: BaseServer[] = useMemo(
    () =>
      convertPublicLeasesToServers(publicState.leases).map((server) => ({
        ...server,
        reputation: reputation.summaries[normalizeHostname(server.dns)] ?? {
          hostname: normalizeHostname(server.dns),
          up: 0,
          down: 0,
          total: 0,
          viewer_vote: "" as const,
        },
      })),
    [publicState.leases, reputation.summaries]
  );

  const list = useList({
    servers,
    storageKey: "serverFavorites",
  });

  return {
    ...list,
    landingPageEnabled: publicState.landingPageEnabled,
    onVote: reputation.vote,
    isVotePending: reputation.isVotePending,
  };
}
