import { useEffect, useMemo, useState } from "react";
import { useList, type BaseServer } from "@/hooks/useList";
import { apiClient } from "@/lib/apiClient";
import { RELAY_API_PATHS } from "@/lib/apiPaths";
import {
  parseLeaseMetadata,
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
      paymentEnabled: metadata.paymentEnabled,
      paymentLabel: metadata.paymentLabel,
    };
  });
}

export function useServerList() {
  const [publicState, setPublicState] = useState<PublicState>({
    leases: [],
    landingPageEnabled: false,
  });

  useEffect(() => {
    let cancelled = false;
    let timer: number | undefined;

    // Serialize polls: the next request is scheduled only after the previous
    // one settles, so a slow response can never arrive after a newer one and
    // overwrite fresh state, and requests cannot accumulate under latency.
    const poll = async () => {
      try {
        const data = await apiClient.get<PublicStateResponse>(
          RELAY_API_PATHS.public.state
        );
        if (!cancelled) {
          setPublicState({
            leases: Array.isArray(data?.leases) ? data.leases : [],
            landingPageEnabled: data?.landing_page_enabled ?? false,
          });
        }
      } catch (error) {
        console.error("Failed to load public relay state", error);
      } finally {
        if (!cancelled) {
          timer = window.setTimeout(() => {
            void poll();
          }, 1500);
        }
      }
    };

    void poll();

    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, []);

  const servers: BaseServer[] = useMemo(
    () => convertPublicLeasesToServers(publicState.leases),
    [publicState.leases]
  );

  const list = useList({
    servers,
    storageKey: "serverFavorites",
  });

  return {
    ...list,
    leases: publicState.leases,
    landingPageEnabled: publicState.landingPageEnabled,
  };
}
