import { useEffect, useMemo, useState } from "react";
import { useList } from "@/hooks/useList";
import type { BaseServer } from "@/types/server";
import { apiClient } from "@/lib/apiClient";
import { BROWSER_API_PATHS } from "@/lib/apiPaths";
import {
  parseLeaseMetadata,
  resolveLeasePayment,
  resolveLeaseThumbnail,
} from "@/lib/metadata";
import type {
  Lease,
  PublicStateResponse,
  ReputationSummary,
  ReputationVote,
} from "@/types/api";

// Tracks in-flight vote request sequences per hostname to discard stale responses.
// When a second vote fires before the first resolves, only the latest fires.
const voteRequestSeq = new Map<string, number>();

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
      reputation: row.reputation,
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

  const servers: BaseServer[] = useMemo(
    () => convertPublicLeasesToServers(publicState.leases),
    [publicState.leases]
  );

  async function handleVote(hostname: string, vote: ReputationVote) {
    try {
      const seq = (voteRequestSeq.get(hostname) ?? 0) + 1;
      voteRequestSeq.set(hostname, seq);

      const summary: ReputationSummary = await apiClient.postReputationVote(
        hostname,
        vote
      );

      // Discard if a newer vote for this hostname has already fired.
      const currentSeq = voteRequestSeq.get(hostname) ?? 0;
      if (currentSeq !== seq) {
        return;
      }

      setPublicState((prev) => ({
        ...prev,
        leases: prev.leases.map((lease) =>
          lease.hostname === hostname
            ? { ...lease, reputation: summary }
            : lease
        ),
      }));
    } catch (error) {
      console.error("Failed to submit reputation vote", error);
    }
  }

  const list = useList({
    servers,
    storageKey: "serverFavorites",
  });

  return {
    ...list,
    landingPageEnabled: publicState.landingPageEnabled,
    onVote: handleVote,
  };
}
