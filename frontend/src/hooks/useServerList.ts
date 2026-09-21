import { useEffect, useMemo, useState } from "react";
import { useList, type BaseServer } from "@/hooks/useList";
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
  ReputationVoteResponse,
} from "@/types/api";

function normalizeHostname(hostname: string): string {
  return hostname.trim().toLowerCase();
}

type PublicState = {
  leases: Lease[];
  landingPageEnabled: boolean;
};

function collectReputation(
  rows: ReputationSummary[] | undefined
): Record<string, ReputationSummary> {
  const summaries: Record<string, ReputationSummary> = {};
  for (const summary of Array.isArray(rows) ? rows : []) {
    if (
      summary?.hostname &&
      typeof summary.up === "number" &&
      typeof summary.down === "number" &&
      typeof summary.total === "number"
    ) {
      summaries[normalizeHostname(summary.hostname)] = summary;
    }
  }
  return summaries;
}

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
  const [summaries, setSummaries] = useState<Record<string, ReputationSummary>>({});

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
        setSummaries(collectReputation(data?.reputation));
        setPublicState({
          leases: Array.isArray(data?.leases) ? data.leases : [],
          landingPageEnabled: data?.landing_page_enabled ?? false,
        });
      } catch (error) {
        console.error("Failed to load public relay state", error);
        if (!cancelled) {
          setPublicState({ leases: [], landingPageEnabled: false });
          setSummaries({});
        }
      }
    })();

    return () => {
      cancelled = true;
    };
  }, []);

  const vote = async (hostname: string, vote: ReputationVote): Promise<void> => {
    const key = normalizeHostname(hostname);
    if (key === "") {
      return;
    }
    try {
      const response = await apiClient.post<ReputationVoteResponse>(
        BROWSER_API_PATHS.public.reputationVote,
        { hostname: key, vote }
      );
      if (
        typeof response?.up === "number" &&
        typeof response?.down === "number" &&
        typeof response?.total === "number"
      ) {
        setSummaries((current) => ({
          ...current,
          [key]: {
            hostname: response.hostname || key,
            up: response.up,
            down: response.down,
            total: response.total,
            viewer_vote: response.viewer_vote ?? "",
          },
        }));
      }
    } catch (error) {
      console.error("Failed to submit vote", error);
      throw error;
    }
  };

  // Join the relay's vote aggregate onto each card by hostname.
  // Deps are plain state (array + record), so the compiler can preserve
  // this memo — a function identity dep would bail compilation out.
  const servers: BaseServer[] = useMemo(
    () =>
      convertPublicLeasesToServers(publicState.leases).map((server) => ({
        ...server,
        reputation: summaries[normalizeHostname(server.dns)] ?? {
          hostname: normalizeHostname(server.dns),
          up: 0,
          down: 0,
          total: 0,
          viewer_vote: "" as const,
        },
      })),
    [publicState.leases, summaries]
  );

  const list = useList({
    servers,
    storageKey: "serverFavorites",
  });

  return {
    ...list,
    landingPageEnabled: publicState.landingPageEnabled,
    onVote: vote,
  };
}
