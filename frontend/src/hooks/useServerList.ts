import { useEffect, useMemo, useState } from "react";
import { useList, type BaseServer } from "@/hooks/useList";
import { apiClient } from "@/lib/apiClient";
import { BROWSER_API_PATHS } from "@/lib/apiPaths";
import { parseLeaseMetadata, resolveLeaseThumbnail } from "@/lib/metadata";
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

    return {
      id: hostname,
      name: serviceName || hostname || "(unnamed)",
      description: metadata.description || "",
      tags: metadata.tags,
      thumbnail: resolveLeaseThumbnail(metadata, hostname),
      owner: metadata.owner || "",
      online: (row.ready || 0) > 0,
      dns: hostname,
      link: hostname ? `https://${hostname}/` : "",
      lastUpdated: row.last_seen_at || undefined,
      firstSeen: row.first_seen_at || undefined,
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

  const list = useList({
    servers,
    storageKey: "serverFavorites",
  });

  return {
    ...list,
    landingPageEnabled: publicState.landingPageEnabled,
  };
}
