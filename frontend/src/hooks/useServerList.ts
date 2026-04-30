import { useMemo } from "react";
import { useSSRData } from "@/hooks/useSSRData";
import type { PublicLeaseData } from "@/hooks/useSSRData";
import { useList, type BaseServer } from "@/hooks/useList";
import { parseLeaseMetadata } from "@/lib/metadata";

function convertSSRDataToServers(ssrData: PublicLeaseData[]): BaseServer[] {
  return ssrData.map((row) => {
    const metadata = parseLeaseMetadata(row.Metadata);
    const hostname = row.Hostname || "";
    const serviceName = row.name || "";

    return {
      id: hostname,
      name: serviceName || hostname || "(unnamed)",
      description: metadata.description || "",
      tags: metadata.tags,
      thumbnail: metadata.thumbnail || "",
      owner: metadata.owner || "",
      online: (row.Ready || 0) > 0,
      dns: hostname,
      link: hostname ? `https://${hostname}/` : "",
      lastUpdated: row.LastSeenAt || undefined,
      firstSeen: row.FirstSeenAt || undefined,
    };
  });
}

export function useServerList() {
  const ssrData = useSSRData();

  const servers: BaseServer[] = useMemo(
    () => convertSSRDataToServers(ssrData),
    [ssrData]
  );

  return useList({
    servers,
    storageKey: "serverFavorites",
  });
}
