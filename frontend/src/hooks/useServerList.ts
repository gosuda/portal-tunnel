import { useMemo } from "react";
import { useSSRData } from "@/hooks/useSSRData";
import type { PublicLeaseData } from "@/hooks/useSSRData";
import { useList, type BaseServer } from "@/hooks/useList";
import { parseLeaseMetadata } from "@/lib/metadata";

export type ClientServer = BaseServer;

function convertSSRDataToServers(ssrData: PublicLeaseData[]): ClientServer[] {
  return ssrData.map((row, index) => {
    const metadata = parseLeaseMetadata(row.Metadata);
    const hostname = row.Hostname || "";
    const serviceName = row.name || "";

    return {
      id: index + 1,
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

  const servers: ClientServer[] = useMemo(
    () => convertSSRDataToServers(ssrData),
    [ssrData]
  );

  return useList({
    servers,
    storageKey: "serverFavorites",
  });
}
