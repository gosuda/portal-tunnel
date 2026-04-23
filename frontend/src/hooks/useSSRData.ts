import { useState, useEffect } from "react";

export interface Metadata {
  description: string;
  tags: string[];
  thumbnail: string;
  owner: string;
  hide: boolean;
}

export interface PublicLeaseData {
  ExpiresAt: string;
  FirstSeenAt: string;
  LastSeenAt: string;
  name?: string;
  Hostname: string;
  Metadata: unknown;
  Ready: number;
}

export interface AdminLeaseData extends PublicLeaseData {
  identity_key: string;
  address: string;
  BPS: number;
  ClientIP: string;
  ReportedIP: string;
  ReportedIPv4?: string;
  ReportedIPv6?: string;
  IsApproved: boolean;
  IsBanned: boolean;
  IsDenied: boolean;
  IsIPBanned: boolean;
}

/**
 * useSSRData hook reads server data injected by Go SSR
 * The data is embedded in a <script id="__SSR_DATA__"> tag in the HTML
 */
export function useSSRData(): PublicLeaseData[] {
  const [data, setData] = useState<PublicLeaseData[]>([]);

  useEffect(() => {
    const ssrScript = document.getElementById("__SSR_DATA__");
    if (!ssrScript?.textContent) {
      return;
    }

    try {
      const parsed = JSON.parse(ssrScript.textContent);
      setData(Array.isArray(parsed) ? parsed : []);
    } catch (error) {
      console.error("Failed to parse SSR data", error);
      setData([]);
    }
  }, []);

  return data;
}
