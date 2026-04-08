import { useEffect, useMemo, useState } from "react";
import type { AdminLeaseData } from "@/hooks/useSSRData";
import { useList, type BaseServer } from "@/hooks/useList";
import type { BanFilter } from "@/components/ServerListView";
import {
  API_PATHS,
  adminIPBanPath,
  adminLeasePath,
} from "@/lib/apiPaths";
import { APIClientError, apiClient } from "@/lib/apiClient";
import { parseLeaseMetadata } from "@/lib/metadata";

export type ApprovalMode = "auto" | "manual";

type LeaseAction = "approve" | "deny" | "ban";

type ApprovalModeResponse = {
  approval_mode?: ApprovalMode;
};

type LandingPageSettingsResponse = {
  enabled?: boolean;
};

type AdminSnapshotResponse = {
  approval_mode?: ApprovalMode;
  landing_page_enabled?: boolean;
  leases?: AdminLeaseData[];
  udp?: { enabled: boolean; max_leases: number };
  tcp_port?: { enabled: boolean; max_leases: number };
};

type LeaseActionResult = ApprovalModeResponse;

export interface AdminServer extends BaseServer {
  identityKey: string;
  address: string;
  isBanned: boolean;
  bps: number;
  isApproved: boolean;
  isDenied: boolean;
  ip: string;
  displayIP: string;
  isIPBanned: boolean;
}

export interface UDPSettings {
  enabled: boolean;
  maxLeases: number;
}

export interface TCPPortSettings {
  enabled: boolean;
  maxLeases: number;
}

const ADMIN_ERROR_MESSAGE_BY_CODE: Record<string, string> = {
  invalid_mode: "Invalid approval mode. Choose auto or manual and retry.",
  invalid_address: "Selected address is invalid. Refresh and try again.",
  invalid_request: "Selected lease is invalid. Refresh and try again.",
  lease_rejected: "Request was rejected by policy. Review conflicts and retry.",
  ip_banned: "Request denied because the source IP is banned.",
  unauthorized: "Admin authorization failed. Sign in again and retry.",
  method_not_allowed: "This action is not supported by the current server version.",
};

function toAdminErrorMessage(error: unknown, fallback: string): string {
  if (error instanceof APIClientError) {
    const mappedMessage = ADMIN_ERROR_MESSAGE_BY_CODE[error.code];
    if (mappedMessage) {
      return mappedMessage;
    }

    if (error.status === 401 || error.status === 403) {
      return "Admin authorization failed. Sign in again and retry.";
    }
    if (error.status === 409) {
      return "Request was rejected by policy. Refresh and retry.";
    }

    const message = error.message.trim();
    return message || fallback;
  }

  if (error instanceof Error) {
    const message = error.message.trim();
    return message || fallback;
  }

  return fallback;
}

function resolveLeaseIdentity(
  rows: AdminLeaseData[],
  identityKey: string
): { name: string; address: string } {
  const match = rows.find((row) => row.identity_key.trim() === identityKey);
  if (!match) {
    throw new Error("Missing lease identity");
  }

  return {
    name: (match.name || "").trim(),
    address: match.address.trim(),
  };
}

function toAdminServer(
  row: AdminLeaseData,
  index: number
): AdminServer {
  const metadata = parseLeaseMetadata(row.Metadata);
  const hostname = row.Hostname || "";
  const serviceName = row.name || "";
  const address = row.address.trim();

  return {
    id: index + 1,
    name: serviceName || hostname || "(unnamed)",
    description: metadata.description,
    tags: metadata.tags,
    thumbnail: metadata.thumbnail,
    owner: metadata.owner,
    online: (row.Ready || 0) > 0,
    dns: hostname,
    link: hostname ? `https://${hostname}/` : "",
    lastUpdated: row.LastSeenAt || undefined,
    firstSeen: row.FirstSeenAt || undefined,
    identityKey: row.identity_key.trim(),
    address,
    isBanned: row.IsBanned,
    bps: row.BPS,
    isApproved: row.IsApproved,
    isDenied: row.IsDenied,
    ip: row.ClientIP,
    displayIP: row.ReportedIP || row.ClientIP,
    isIPBanned: row.IsIPBanned,
  };
}

function normalizeApprovalMode(value: string | undefined): ApprovalMode {
  return value === "manual" ? "manual" : "auto";
}

interface AdminSnapshot {
  serverData: AdminLeaseData[];
  approvalMode: ApprovalMode;
  landingPageEnabled: boolean;
  udpSettings: UDPSettings;
  tcpPortSettings: TCPPortSettings;
}

async function loadAdminSnapshot(): Promise<AdminSnapshot> {
  const snapshot = await apiClient.get<AdminSnapshotResponse>(API_PATHS.admin.snapshot);
  const normalizedLeases = Array.isArray(snapshot?.leases) ? snapshot.leases : [];

  return {
    serverData: normalizedLeases,
    approvalMode: normalizeApprovalMode(snapshot?.approval_mode),
    landingPageEnabled: snapshot?.landing_page_enabled ?? true,
    udpSettings: {
      enabled: snapshot?.udp?.enabled ?? false,
      maxLeases: snapshot?.udp?.max_leases ?? 0,
    },
    tcpPortSettings: {
      enabled: snapshot?.tcp_port?.enabled ?? false,
      maxLeases: snapshot?.tcp_port?.max_leases ?? 0,
    },
  };
}

export function useAdmin() {
  const [serverData, setServerData] = useState<AdminLeaseData[]>([]);
  const [approvalMode, setApprovalMode] = useState<ApprovalMode>("auto");
  const [landingPageEnabled, setLandingPageEnabled] = useState(true);
  const [udpSettings, setUDPSettings] = useState<UDPSettings>({ enabled: false, maxLeases: 0 });
  const [tcpPortSettings, setTCPPortSettings] = useState<TCPPortSettings>({ enabled: false, maxLeases: 0 });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const [banFilter, setBanFilter] = useState<BanFilter>("all");

  const applySnapshot = (snapshot: AdminSnapshot) => {
    setServerData(snapshot.serverData);
    setApprovalMode(snapshot.approvalMode);
    setLandingPageEnabled(snapshot.landingPageEnabled);
    setUDPSettings(snapshot.udpSettings);
    setTCPPortSettings(snapshot.tcpPortSettings);
  };

  const fetchData = async () => {
    setError("");

    try {
      applySnapshot(await loadAdminSnapshot());
    } catch (err: unknown) {
      setError(toAdminErrorMessage(err, "Failed to load admin data"));
    }
  };

  useEffect(() => {
    let mounted = true;
    const loadInitialData = async () => {
      setError("");
      setLoading(true);
      try {
        const snapshot = await loadAdminSnapshot();
        if (!mounted) {
          return;
        }
        applySnapshot(snapshot);
      } catch (err: unknown) {
        if (!mounted) {
          return;
        }
        setError(toAdminErrorMessage(err, "Failed to load admin data"));
      } finally {
        if (mounted) {
          setLoading(false);
        }
      }
    };

    void loadInitialData();
    return () => {
      mounted = false;
    };
  }, []);

  const servers: AdminServer[] = useMemo(() => {
    return serverData.map((row, index) => toAdminServer(row, index));
  }, [serverData]);

  const additionalFilter = (server: AdminServer) => {
    switch (banFilter) {
      case "banned":
        return server.isBanned;
      case "active":
        return !server.isBanned;
      default:
        return true;
    }
  };

  const listState = useList({
    servers,
    storageKey: "adminFavorites",
    additionalFilter,
  });

  const runAdminAction = async (action: () => Promise<void>) => {
    setError("");
    try {
      await action();
      await fetchData();
    } catch (err: unknown) {
      const message = toAdminErrorMessage(err, "Action failed");
      console.error(err);
      setError(message);
      throw err;
    }
  };

  const updateLeaseAction = async (
    identityKey: string,
    action: LeaseAction,
    enabled: boolean
  ) => {
    const identity = resolveLeaseIdentity(serverData, identityKey);
    const method = enabled ? apiClient.post : apiClient.delete;
    await method<LeaseActionResult>(
      adminLeasePath(identity.name, identity.address, action)
    );
  };

  const handleBanFilterChange = (value: BanFilter) => {
    setBanFilter(value);
  };

  const handleBanStatus = (identityKey: string, isBan: boolean) =>
    runAdminAction(() => updateLeaseAction(identityKey, "ban", isBan));

  const handleBPSChange = async (identityKey: string, bps: number) => {
    if (!identityKey) {
      throw new Error("Missing lease identity");
    }

    const identity = resolveLeaseIdentity(serverData, identityKey);
    const normalizedBPS = Math.max(0, Math.trunc(bps));
    const previousBPS =
      serverData.find((row) => row.identity_key.trim() === identityKey)?.BPS ?? 0;

    setServerData((prev) =>
      prev.map((row) =>
        row.identity_key.trim() === identityKey
          ? { ...row, BPS: normalizedBPS }
          : row
      )
    );

    try {
      await runAdminAction(async () => {
        if (!Number.isFinite(normalizedBPS) || normalizedBPS <= 0) {
          await apiClient.delete<LeaseActionResult>(
            adminLeasePath(identity.name, identity.address, "bps")
          );
          return;
        }
        await apiClient.post<LeaseActionResult>(
          adminLeasePath(identity.name, identity.address, "bps"),
          { bps: normalizedBPS }
        );
      });
    } catch (err) {
      setServerData((prev) =>
        prev.map((row) =>
          row.identity_key.trim() === identityKey
            ? { ...row, BPS: previousBPS }
            : row
        )
      );
      throw err;
    }
  };

  const handleApprovalModeChange = async (mode: ApprovalMode) => {
    await runAdminAction(async () => {
      const response = await apiClient.post<ApprovalModeResponse>(
        API_PATHS.admin.approvalMode,
        { mode }
      );
      const nextMode = normalizeApprovalMode(response?.approval_mode ?? mode);
      setApprovalMode(nextMode);
    });
  };

  const handleSettingsChange = (path: string, setter: (s: { enabled: boolean; maxLeases: number }) => void) =>
    async (settings: { enabled: boolean; maxLeases: number }) => {
      await runAdminAction(async () => {
        const response = await apiClient.post<{ enabled: boolean; max_leases: number }>(path, {
          enabled: settings.enabled,
          max_leases: settings.maxLeases,
        });
        setter({
          enabled: response?.enabled ?? settings.enabled,
          maxLeases: response?.max_leases ?? settings.maxLeases,
        });
      });
    };

  const handleUDPSettingsChange = handleSettingsChange(API_PATHS.admin.udpSettings, setUDPSettings);
  const handleTCPPortSettingsChange = handleSettingsChange(API_PATHS.admin.tcpPortSettings, setTCPPortSettings);

  const handleLandingPageEnabledChange = async (enabled: boolean) => {
    await runAdminAction(async () => {
      const response = await apiClient.post<LandingPageSettingsResponse>(
        API_PATHS.admin.landingPage,
        { enabled }
      );
      setLandingPageEnabled(response?.enabled ?? enabled);
    });
  };

  const handleApproveStatus = (identityKey: string, approve: boolean) =>
    runAdminAction(() => updateLeaseAction(identityKey, "approve", approve));

  const handleDenyStatus = (identityKey: string, deny: boolean) =>
    runAdminAction(() => updateLeaseAction(identityKey, "deny", deny));

  const handleIPBanStatus = (ip: string, isBan: boolean) =>
    runAdminAction(async () => {
      const normalizedIP = ip.trim();
      if (!normalizedIP) {
        throw new Error("Missing IP address");
      }
      if (isBan) {
        await apiClient.post<LeaseActionResult>(adminIPBanPath(normalizedIP));
        return;
      }
      await apiClient.delete<LeaseActionResult>(adminIPBanPath(normalizedIP));
    });

  const runBulkLeaseAction = async (identityKeys: string[], action: LeaseAction) => {
    const normalizedIdentityKeys = [...new Set(
      identityKeys.filter((identityKey) => identityKey.length > 0)
    )];
    if (normalizedIdentityKeys.length === 0) {
      throw new Error("No valid leases selected");
    }

    const results = await Promise.allSettled(
      normalizedIdentityKeys.map((identityKey) => {
        const identity = resolveLeaseIdentity(serverData, identityKey);
        return apiClient.post<LeaseActionResult>(
          adminLeasePath(identity.name, identity.address, action)
        );
      })
    );

    const failed = results.find(
      (
        result
      ): result is PromiseRejectedResult =>
        result.status === "rejected"
    );
    if (failed) {
      throw failed.reason instanceof Error
        ? failed.reason
        : new Error(String(failed.reason));
    }
  };

  const handleBulkAction = (identityKeys: string[], action: LeaseAction) =>
    runAdminAction(() => runBulkLeaseAction(identityKeys, action));

  const handleBulkApprove = (identityKeys: string[]) => handleBulkAction(identityKeys, "approve");

  const handleBulkDeny = (identityKeys: string[]) => handleBulkAction(identityKeys, "deny");

  const handleBulkBan = (identityKeys: string[]) => handleBulkAction(identityKeys, "ban");

  return {
    servers,
    ...listState,
    banFilter,
    approvalMode,
    landingPageEnabled,
    udpSettings,
    tcpPortSettings,
    loading,
    error,
    handleBanFilterChange,
    handleBanStatus,
    handleBPSChange,
    handleApprovalModeChange,
    handleLandingPageEnabledChange,
    handleUDPSettingsChange,
    handleTCPPortSettingsChange,
    handleApproveStatus,
    handleDenyStatus,
    handleIPBanStatus,
    handleBulkApprove,
    handleBulkDeny,
    handleBulkBan,
  };
}
