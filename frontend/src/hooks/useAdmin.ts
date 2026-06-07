import { useEffect, useMemo, useState } from "react";
import { useList, type BaseServer } from "@/hooks/useList";
import type { BanFilter } from "@/types/filters";
import { BROWSER_API_PATHS } from "@/lib/apiPaths";
import { APIClientError, apiClient } from "@/lib/apiClient";
import { parseLeaseMetadata, resolveLeaseThumbnail } from "@/lib/metadata";
import type {
  ApprovalMode,
  IPPolicyUpdate,
  LeasePolicyUpdate,
  PolicyLease,
  PolicyPortSettings,
  PolicySettings,
  PolicyStateResponse,
} from "@/types/api";

export type { ApprovalMode } from "@/types/api";

type LeaseAction = "approve" | "deny" | "ban";

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

const DEFAULT_POLICY_SETTINGS: PolicySettings = {
  approval_mode: "auto",
  landing_page_enabled: false,
  udp: { enabled: false, max_leases: 0 },
  tcp_port: { enabled: false, max_leases: 0 },
};

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

function toAdminServer(
  row: PolicyLease,
): AdminServer {
  const metadata = parseLeaseMetadata(row.metadata);
  const hostname = row.hostname || "";
  const serviceName = row.name || "";
  const address = row.address.trim();

  return {
    id: hostname,
    name: serviceName || hostname || "(unnamed)",
    description: metadata.description,
    tags: metadata.tags,
    thumbnail: resolveLeaseThumbnail(metadata, hostname),
    owner: metadata.owner,
    online: (row.ready || 0) > 0,
    dns: hostname,
    link: hostname ? `https://${hostname}/` : "",
    lastUpdated: row.last_seen_at || undefined,
    firstSeen: row.first_seen_at || undefined,
    identityKey: row.identity_key.trim(),
    address,
    isBanned: row.is_banned,
    bps: row.bps,
    isApproved: row.is_approved,
    isDenied: row.is_denied,
    ip: row.client_ip,
    displayIP: row.reported_ip || row.client_ip,
    isIPBanned: row.is_ip_banned,
  };
}

function normalizeApprovalMode(value: string | undefined): ApprovalMode {
  return value === "manual" ? "manual" : "auto";
}

function normalizePolicySettings(settings: PolicySettings | undefined): PolicySettings {
  return {
    approval_mode: normalizeApprovalMode(settings?.approval_mode),
    landing_page_enabled:
      settings?.landing_page_enabled ?? DEFAULT_POLICY_SETTINGS.landing_page_enabled,
    udp: {
      enabled: settings?.udp?.enabled ?? DEFAULT_POLICY_SETTINGS.udp.enabled,
      max_leases: settings?.udp?.max_leases ?? DEFAULT_POLICY_SETTINGS.udp.max_leases,
    },
    tcp_port: {
      enabled: settings?.tcp_port?.enabled ?? DEFAULT_POLICY_SETTINGS.tcp_port.enabled,
      max_leases: settings?.tcp_port?.max_leases ?? DEFAULT_POLICY_SETTINGS.tcp_port.max_leases,
    },
  };
}

interface PolicyViewState {
  serverData: PolicyLease[];
  settings: PolicySettings;
}

async function loadPolicyState(): Promise<PolicyViewState> {
  const state = await apiClient.get<PolicyStateResponse>(BROWSER_API_PATHS.policy.state);
  const normalizedLeases = Array.isArray(state?.leases) ? state.leases : [];

  return {
    serverData: normalizedLeases,
    settings: normalizePolicySettings(state?.policy),
  };
}

export function useAdmin(enabled = true) {
  const [serverData, setServerData] = useState<PolicyLease[]>([]);
  const [policySettings, setPolicySettings] = useState<PolicySettings>(DEFAULT_POLICY_SETTINGS);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const [banFilter, setBanFilter] = useState<BanFilter>("all");

  const applyPolicyState = (state: PolicyViewState) => {
    setServerData(state.serverData);
    setPolicySettings(state.settings);
  };

  const fetchData = async () => {
    setError("");

    try {
      applyPolicyState(await loadPolicyState());
    } catch (err: unknown) {
      setError(toAdminErrorMessage(err, "Failed to load admin data"));
    }
  };

  useEffect(() => {
    let mounted = true;
    if (!enabled) {
      setError("");
      setLoading(false);
      return () => {
        mounted = false;
      };
    }

    const loadInitialData = async () => {
      setError("");
      setLoading(true);
      try {
        const state = await loadPolicyState();
        if (!mounted) {
          return;
        }
        applyPolicyState(state);
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
  }, [enabled]);

  const servers: AdminServer[] = useMemo(() => {
    return serverData.map((row) => toAdminServer(row));
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

  const postPolicySettings = async (settings: PolicySettings) => {
    const response = await apiClient.post<PolicySettings>(BROWSER_API_PATHS.policy.root, settings);
    setPolicySettings(normalizePolicySettings(response));
  };

  const currentPolicySettings = (overrides: Partial<PolicySettings> = {}): PolicySettings => ({
    ...policySettings,
    ...overrides,
  });

  const updateLeasePolicy = async (
    identityKey: string,
    policy: Omit<LeasePolicyUpdate, "identity_key">,
  ) => {
    if (!identityKey) {
      throw new Error("Missing lease identity");
    }
    await apiClient.post<unknown>(BROWSER_API_PATHS.policy.leases, {
      identity_key: identityKey,
      ...policy,
    } satisfies LeasePolicyUpdate);
  };

  const handleBanFilterChange = (value: BanFilter) => {
    setBanFilter(value);
  };

  const handleBanStatus = (identityKey: string, isBan: boolean) =>
    runAdminAction(() => updateLeasePolicy(identityKey, { is_banned: isBan }));

  const handleBPSChange = async (identityKey: string, bps: number) => {
    if (!identityKey) {
      throw new Error("Missing lease identity");
    }

    const normalizedBPS = Math.max(0, Math.trunc(bps));
    const previousBPS =
      serverData.find((row) => row.identity_key.trim() === identityKey)?.bps ?? 0;

    setServerData((prev) =>
      prev.map((row) =>
        row.identity_key.trim() === identityKey
          ? { ...row, bps: normalizedBPS }
          : row
      )
    );

    try {
      await runAdminAction(async () => {
        if (!Number.isFinite(normalizedBPS) || normalizedBPS <= 0) {
          await updateLeasePolicy(identityKey, { bps: 0 });
          return;
        }
        await updateLeasePolicy(identityKey, { bps: normalizedBPS });
      });
    } catch (err) {
      setServerData((prev) =>
        prev.map((row) =>
          row.identity_key.trim() === identityKey
            ? { ...row, bps: previousBPS }
            : row
        )
      );
      throw err;
    }
  };

  const handleApprovalModeChange = async (mode: ApprovalMode) => {
    await runAdminAction(async () => {
      await postPolicySettings(currentPolicySettings({ approval_mode: mode }));
    });
  };

  const handleSettingsChange = (key: "udp" | "tcp_port") =>
    async (settings: { enabled: boolean; maxLeases: number }) => {
      await runAdminAction(async () => {
        const nextPortSettings: PolicyPortSettings = {
          enabled: settings.enabled,
          max_leases: settings.maxLeases,
        };
        const nextSettings =
          key === "udp"
            ? currentPolicySettings({ udp: nextPortSettings })
            : currentPolicySettings({ tcp_port: nextPortSettings });
        await postPolicySettings(nextSettings);
      });
    };

  const handleUDPSettingsChange = handleSettingsChange("udp");
  const handleTCPPortSettingsChange = handleSettingsChange("tcp_port");

  const handleLandingPageEnabledChange = async (enabled: boolean) => {
    await runAdminAction(async () => {
      await postPolicySettings(currentPolicySettings({ landing_page_enabled: enabled }));
    });
  };

  const handleApproveStatus = (identityKey: string, approve: boolean) =>
    runAdminAction(() => updateLeasePolicy(identityKey, { is_approved: approve }));

  const handleDenyStatus = (identityKey: string, deny: boolean) =>
    runAdminAction(() => updateLeasePolicy(identityKey, { is_denied: deny }));

  const handleIPBanStatus = (ip: string, isBan: boolean) =>
    runAdminAction(async () => {
      const normalizedIP = ip.trim();
      if (!normalizedIP) {
        throw new Error("Missing IP address");
      }
      await apiClient.post<unknown>(BROWSER_API_PATHS.policy.ips, {
        ip: normalizedIP,
        is_banned: isBan,
      } satisfies IPPolicyUpdate);
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
        const policy: LeasePolicyUpdate =
          action === "approve"
            ? { identity_key: identityKey, is_approved: true }
            : action === "deny"
              ? { identity_key: identityKey, is_denied: true }
              : { identity_key: identityKey, is_banned: true };
        return apiClient.post<unknown>(BROWSER_API_PATHS.policy.leases, policy);
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

  const approvalMode = normalizeApprovalMode(policySettings.approval_mode);
  const landingPageEnabled = policySettings.landing_page_enabled;
  const udpSettings: UDPSettings = {
    enabled: policySettings.udp.enabled,
    maxLeases: policySettings.udp.max_leases,
  };
  const tcpPortSettings: TCPPortSettings = {
    enabled: policySettings.tcp_port.enabled,
    maxLeases: policySettings.tcp_port.max_leases,
  };

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
