import { useEffect, useEffectEvent, useMemo, useRef, useState } from "react";
import { useList } from "@/hooks/useList";
import { leaseToServer, type BaseServer } from "@/lib/server";
import type { BanFilter } from "@/types/filters";
import { RELAY_API_PATHS } from "@/lib/apiPaths";
import { APIClientError, apiClient } from "@/lib/apiClient";
import type {
  ApprovalMode,
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
}

export interface PortSettings {
  enabled: boolean;
  maxLeases: number;
}

function toPortSettings(settings: PolicyPortSettings): PortSettings {
  return { enabled: settings.enabled, maxLeases: settings.max_leases };
}

const DEFAULT_POLICY_SETTINGS: PolicySettings = {
  approval_mode: "auto",
  udp: { enabled: false, max_leases: 0 },
  tcp_port: { enabled: false, max_leases: 0 },
};

const ADMIN_ERROR_MESSAGE_BY_CODE: Record<string, string> = {
  invalid_mode: "Invalid approval mode. Choose auto or manual and retry.",
  invalid_address: "Selected address is invalid. Refresh and try again.",
  invalid_request: "Selected lease is invalid. Refresh and try again.",
  lease_rejected: "Request was rejected by policy. Review conflicts and retry.",
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

function toAdminServer(row: PolicyLease): AdminServer {
  return {
    ...leaseToServer(row),
    identityKey: row.identity_key.trim(),
    address: row.address.trim(),
    isBanned: row.is_banned,
    bps: row.bps,
    isApproved: row.is_approved,
    isDenied: row.is_denied,
    ip: row.client_ip,
    displayIP: row.reported_ip || row.client_ip,
  };
}

function normalizeApprovalMode(value: string | undefined): ApprovalMode {
  return value === "manual" ? "manual" : "auto";
}

function normalizePolicySettings(settings: PolicySettings | undefined): PolicySettings {
  return {
    approval_mode: normalizeApprovalMode(settings?.approval_mode),
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
  const state = await apiClient.get<PolicyStateResponse>(RELAY_API_PATHS.policy.state);
  const normalizedLeases = Array.isArray(state?.leases) ? state.leases : [];

  return {
    serverData: normalizedLeases,
    settings: normalizePolicySettings(state?.policy),
  };
}

export function useAdmin(enabled = true) {
  const [serverData, setServerData] = useState<PolicyLease[]>([]);
  const [policySettings, setPolicySettings] = useState<PolicySettings>(DEFAULT_POLICY_SETTINGS);
  const policyUpdatePending = useRef(false);
  const [policySaving, setPolicySaving] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const [banFilter, setBanFilter] = useState<BanFilter>("all");

  const applyPolicyState = (state: PolicyViewState) => {
    setServerData(state.serverData);
    setPolicySettings(state.settings);
  };

  const loadGeneration = useRef(0);

  const reload = async (showLoading: boolean) => {
    const generation = ++loadGeneration.current;
    setError("");
    if (showLoading) {
      setLoading(true);
    }
    try {
      const state = await loadPolicyState();
      if (generation === loadGeneration.current) {
        applyPolicyState(state);
      }
    } catch (err: unknown) {
      if (generation === loadGeneration.current) {
        setError(toAdminErrorMessage(err, "Failed to load admin data"));
      }
    } finally {
      if (generation === loadGeneration.current) {
        setLoading(false);
      }
    }
  };

  const loadOnEnable = useEffectEvent(() => {
    if (enabled) {
      void reload(true);
    } else {
      setError("");
      setLoading(false);
    }
  });

  useEffect(() => {
    loadOnEnable();
    return () => {
      loadGeneration.current += 1;
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
    additionalFilter,
  });

  const runAdminAction = async (action: () => Promise<void>) => {
    setError("");
    try {
      await action();
      await reload(false);
    } catch (err: unknown) {
      const message = toAdminErrorMessage(err, "Action failed");
      console.error(err);
      setError(message);
      throw err;
    }
  };

  const updatePolicySettings = async (overrides: Partial<PolicySettings>) => {
    if (policyUpdatePending.current) return;
    policyUpdatePending.current = true;
    setPolicySaving(true);
    try {
      await runAdminAction(async () => {
        const response = await apiClient.post<PolicySettings>(RELAY_API_PATHS.policy.root, {
          ...policySettings,
          ...overrides,
        });
        setPolicySettings(normalizePolicySettings(response));
      });
    } finally {
      policyUpdatePending.current = false;
      setPolicySaving(false);
    }
  };

  const updateLeasePolicy = async (
    identityKey: string,
    policy: Omit<LeasePolicyUpdate, "identity_key">,
  ) => {
    if (!identityKey) {
      throw new Error("Missing lease identity");
    }
    await apiClient.post<unknown>(RELAY_API_PATHS.policy.leases, {
      identity_key: identityKey,
      ...policy,
    } satisfies LeasePolicyUpdate);
  };

  const handleBanFilterChange = (value: BanFilter) => {
    setBanFilter(value);
  };

  const handleBanStatus = (identityKey: string, isBan: boolean) =>
    runAdminAction(() => updateLeasePolicy(identityKey, { is_banned: isBan }));

  const handleBPSChange = async (identityKey: string, bps: number | null) => {
    if (!identityKey) {
      throw new Error("Missing lease identity");
    }

    if (bps === null) {
      await runAdminAction(() => updateLeasePolicy(identityKey, { reset_bps: true }));
      return;
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

  const handleApprovalModeChange = (mode: ApprovalMode) =>
    updatePolicySettings({ approval_mode: mode });

  const handleSettingsChange = (key: "udp" | "tcp_port") =>
    (settings: PortSettings) =>
      updatePolicySettings({
        [key]: { enabled: settings.enabled, max_leases: settings.maxLeases },
      });

  const handleUDPSettingsChange = handleSettingsChange("udp");
  const handleTCPPortSettingsChange = handleSettingsChange("tcp_port");

  const handleApproveStatus = (identityKey: string, approve: boolean) =>
    runAdminAction(() => updateLeasePolicy(identityKey, { is_approved: approve }));

  const handleDenyStatus = (identityKey: string, deny: boolean) =>
    runAdminAction(() => updateLeasePolicy(identityKey, { is_denied: deny }));

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
        return apiClient.post<unknown>(RELAY_API_PATHS.policy.leases, policy);
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
  const udpSettings = toPortSettings(policySettings.udp);
  const tcpPortSettings = toPortSettings(policySettings.tcp_port);

  return {
    servers,
    ...listState,
    banFilter,
    approvalMode,
    udpSettings,
    tcpPortSettings,
    policySaving,
    loading,
    error,
    handleBanFilterChange,
    handleBanStatus,
    handleBPSChange,
    handleApprovalModeChange,
    handleUDPSettingsChange,
    handleTCPPortSettingsChange,
    handleApproveStatus,
    handleDenyStatus,
    handleBulkApprove,
    handleBulkDeny,
    handleBulkBan,
  };
}
