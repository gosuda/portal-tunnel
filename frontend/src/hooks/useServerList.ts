import { useEffect, useMemo, useState } from "react";
import type { BrowseView } from "@/types/filters";
import { useList } from "@/hooks/useList";
import { leaseToServer, type BaseServer } from "@/lib/server";
import { apiClient } from "@/lib/apiClient";
import { isHiddenByVotes } from "@/utils/reputation";
import { RELAY_API_PATHS } from "@/lib/apiPaths";
import type {
  Lease,
  PublicStateResponse,
  ReputationSummary,
  ReputationVoteAction,
  ReputationVoteResponse,
} from "@/types/api";

function normalizeHostname(hostname: string): string {
  return hostname.trim().toLowerCase();
}

type PublicState = {
  leases: Lease[];
  stale: boolean;
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

export function useServerList() {
  const [commentServer, setCommentServer] = useState<BaseServer | null>(null);
  const [browseView, setBrowseView] = useState<BrowseView>("home");
  const [showHidden, setShowHidden] = useState(false);
  const [sidebarOpen, setSidebarOpen] = useState(() =>
    typeof window !== "undefined" && typeof window.matchMedia === "function"
      ? window.matchMedia("(min-width: 1024px)").matches
      : false
  );
  const [publicState, setPublicState] = useState<PublicState>({
    leases: [],
    stale: true,
  });
  const [summaries, setSummaries] = useState<Record<string, ReputationSummary>>({});

  useEffect(() => {
    if (typeof window === "undefined" || typeof window.matchMedia !== "function") {
      return;
    }
    const desktop = window.matchMedia("(min-width: 1024px)");
    const handleBreakpointChange = (event: MediaQueryListEvent) => {
      setSidebarOpen(event.matches);
    };
    setSidebarOpen(desktop.matches);
    desktop.addEventListener("change", handleBreakpointChange);
    return () => desktop.removeEventListener("change", handleBreakpointChange);
  }, []);

  useEffect(() => {
    let cancelled = false;

    let timer: number | undefined;

    const refresh = async () => {
      try {
        const data = await apiClient.get<PublicStateResponse>(
          RELAY_API_PATHS.public.state
        );
        if (cancelled) {
          return;
        }
        setSummaries(collectReputation(data?.reputation));
        setPublicState({
          leases: Array.isArray(data?.leases) ? data.leases : [],
          stale: false,
        });
      } catch (error) {
        console.error("Failed to load public relay state", error);
        if (!cancelled) {
          setPublicState((previous) => ({ ...previous, stale: true }));
        }
      } finally {
        if (!cancelled) {
          timer = window.setTimeout(() => void refresh(), 1500);
        }
      }
    };

    void refresh();

    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, []);

  const vote = async (hostname: string, vote: ReputationVoteAction): Promise<void> => {
    const key = normalizeHostname(hostname);
    if (key === "") {
      return;
    }
    try {
      const response = await apiClient.post<ReputationVoteResponse>(
        RELAY_API_PATHS.public.reputationVote,
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
      publicState.leases.map(leaseToServer).map((server) => ({
        ...server,
        reputation: summaries[normalizeHostname(server.id)] ?? {
          hostname: normalizeHostname(server.id),
          up: 0,
          down: 0,
          total: 0,
          viewer_vote: "" as const,
        },
      })),
    [publicState.leases, summaries]
  );

  const hiddenCount = servers.filter((server) => isHiddenByVotes(server.reputation?.up ?? 0, server.reputation?.down ?? 0)).length;
  const visibleServers = useMemo(
    () => showHidden ? servers : servers.filter((server) => !isHiddenByVotes(server.reputation?.up ?? 0, server.reputation?.down ?? 0)),
    [servers, showHidden]
  );
  const list = useList({ servers: visibleServers });
  const favorites = visibleServers.filter((server) => server.reputation?.viewer_vote === "up").length;

  return {
    ...list,
    commentServer: commentServer ? servers.find((server) => server.id === commentServer.id) ?? commentServer : null,
    setCommentServer,
    browseView,
    favorites,
    showHidden,
    setShowHidden,
    hiddenCount,
    sidebarOpen,
    setSidebarOpen,
    filteredServers: browseView === "favorites"
      ? list.filteredServers.filter((server) => server.reputation?.viewer_vote === "up")
      : list.filteredServers,
    handleBrowseViewChange: (view: BrowseView) => {
      setBrowseView(view);
      if (typeof window !== "undefined" && typeof window.matchMedia === "function" && !window.matchMedia("(min-width: 1024px)").matches) {
        setSidebarOpen(false);
      }
      list.handleSearchChange("");
      list.handleStatusChange("all");
      list.handleSortByChange("default");
      list.selectedTags.forEach(list.handleTagToggle);
    },
    // null means unavailable; an empty array is an authoritative empty snapshot.
    leases: publicState.stale ? null : publicState.leases,
    onVote: vote,
  };
}
