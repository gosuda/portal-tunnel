import { useEffect, useMemo, useRef, useState } from "react";
import type { BrowseView } from "@/types/filters";
import { useList } from "@/hooks/useList";
import { useMediaQuery } from "@/hooks/useMediaQuery";
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

const DESKTOP_QUERY = "(min-width: 1024px)";
const POLL_INTERVAL_MS = 1500;

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
  const isDesktop = useMediaQuery(DESKTOP_QUERY);
  // The sidebar opens on desktop and closes on mobile, and follows the
  // breakpoint when it is crossed; in between, the visitor toggles it.
  const [sidebarOpen, setSidebarOpen] = useState(isDesktop);
  const [sidebarBreakpoint, setSidebarBreakpoint] = useState(isDesktop);
  if (sidebarBreakpoint !== isDesktop) {
    setSidebarBreakpoint(isDesktop);
    setSidebarOpen(isDesktop);
  }
  const [publicState, setPublicState] = useState<PublicState>({
    leases: [],
    stale: true,
  });
  const [summaries, setSummaries] = useState<Record<string, ReputationSummary>>({});

  // The last snapshot as the relay sent it; an identical poll keeps the
  // current state, so the directory does not filter, sort and re-render.
  const lastSnapshot = useRef("");

  useEffect(() => {
    let cancelled = false;
    let timer: number | undefined;
    let inFlight = false;

    const schedule = () => {
      window.clearTimeout(timer);
      timer = undefined;
      // A hidden tab stops polling; becoming visible refreshes at once.
      if (!cancelled && !document.hidden) {
        timer = window.setTimeout(() => void refresh(), POLL_INTERVAL_MS);
      }
    };

    const refresh = async () => {
      if (inFlight) {
        return;
      }
      inFlight = true;
      try {
        const data = await apiClient.get<PublicStateResponse>(
          RELAY_API_PATHS.public.state
        );
        if (cancelled) {
          return;
        }
        const leases = Array.isArray(data?.leases) ? data.leases : [];
        const snapshot = JSON.stringify([leases, data?.reputation ?? null]);
        if (snapshot === lastSnapshot.current) {
          setPublicState((previous) =>
            previous.stale ? { ...previous, stale: false } : previous
          );
          return;
        }
        lastSnapshot.current = snapshot;
        setSummaries(collectReputation(data?.reputation));
        setPublicState({ leases, stale: false });
      } catch (error) {
        console.error("Failed to load public relay state", error);
        if (!cancelled) {
          setPublicState((previous) =>
            previous.stale ? previous : { ...previous, stale: true }
          );
        }
      } finally {
        inFlight = false;
        schedule();
      }
    };

    const handleVisibilityChange = () => {
      if (document.hidden) {
        window.clearTimeout(timer);
        timer = undefined;
      } else {
        void refresh();
      }
    };

    document.addEventListener("visibilitychange", handleVisibilityChange);
    void refresh();

    return () => {
      cancelled = true;
      window.clearTimeout(timer);
      document.removeEventListener("visibilitychange", handleVisibilityChange);
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
        // The next poll must apply the relay's count even if it matches the old snapshot.
        lastSnapshot.current = "";
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
      if (!isDesktop) {
        setSidebarOpen(false);
      }
      list.resetFilters();
    },
    // null means unavailable; an empty array is an authoritative empty snapshot.
    leases: publicState.stale ? null : publicState.leases,
    onVote: vote,
  };
}
