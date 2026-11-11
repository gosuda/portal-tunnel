import { useEffect, useMemo, useRef, useState, type Dispatch, type SetStateAction } from "react";
import type { BrowseView } from "@/types/filters";
import { useList, type UseListReturn } from "@/hooks/useList";
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
  ReputationVoteRequest,
  ReputationVoteResponse,
} from "@/types/api";

const DESKTOP_QUERY = "(min-width: 1280px)";
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
      summaries[normalizeHostname(summary.hostname)] = {
        ...summary,
        comments: typeof summary.comments === "number" ? summary.comments : 0,
      };
    }
  }
  return summaries;
}
type PublicStateSnapshot = {
  leases: Lease[];
  snapshot: string;
};

function snapshotPublicState(data: PublicStateResponse | undefined): PublicStateSnapshot {
  const leases = Array.isArray(data?.leases) ? data.leases : [];
  return { leases, snapshot: JSON.stringify([leases, data?.reputation ?? null]) };
}

function transitionPublicState(
  data: PublicStateResponse | undefined,
  previousSnapshot: string
): { leases: Lease[]; snapshot: string; summaries: Record<string, ReputationSummary> } | null {
  const { leases, snapshot } = snapshotPublicState(data);
  if (snapshot === previousSnapshot) {
    return null;
  }
  return { leases, snapshot, summaries: collectReputation(data?.reputation) };
}

async function loadPublicStateIntoStores(
  isCancelled: () => boolean,
  snapshotRef: { current: string },
  setPublicState: Dispatch<SetStateAction<PublicState>>,
  setSummaries: Dispatch<SetStateAction<Record<string, ReputationSummary>>>
): Promise<void> {
  try {
    const data = await apiClient.get<PublicStateResponse>(RELAY_API_PATHS.public.state);
    if (isCancelled()) {
      return;
    }
    storePublicTransition(transitionPublicState(data, snapshotRef.current), snapshotRef, setPublicState, setSummaries);
  } catch (error) {
    storePublicLoadError(isCancelled, setPublicState, error);
  }
}

function storePublicTransition(transition: { leases: Lease[]; snapshot: string; summaries: Record<string, ReputationSummary> } | null, snapshotRef: { current: string }, setPublicState: Dispatch<SetStateAction<PublicState>>, setSummaries: Dispatch<SetStateAction<Record<string, ReputationSummary>>>): void {
  if (transition === null) {
    setPublicState((previous) => (previous.stale ? { ...previous, stale: false } : previous));
    return;
  }
  snapshotRef.current = transition.snapshot;
  setSummaries(transition.summaries);
  setPublicState({ leases: transition.leases, stale: false });
}

function storePublicLoadError(isCancelled: () => boolean, setPublicState: Dispatch<SetStateAction<PublicState>>, error: unknown): void {
  console.error("Failed to load public relay state", error);
  if (!isCancelled()) {
    setPublicState((previous) => (previous.stale ? previous : { ...previous, stale: true }));
  }
}

type PublicPollingControl = { timer: number | undefined; cancelled: boolean; tick: (isCancelled: () => boolean) => Promise<void> };

function schedulePublicPolling(control: PublicPollingControl): void {
  window.clearTimeout(control.timer);
  control.timer = undefined;
  if (!control.cancelled && !document.hidden) {
    control.timer = window.setTimeout(() => runPublicPollTick(control), POLL_INTERVAL_MS);
  }
}

function runPublicPollTick(control: PublicPollingControl): void {
  void control.tick(() => control.cancelled).finally(() => schedulePublicPolling(control));
}

function handlePollVisibility(control: PublicPollingControl): void {
  if (document.hidden) {
    window.clearTimeout(control.timer);
    control.timer = undefined;
  } else {
    runPublicPollTick(control);
  }
}

function stopPublicPolling(control: PublicPollingControl, handleVisibilityChange: () => void): void {
  control.cancelled = true;
  window.clearTimeout(control.timer);
  document.removeEventListener("visibilitychange", handleVisibilityChange);
}

function createPublicRefresh(snapshotRef: { current: string }, setPublicState: Dispatch<SetStateAction<PublicState>>, setSummaries: Dispatch<SetStateAction<Record<string, ReputationSummary>>>): (isCancelled: () => boolean) => Promise<void> {
  let inFlight = false;
  return async (isCancelled: () => boolean) => {
    if (inFlight) {
      return;
    }
    inFlight = true;
    try {
      await loadPublicStateIntoStores(isCancelled, snapshotRef, setPublicState, setSummaries);
    } finally {
      inFlight = false;
    }
  };
}

function useSyncedSidebar(isDesktop: boolean): [boolean, Dispatch<SetStateAction<boolean>>] {
  const [sidebarOpen, setSidebarOpen] = useState(isDesktop);
  const [sidebarBreakpoint, setSidebarBreakpoint] = useState(isDesktop);
  if (sidebarBreakpoint !== isDesktop) {
    setSidebarBreakpoint(isDesktop);
    setSidebarOpen(isDesktop);
  }
  return [sidebarOpen, setSidebarOpen];
}

async function postVoteAndMerge(hostname: string, vote: ReputationVoteAction, snapshotRef: { current: string }, setSummaries: Dispatch<SetStateAction<Record<string, ReputationSummary>>>): Promise<void> {
  const key = normalizeHostname(hostname);
  if (key === "") {
    return;
  }
  const response = await apiClient.post<ReputationVoteResponse>(
    RELAY_API_PATHS.public.reputationVote,
    { hostname: key, vote } satisfies ReputationVoteRequest
  );
  if (!hasReputationTally(response)) {
    return;
  }
  snapshotRef.current = "";
  setSummaries((current) => mergeVoteSummary(key, response, current));
}

function countHidden(servers: BaseServer[]): number {
  return servers.filter((server) => isHiddenByVotes(server.reputation?.up ?? 0, server.reputation?.down ?? 0)).length;
}

function selectFilteredServers(browseView: BrowseView, filteredServers: BaseServer[]): BaseServer[] {
  if (browseView !== "favorites") {
    return filteredServers;
  }
  return filteredServers.filter((server) => server.reputation?.viewer_vote === "up");
}

function selectLeases(publicState: PublicState): Lease[] | null {
  return publicState.stale ? null : publicState.leases;
}

function applyBrowseViewChange(view: BrowseView, isDesktop: boolean, setBrowseView: (view: BrowseView) => void, setSidebarOpen: (value: boolean) => void, resetFilters: () => void): void {
  setBrowseView(view);
  if (!isDesktop) {
    setSidebarOpen(false);
  }
  resetFilters();
}

function startPublicStatePolling(tick: (isCancelled: () => boolean) => Promise<void>): () => void {
  const control: PublicPollingControl = { timer: undefined, cancelled: false, tick };
  const handleVisibilityChange = () => handlePollVisibility(control);
  document.addEventListener("visibilitychange", handleVisibilityChange);
  runPublicPollTick(control);
  return () => stopPublicPolling(control, handleVisibilityChange);
}

function hasReputationTally(response: ReputationVoteResponse): boolean {
  return (
    typeof response?.up === "number" &&
    typeof response?.down === "number" &&
    typeof response?.total === "number"
  );
}

function mergeVoteSummary(
  key: string,
  response: ReputationVoteResponse,
  current: Record<string, ReputationSummary>
): Record<string, ReputationSummary> {
  return {
    ...current,
    [key]: {
      hostname: response.hostname || key,
      up: response.up,
      down: response.down,
      total: response.total,
      viewer_vote: response.viewer_vote ?? "",
      comments: response.comments ?? current[key]?.comments ?? 0,
    },
  };
}

function attachReputation(
  leases: Lease[],
  summaries: Record<string, ReputationSummary>
): BaseServer[] {
  return leases.map(leaseToServer).map((server) => ({
    ...server,
    reputation: summaries[normalizeHostname(server.id)] ?? {
      hostname: normalizeHostname(server.id),
      up: 0,
      down: 0,
      total: 0,
      viewer_vote: "" as const,
      comments: 0,
    },
  }));
}

function selectVisibleServers(servers: BaseServer[], showHidden: boolean): BaseServer[] {
  if (showHidden) {
    return servers;
  }
  return servers.filter(
    (server) => !isHiddenByVotes(server.reputation?.up ?? 0, server.reputation?.down ?? 0)
  );
}

export function useServerList(): UseListReturn<BaseServer> & { commentServer: BaseServer | null; toggleComments: (server: BaseServer) => void; closeComments: () => void; browseView: BrowseView; favorites: number; showHidden: boolean; setShowHidden: (value: boolean) => void; hiddenCount: number; sidebarOpen: boolean; setSidebarOpen: (value: boolean) => void; filteredServers: BaseServer[]; handleBrowseViewChange: (view: BrowseView) => void; leases: Lease[] | null; onVote: (hostname: string, vote: ReputationVoteAction) => Promise<void> } {
  const [commentServerId, setCommentServerId] = useState<string | null>(null);
  const [browseView, setBrowseView] = useState<BrowseView>("home");
  const [showHidden, setShowHidden] = useState(false);
  const isDesktop = useMediaQuery(DESKTOP_QUERY);
  const [sidebarOpen, setSidebarOpen] = useSyncedSidebar(isDesktop);
  const [publicState, setPublicState] = useState<PublicState>({
    leases: [],
    stale: true,
  });
  const [summaries, setSummaries] = useState<Record<string, ReputationSummary>>({});

  const lastSnapshot = useRef("");

  useEffect(() => {
    return startPublicStatePolling(createPublicRefresh(lastSnapshot, setPublicState, setSummaries));
  }, []);

  const vote = async (hostname: string, voteAction: ReputationVoteAction): Promise<void> => {
    await postVoteAndMerge(hostname, voteAction, lastSnapshot, setSummaries);
  };


  const servers: BaseServer[] = useMemo(
    () => attachReputation(publicState.leases, summaries),
    [publicState.leases, summaries]
  );

  const hiddenCount = countHidden(servers);
  const visibleServers = useMemo(
    () => selectVisibleServers(servers, showHidden),
    [servers, showHidden]
  );
  const list = useList({ servers: visibleServers });
  const favorites = visibleServers.filter((server) => server.reputation?.viewer_vote === "up").length;

  return {
    ...list,
    commentServer: servers.find((server) => server.id === commentServerId) ?? null,
    toggleComments: (server: BaseServer) =>
      setCommentServerId((current) => (current === server.id ? null : server.id)),
    closeComments: () => setCommentServerId(null),
    browseView,
    favorites,
    showHidden,
    setShowHidden,
    hiddenCount,
    sidebarOpen,
    setSidebarOpen,
    filteredServers: selectFilteredServers(browseView, list.filteredServers),
    handleBrowseViewChange: (view: BrowseView) => {
      applyBrowseViewChange(view, isDesktop, setBrowseView, setSidebarOpen, list.resetFilters);
    },
    leases: selectLeases(publicState),
    onVote: vote,
  };
}
