import { useEffect, useRef, useState } from "react";
import { apiClient } from "@/lib/apiClient";
import { BROWSER_API_PATHS } from "@/lib/apiPaths";
import type {
  ReputationAggregatesResponse,
  ReputationSummary,
  ReputationVote,
  ReputationVoteResponse,
} from "@/types/api";

// Directory presentation policy; the relay only stores vote aggregates.
export function isReputationWarning(summary: ReputationSummary | undefined): boolean {
  return summary !== undefined && summary.total >= 5 && summary.down >= 3 && summary.down * 100 >= summary.total * 70;
}

export function applyVoteToSummary(
  summary: ReputationSummary,
  vote: ReputationVote
): ReputationSummary {
  if (summary.viewer_vote === vote) {
    return summary;
  }

  const up =
    summary.up +
    (vote === "up" ? 1 : 0) -
    (summary.viewer_vote === "up" ? 1 : 0);
  const down =
    summary.down +
    (vote === "down" ? 1 : 0) -
    (summary.viewer_vote === "down" ? 1 : 0);
  const total = up + down;

  return {
    ...summary,
    up,
    down,
    total,
    viewer_vote: vote,
  };
}

function applyVoteResponse(
  summary: ReputationSummary,
  response: ReputationVoteResponse
): ReputationSummary {
  return {
    ...summary,
    up: response.up,
    down: response.down,
    total: response.total,
    viewer_vote: response.viewer_vote ?? "",
  };
}

export function openAnywaySessionKey(hostname: string): string {
  return `portal:reputation:openAnyway:${hostname.trim().toLowerCase()}`;
}

export function readOpenAnyway(hostname: string): boolean {
  try {
    return sessionStorage.getItem(openAnywaySessionKey(hostname)) === "1";
  } catch {
    // Session storage can be unavailable (private browsing); the gate then re-asks.
    return false;
  }
}

export function rememberOpenAnyway(hostname: string): void {
  try {
    sessionStorage.setItem(openAnywaySessionKey(hostname), "1");
  } catch {
    // Same availability caveat: forgetting the skip is acceptable.
  }
}

export function normalizeHostname(hostname: string): string {
  return hostname.trim().toLowerCase();
}

function isUsableSummary(
  summary: ReputationSummary | undefined
): summary is ReputationSummary {
  return (
    typeof summary?.hostname === "string" &&
    summary.hostname.trim() !== "" &&
    typeof summary.up === "number" &&
    typeof summary.down === "number" &&
    typeof summary.total === "number"
  );
}

function collectSummaries(
  response: ReputationAggregatesResponse | undefined
): Record<string, ReputationSummary> {
  const summaries: Record<string, ReputationSummary> = {};
  for (const summary of Array.isArray(response?.hostnames)
    ? response.hostnames
    : []) {
    if (isUsableSummary(summary)) {
      summaries[normalizeHostname(summary.hostname)] = summary;
    }
  }
  return summaries;
}

export function useReputation() {
  const [summaries, setSummaries] = useState<Record<string, ReputationSummary>>(
    {}
  );
  // Keep the current map for the stable vote handler without re-running effects.
  const summariesRef = useRef(summaries);
  const [pending, setPending] = useState<Record<string, boolean>>({});

  const applySummaries = (next: Record<string, ReputationSummary>) => {
    summariesRef.current = next;
    setSummaries(next);
  };

  useEffect(() => {
    let cancelled = false;

    void (async () => {
      try {
        const data = await apiClient.get<ReputationAggregatesResponse>(
          BROWSER_API_PATHS.public.reputation
        );
        if (cancelled) {
          return;
        }
        const next = collectSummaries(data);
        summariesRef.current = next;
        setSummaries(next);
      } catch (error) {
        console.error("Failed to load reputation aggregates", error);
      }
    })();

    return () => {
      cancelled = true;
    };
  }, []);

  const vote = (hostname: string, vote: ReputationVote) => {
    const key = normalizeHostname(hostname);
    if (key === "" || pending[key]) {
      return;
    }
    const current = summariesRef.current[key] ?? {
      hostname: key,
      up: 0,
      down: 0,
      total: 0,
      viewer_vote: "" as const,
    };

    // Optimistic counts use the same directory warning policy immediately.
    const snapshot = current;
    applySummaries({
      ...summariesRef.current,
      [key]: applyVoteToSummary(current, vote),
    });

    setPending((previous) => ({ ...previous, [key]: true }));

    void (async () => {
      try {
        const response = await apiClient.post<ReputationVoteResponse>(
          BROWSER_API_PATHS.public.reputationVote,
          { hostname: current.hostname, vote }
        );
        if (
          typeof response?.up === "number" &&
          typeof response?.down === "number" &&
          typeof response?.total === "number"
        ) {
          applySummaries({
            ...summariesRef.current,
            [key]: applyVoteResponse(summariesRef.current[key] ?? current, response),
          });
        }
      } catch (error) {
        console.error("Failed to submit vote", error);
        applySummaries({ ...summariesRef.current, [key]: snapshot });
      } finally {
        setPending((previous) => ({ ...previous, [key]: false }));
      }
    })();
  };

  const getSummary = (hostname: string): ReputationSummary | undefined =>
    summaries[normalizeHostname(hostname)];

  return { getSummary, summaries, vote, isVotePending: (hostname: string) => Boolean(pending[normalizeHostname(hostname)]) };
}
