import { useEffect, useRef, useState } from "react";
import { apiClient } from "@/lib/apiClient";
import { BROWSER_API_PATHS } from "@/lib/apiPaths";
import type {
  ReputationAggregatesResponse,
  ReputationSummary,
  ReputationVote,
  ReputationVoteResponse,
} from "@/types/api";

// The relay owns the warning decision; this projection only shifts counts.
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
    down_ratio: total > 0 ? down / total : 0,
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
  // Votes read and reconcile through the ref so handlers stay current without
  // effect re-runs; the relay's newest response wins per hostname.
  const summariesRef = useRef(summaries);
  const voteSeqRef = useRef<Record<string, number>>({});

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
    const current = summariesRef.current[key];
    if (key === "" || !current) {
      return;
    }

    // Optimistic: show the new tally immediately; the relay's warning
    // decision stays untouched until the authoritative response arrives.
    const snapshot = current;
    applySummaries({
      ...summariesRef.current,
      [key]: applyVoteToSummary(current, vote),
    });

    const seq = (voteSeqRef.current[key] ?? 0) + 1;
    voteSeqRef.current[key] = seq;

    void (async () => {
      try {
        const response = await apiClient.post<ReputationVoteResponse>(
          BROWSER_API_PATHS.public.reputationVote,
          { hostname: current.hostname, vote }
        );
        if (voteSeqRef.current[key] !== seq) {
          return;
        }
        if (
          typeof response?.up === "number" &&
          typeof response?.down === "number" &&
          typeof response?.total === "number"
        ) {
          applySummaries({
            ...summariesRef.current,
            [key]: applyVoteResponse(current, response),
          });
        }
      } catch (error) {
        if (voteSeqRef.current[key] !== seq) {
          return;
        }
        console.error("Failed to submit vote", error);
        applySummaries({ ...summariesRef.current, [key]: snapshot });
      }
    })();
  };

  const getSummary = (hostname: string): ReputationSummary | undefined =>
    summaries[normalizeHostname(hostname)];

  return { getSummary, summaries, vote };
}
