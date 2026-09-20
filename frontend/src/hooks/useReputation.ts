import { useEffect, useState } from "react";
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
        setSummaries(collectSummaries(data));
      } catch (error) {
        console.error("Failed to load reputation aggregates", error);
      }
    })();

    return () => {
      cancelled = true;
    };
  }, []);

  const vote = async (hostname: string, vote: ReputationVote): Promise<void> => {
    const key = normalizeHostname(hostname);
    if (key === "") {
      return;
    }
    try {
      const response = await apiClient.post<ReputationVoteResponse>(
        BROWSER_API_PATHS.public.reputationVote,
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
    }
  };

  return { summaries, vote };
}
