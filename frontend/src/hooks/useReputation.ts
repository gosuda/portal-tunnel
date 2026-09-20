import { useEffect, useState } from "react";
import { apiClient } from "@/lib/apiClient";
import { BROWSER_API_PATHS } from "@/lib/apiPaths";
import type {
  ReputationSummary,
  ReputationVote,
  ReputationVoteResponse,
} from "@/types/api";

// Directory presentation policy; the relay only stores vote aggregates.
export function isReputationWarning(summary: ReputationSummary | undefined): boolean {
  return summary !== undefined && summary.total >= 5 && summary.down >= 3 && summary.down * 100 >= summary.total * 70;
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

function collectSummaries(rows: ReputationSummary[]): Record<string, ReputationSummary> {
  const summaries: Record<string, ReputationSummary> = {};
  for (const summary of rows) {
    if (isUsableSummary(summary)) {
      summaries[normalizeHostname(summary.hostname)] = summary;
    }
  }
  return summaries;
}

export function useReputation(rows: ReputationSummary[]) {
  const [summaries, setSummaries] = useState<Record<string, ReputationSummary>>(
    {}
  );
  useEffect(() => {
    setSummaries(collectSummaries(rows));
  }, [rows]);

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
