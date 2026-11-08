import type { ReputationSummary } from "@/types/api";

// Directory presentation policy; the relay only stores vote aggregates.

/** An app or comment the directory hides by default: at least 5 down votes, outnumbering the up votes. */
export function isHiddenByVotes(up: number, down: number): boolean {
  return down >= 5 && down > up;
}

/** An app that opens behind a warning: at least 5 ratings, 3 or more down, and 70% or more down. */
export function isReputationWarning(summary: ReputationSummary | undefined): boolean {
  return (
    summary !== undefined &&
    summary.total >= 5 &&
    summary.down >= 3 &&
    summary.down * 100 >= summary.total * 70
  );
}
