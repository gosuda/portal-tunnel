import type { ReputationSummary } from "@/types/api";

export function isHiddenByVotes(up: number, down: number): boolean {
  return down >= 5 && down > up;
}

export function isReputationWarning(summary: ReputationSummary | undefined): boolean {
  return (
    summary !== undefined &&
    summary.total >= 5 &&
    summary.down >= 3 &&
    summary.down * 100 >= summary.total * 70
  );
}
