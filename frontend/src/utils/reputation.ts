export function isHiddenByVotes(up: number, down: number): boolean {
  return down >= 5 && down > up;
}
