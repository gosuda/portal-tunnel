import type { BaseServer } from "@/lib/server";

export function approval(server: BaseServer): number | null {
  const up = server.reputation?.up ?? 0;
  const down = server.reputation?.down ?? 0;
  return up + down === 0 ? null : up / (up + down);
}

export function firstSeenTime(server: BaseServer): number {
  const time = Date.parse(server.firstSeen ?? "");
  return Number.isNaN(time) ? 0 : time;
}
