import { useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { cn } from "@/lib/utils";
import type { BaseServer } from "@/lib/server";
import { isReputationWarning } from "@/utils/reputation";
import { recordAppOpened } from "@/components/list/recentApps";

const PLACEHOLDER_THUMBNAILS = [
  "/placeholders/aurora-peaks.svg",
  "/placeholders/twilight-watchtower.svg",
  "/placeholders/nebula-fjord.svg",
  "/placeholders/synth-horizon.svg",
] as const;

function pickPlaceholderThumbnail(seed: string): string {
  let hash = 0;
  for (let i = 0; i < seed.length; i += 1) {
    hash = (hash * 33 + seed.charCodeAt(i)) >>> 0;
  }
  return PLACEHOLDER_THUMBNAILS[hash % PLACEHOLDER_THUMBNAILS.length];
}

export function AppThumbnail({ server, className }: { server: BaseServer; className?: string }) {
  const [failedThumbnail, setFailedThumbnail] = useState<string | null>(null);
  const effective = failedThumbnail === server.thumbnail ? "" : server.thumbnail.trim();
  return (
    <img
      src={effective || pickPlaceholderThumbnail(server.name || server.id)}
      alt=""
      loading="lazy"
      className={cn("size-full object-cover", className)}
      onError={effective ? () => setFailedThumbnail(server.thumbnail) : undefined}
    />
  );
}

export function WebAppLink({ server, className, children }: { server: BaseServer; className?: string; children: ReactNode }) {
  if (isReputationWarning(server.reputation)) {
    return (
      <Link to={`/server/${encodeURIComponent(server.id)}`} state={server} aria-label={`Open ${server.name}`} onClick={() => recordAppOpened(server.id)} className={className}>
        {children}
      </Link>
    );
  }
  return (
    <a href={server.link || "#"} aria-label={`Open ${server.name}`} onClick={() => recordAppOpened(server.id)} className={className}>
      {children}
    </a>
  );
}
