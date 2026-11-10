import { useId, useMemo, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import clsx from "clsx";
import {
  BadgeDollarSign,
  MessageSquare,
  ThumbsDown,
  ThumbsUp,
} from "lucide-react";
import type { BaseServer } from "@/lib/server";
import type { ReputationVoteAction } from "@/types/api";
import { useCopy } from "@/hooks/useCopy";
import { isHiddenByVotes, isReputationWarning } from "@/utils/reputation";

export interface ConstellationData {
  nebulaHue: number;
  nebulaCx: number;
  nebulaCy: number;
  bgStars: { cx: number; cy: number; r: number; opacity: number }[];
  stars: { x: number; y: number; r: number; opacity: number; isPrimary: boolean }[];
  lines: { x1: number; y1: number; x2: number; y2: number; opacity: number }[];
}

export function createConstellationData(seed: string): ConstellationData {
  const normalizedSeed = seed.toLowerCase().trim();
  const randseed = new Int32Array(4);
  for (let i = 0; i < normalizedSeed.length; i += 1) {
    randseed[i % 4] = ((randseed[i % 4] << 5) - randseed[i % 4]) + normalizedSeed.charCodeAt(i);
  }

  function rand(): number {
    const t = randseed[0] ^ (randseed[0] << 11);
    randseed[0] = randseed[1];
    randseed[1] = randseed[2];
    randseed[2] = randseed[3];
    randseed[3] = (randseed[3] ^ (randseed[3] >> 19)) ^ t ^ (t >> 8);
    return (randseed[3] >>> 0) / ((1 << 31) >>> 0);
  }

  const nebulaHue = Math.floor(205 + rand() * 35);
  const nebulaCx = Math.floor(90 + rand() * 140);
  const nebulaCy = Math.floor(45 + rand() * 90);

  const bgCount = 20 + Math.floor(rand() * 9);
  const bgStars: { cx: number; cy: number; r: number; opacity: number }[] = [];
  for (let i = 0; i < bgCount; i += 1) {
    bgStars.push({
      cx: Math.round(rand() * 320 * 10) / 10,
      cy: Math.round(rand() * 180 * 10) / 10,
      r: Math.round((0.5 + rand() * 0.7) * 10) / 10,
      opacity: Math.round((0.15 + rand() * 0.35) * 100) / 100,
    });
  }

  const starCount = 6 + Math.floor(rand() * 3);
  const candidateStars: { x: number; y: number; r: number; opacity: number }[] = [];

  const minDistance = 42;
  const minDistanceSq = minDistance * minDistance;

  for (let attempt = 0; attempt < 120 && candidateStars.length < starCount; attempt += 1) {
    const x = Math.round((45 + rand() * 230) * 10) / 10;
    const y = Math.round((30 + rand() * 120) * 10) / 10;

    let tooClose = false;
    for (const existing of candidateStars) {
      const dx = existing.x - x;
      const dy = existing.y - y;
      if (dx * dx + dy * dy < minDistanceSq) {
        tooClose = true;
        break;
      }
    }

    if (tooClose) {
      continue;
    }
    candidateStars.push({
      x,
      y,
      r: Math.round((1.6 + rand() * 1.5) * 10) / 10,
      opacity: Math.round((0.85 + rand() * 0.15) * 100) / 100,
    });
  }

  const sortedIndices = candidateStars
    .map((s, idx) => ({ r: s.r, idx }))
    .sort((a, b) => b.r - a.r);
  const primarySet = new Set(sortedIndices.slice(0, 2).map((item) => item.idx));

  const stars = candidateStars.map((s, idx) => ({
    ...s,
    isPrimary: primarySet.has(idx),
  }));

  const n = stars.length;
  const inTree = new Set<number>([0]);
  const edges: [number, number][] = [];

  while (inTree.size < n) {
    let bestDist = Infinity;
    let bestU = -1;
    let bestV = -1;

    for (const u of inTree) {
      for (let v = 0; v < n; v += 1) {
        if (inTree.has(v)) {
          continue;
        }
        const dx = stars[u].x - stars[v].x;
        const dy = stars[u].y - stars[v].y;
        const distSq = dx * dx + dy * dy;
        if (distSq < bestDist) {
          bestDist = distSq;
          bestU = u;
          bestV = v;
        }
      }
    }

    if (bestU === -1 || bestV === -1) {
      break;
    }
    inTree.add(bestV);
    edges.push([bestU, bestV]);
  }

  if (n >= 4) {
    let extraDist = Infinity;
    let extraU = -1;
    let extraV = -1;
    for (let u = 0; u < n; u += 1) {
      for (let v = u + 1; v < n; v += 1) {
        const alreadyConnected = edges.some(
          ([a, b]) => (a === u && b === v) || (a === v && b === u)
        );
        if (alreadyConnected) {
          continue;
        }
        const dx = stars[u].x - stars[v].x;
        const dy = stars[u].y - stars[v].y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < 85 && dist < extraDist) {
          extraDist = dist;
          extraU = u;
          extraV = v;
        }
      }
    }
    if (extraU !== -1 && extraV !== -1 && rand() > 0.3) {
      edges.push([extraU, extraV]);
    }
  }

  const lines = edges.map(([u, v]) => ({
    x1: stars[u].x,
    y1: stars[u].y,
    x2: stars[v].x,
    y2: stars[v].y,
    opacity: Math.round((0.26 + rand() * 0.16) * 100) / 100,
  }));

  return {
    nebulaHue,
    nebulaCx,
    nebulaCy,
    bgStars,
    stars,
    lines,
  };
}

export function DefaultServerThumbnail({ server }: { server: BaseServer }) {
  const seed = (server.address || server.name || server.id || "portal").trim();
  const data = useMemo(() => createConstellationData(seed), [seed]);
  const nebulaId = useId();
  const skyGradId = useId();
  const starGlowId = useId();

  return (
    <div
      className="absolute inset-0 select-none overflow-hidden bg-[#040711] transition-transform duration-300 ease-out motion-safe:group-hover:scale-[1.02]"
      aria-hidden="true"
    >
      <svg
        viewBox="0 0 320 180"
        className="h-full w-full object-cover"
        preserveAspectRatio="xMidYMid slice"
        xmlns="http://www.w3.org/2000/svg"
      >
        <defs>
          <linearGradient id={skyGradId} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#040711" />
            <stop offset="48%" stopColor="#081020" />
            <stop offset="100%" stopColor="#0c172e" />
          </linearGradient>

          <radialGradient id={nebulaId} cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor={`hsl(${data.nebulaHue}, 50%, 28%)`} stopOpacity="0.32" />
            <stop offset="60%" stopColor={`hsl(${data.nebulaHue}, 45%, 16%)`} stopOpacity="0.12" />
            <stop offset="100%" stopColor="#040711" stopOpacity="0" />
          </radialGradient>

          <radialGradient id={starGlowId} cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="#ffffff" stopOpacity="0.9" />
            <stop offset="35%" stopColor="#bae6fd" stopOpacity="0.4" />
            <stop offset="100%" stopColor="#38bdf8" stopOpacity="0" />
          </radialGradient>
        </defs>

        <rect width="320" height="180" fill={`url(#${skyGradId})`} />

        <ellipse
          cx={data.nebulaCx}
          cy={data.nebulaCy}
          rx={150}
          ry={95}
          fill={`url(#${nebulaId})`}
        />

        <g fill="#f8fafc">
          {data.bgStars.map((s, idx) => (
            <circle
              key={`bg-${idx}`}
              cx={s.cx}
              cy={s.cy}
              r={s.r}
              opacity={s.opacity}
            />
          ))}
        </g>

        <g stroke="#bae6fd" strokeWidth="1" strokeLinecap="round">
          {data.lines.map((line, idx) => (
            <line
              key={`line-${idx}`}
              x1={line.x1}
              y1={line.y1}
              x2={line.x2}
              y2={line.y2}
              strokeOpacity={line.opacity}
            />
          ))}
        </g>

        {data.stars.map((star, idx) => (
          <g key={`star-${idx}`}>
            {star.isPrimary && (
              <>
                <circle
                  cx={star.x}
                  cy={star.y}
                  r={star.r * 2.8}
                  fill={`url(#${starGlowId})`}
                  opacity="0.4"
                />
                <line
                  x1={star.x - star.r * 3.5}
                  y1={star.y}
                  x2={star.x + star.r * 3.5}
                  y2={star.y}
                  stroke="#ffffff"
                  strokeWidth="0.65"
                  strokeOpacity="0.65"
                />
                <line
                  x1={star.x}
                  y1={star.y - star.r * 3.5}
                  x2={star.x}
                  y2={star.y + star.r * 3.5}
                  stroke="#ffffff"
                  strokeWidth="0.65"
                  strokeOpacity="0.65"
                />
              </>
            )}

            <circle
              cx={star.x}
              cy={star.y}
              r={star.r + 0.6}
              fill="#bae6fd"
              opacity="0.35"
            />

            <circle
              cx={star.x}
              cy={star.y}
              r={star.r}
              fill="#ffffff"
            />
          </g>
        ))}
      </svg>
    </div>
  );
}

interface ServerCardProps {
  server: BaseServer;
  action?: ReactNode;
  children?: ReactNode;
  navigable?: boolean;
  onOpenComments?: (server: BaseServer) => void;
  onVote?: (hostname: string, vote: ReputationVoteAction) => void | Promise<void>;
}

export function ServerCard({
  server,
  action,
  children,
  navigable = true,
  onOpenComments,
  onVote,
}: ServerCardProps) {
  const {
    id: serverId, name, description, tags, thumbnail, online,
    tcpAddr, udpAddr, paymentEnabled = false, paymentLabel = "",
  } = server;
  const [failedThumbnail, setFailedThumbnail] = useState<string | null>(null);
  const [isVoting, setIsVoting] = useState(false);
  const { copiedKey: copiedProtocol, copy } = useCopy(1500);
  const hasDetails = Boolean(description || (tags && tags.length > 0));
  const effectiveThumbnail = failedThumbnail === thumbnail ? "" : thumbnail.trim();
  const normalizedPaymentLabel = paymentLabel.trim();
  const showPaymentBadge = paymentEnabled || normalizedPaymentLabel !== "";
  const effectivePaymentLabel = normalizedPaymentLabel || "Paid app";
  const endpoints = [
    ...(tcpAddr ? [{ protocol: "TCP", address: tcpAddr }] : []),
    ...(udpAddr ? [{ protocol: "UDP", address: udpAddr }] : []),
  ];
  const isTransportService = endpoints.length > 0;
  const isNavigable = navigable && !isTransportService;
  const showActions = Boolean(!children && (onVote || onOpenComments || server.reputation));

  const copyEndpoint = (protocol: string, address: string) =>
    copy(address, protocol);

  const handleVote = async (event: React.MouseEvent, targetVote: "up" | "down") => {
    event.preventDefault();
    event.stopPropagation();
    if (!onVote || isVoting) return;
    setIsVoting(true);
    try {
      const currentVote = server.reputation?.viewer_vote;
      const nextVote: ReputationVoteAction = currentVote === targetVote ? "clear" : targetVote;
      const targetHost = server.id || server.reputation?.hostname || "";
      await onVote(targetHost, nextVote);
    } catch (err) {
      console.error("Failed to vote from card", err);
    } finally {
      setIsVoting(false);
    }
  };

  const cardBody = (
    <article className="relative w-full min-w-0">
      <div className="relative aspect-video w-full overflow-hidden rounded-xl border border-border/70 dark:border-white/10 bg-muted shadow-2xs transition-all duration-300 ease-out group-hover:scale-[1.02] group-hover:border-border group-hover:shadow-md">
        {effectiveThumbnail ? (
          <img
            src={effectiveThumbnail}
            alt=""
            loading="lazy"
            className="absolute inset-0 h-full w-full object-cover transition-transform duration-300 ease-out motion-safe:group-hover:scale-[1.03]"
            onError={() => setFailedThumbnail(thumbnail)}
          />
        ) : (
          <DefaultServerThumbnail server={server} />
        )}

        {action && (
          <div className="pointer-events-auto absolute top-2.5 right-2.5 z-30">
            {action}
          </div>
        )}
        {server.reputation && isHiddenByVotes(server.reputation.up, server.reputation.down) && (
          <span className="absolute top-2.5 right-2.5 rounded bg-black/80 px-2 py-0.5 text-xs text-white">
            Hidden by downvotes
          </span>
        )}

        {showPaymentBadge && (
          <span
            className={clsx(
              "absolute inline-flex max-w-[80%] items-center gap-1 rounded bg-black/80 px-2 py-0.5 text-xs font-medium text-white backdrop-blur-xs",
              isTransportService ? "top-2.5 left-2.5" : "bottom-2.5 left-2.5"
            )}
          >
            <BadgeDollarSign className="size-3.5 shrink-0 text-emerald-400" />
            <span className="truncate">{effectivePaymentLabel}</span>
          </span>
        )}

        {online && !isTransportService && (
          <span className="absolute bottom-2.5 right-2.5 inline-flex items-center gap-1.5 rounded bg-black/80 px-2 py-0.5 text-[11px] font-bold tracking-wider text-emerald-400 backdrop-blur-xs">
            <span className="size-1.5 rounded-full bg-emerald-400 animate-pulse" />
            LIVE
          </span>
        )}

        {hasDetails && (
          <div
            className={clsx(
              "pointer-events-none absolute inset-0 z-20 flex flex-col justify-end bg-gradient-to-t from-black/95 via-black/85 to-black/40 p-3.5 opacity-0 transition-opacity duration-200 group-hover:opacity-100 group-focus-within:opacity-100",
              isTransportService ? (endpoints.length > 1 ? "pb-24" : "pb-18") : ""
            )}
          >
            {description && (
              <>
                <div className="mb-1 flex items-center justify-between">
                  <span className="text-[10px] font-semibold uppercase tracking-wider text-white/60">
                    Description
                  </span>
                </div>
                <p className="line-clamp-4 text-xs leading-relaxed text-white/95 whitespace-pre-wrap break-words">
                  {description}
                </p>
              </>
            )}
            {tags && tags.length > 0 && (
              <div className={clsx("flex flex-wrap gap-1", description ? "mt-2" : "")}>
                {tags.slice(0, 4).map((tag) => (
                  <span
                    key={tag}
                    className="rounded bg-white/20 px-1.5 py-0.5 text-[10px] font-medium text-white backdrop-blur-xs"
                  >
                    #{tag}
                  </span>
                ))}
              </div>
            )}
          </div>
        )}

        {isTransportService && (
          <div className="pointer-events-auto absolute inset-x-2.5 bottom-2.5 z-30 space-y-1 rounded-lg border border-white/10 bg-black/85 p-2 backdrop-blur-md shadow-xs">
            {endpoints.map((endpoint) => (
              <div key={endpoint.protocol} className="flex min-w-0 items-center gap-2">
                <code
                  className="min-w-0 flex-1 truncate font-mono text-xs text-white/90"
                  title={endpoint.address}
                >
                  {endpoint.address}
                </code>
                <button
                  type="button"
                  onClick={() => void copyEndpoint(endpoint.protocol, endpoint.address)}
                  className="pointer-events-auto relative z-30 shrink-0 rounded bg-white/20 px-2 py-0.5 text-[11px] font-semibold text-white transition-colors hover:bg-primary hover:text-primary-foreground focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-primary cursor-pointer active:scale-95"
                >
                  {copiedProtocol === endpoint.protocol ? "Copied!" : `Copy ${endpoint.protocol}`}
                </button>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className={clsx("mt-2.5 flex items-center justify-between gap-2", isNavigable ? "pointer-events-none" : "")}>
        <h3
          title={name}
          className="min-w-0 flex-1 truncate text-[15px] font-semibold leading-snug text-foreground transition-colors group-hover:text-primary"
        >
          {name}
        </h3>

        {showActions && (
          <div className="pointer-events-auto relative z-30 flex shrink-0 items-center gap-1.5">
            {(onVote || server.reputation) && (
              <div className="inline-flex h-7 items-center rounded-lg border border-border/70 bg-secondary/50 p-0.5 text-xs text-muted-foreground shadow-2xs backdrop-blur-xs">
                <button
                  type="button"
                  onClick={(e) => void handleVote(e, "up")}
                  disabled={!onVote || isVoting}
                  aria-label="Recommend app"
                  aria-pressed={server.reputation?.viewer_vote === "up"}
                  title={`Recommend: ${server.reputation?.up ?? 0}`}
                  className={clsx(
                    "inline-flex h-full items-center gap-1 rounded-md px-2 text-[11px] font-medium transition-all active:scale-95",
                    onVote ? "cursor-pointer" : "cursor-default",
                    server.reputation?.viewer_vote === "up"
                      ? "bg-primary text-primary-foreground shadow-xs font-semibold hover:bg-primary/90"
                      : "hover:bg-secondary hover:text-foreground"
                  )}
                >
                  <ThumbsUp className="size-3.5 shrink-0" />
                  <span className="tabular-nums">{server.reputation?.up ?? 0}</span>
                </button>

                <div className="my-1 h-3 w-px bg-border/70" />

                <button
                  type="button"
                  onClick={(e) => void handleVote(e, "down")}
                  disabled={!onVote || isVoting}
                  aria-label="Do not recommend app"
                  aria-pressed={server.reputation?.viewer_vote === "down"}
                  title={`Do not recommend: ${server.reputation?.down ?? 0}`}
                  className={clsx(
                    "inline-flex h-full items-center gap-1 rounded-md px-2 text-[11px] font-medium transition-all active:scale-95",
                    onVote ? "cursor-pointer" : "cursor-default",
                    server.reputation?.viewer_vote === "down"
                      ? "bg-destructive text-destructive-foreground shadow-xs font-semibold hover:bg-destructive/90"
                      : "hover:bg-secondary hover:text-foreground"
                  )}
                >
                  <ThumbsDown className="size-3.5 shrink-0" />
                  <span className="tabular-nums">{server.reputation?.down ?? 0}</span>
                </button>
              </div>
            )}

            {(onOpenComments || server.reputation?.comments !== undefined) && (
              onOpenComments ? (
                <button
                  type="button"
                  data-comments-trigger
                  onClick={(event) => {
                    event.preventDefault();
                    event.stopPropagation();
                    onOpenComments(server);
                  }}
                  aria-label="Comments"
                  title={`Comments: ${server.reputation?.comments ?? 0}`}
                  className="inline-flex h-7 items-center gap-1.5 rounded-lg border border-border/70 bg-secondary/50 px-2 text-[11px] font-medium text-muted-foreground shadow-2xs transition-all hover:bg-secondary hover:text-foreground active:scale-95 cursor-pointer"
                >
                  <MessageSquare className="size-3.5 shrink-0" />
                  <span className="tabular-nums">{server.reputation?.comments ?? 0}</span>
                </button>
              ) : (
                <span
                  className="inline-flex h-7 items-center gap-1.5 rounded-lg border border-border/70 bg-secondary/50 px-2 text-[11px] font-medium text-muted-foreground shadow-2xs"
                  title={`Comments: ${server.reputation?.comments ?? 0}`}
                >
                  <MessageSquare className="size-3.5 shrink-0" />
                  <span className="tabular-nums">{server.reputation?.comments ?? 0}</span>
                </span>
              )
            )}
          </div>
        )}
      </div>

      {children && (
        <div className="pointer-events-auto relative z-30 mt-3 border-t border-border pt-3">
          {children}
        </div>
      )}
    </article>
  );

  const isWarning = isReputationWarning(server.reputation);
  const detailPath = isWarning && serverId
    ? `/server/${encodeURIComponent(serverId)}`
    : (server.link || "#");

  return (
    <div className="group relative" title={description || undefined}>
      {cardBody}
      {isNavigable && (
        isWarning ? (
          <Link
            to={detailPath}
            state={server}
            aria-label={`Open ${name}`}
            className="absolute inset-0 z-10 cursor-pointer rounded-xl focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-primary"
          />
        ) : (
          <a
            href={server.link || "#"}
            aria-label={`Open ${name}`}
            className="absolute inset-0 z-10 cursor-pointer rounded-xl focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-primary"
          />
        )
      )}
    </div>
  );
}
