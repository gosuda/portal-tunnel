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

/**
 * Canonical Ethereum Blockies generator (https://github.com/ethereum/blockies).
 * Creates an 8x8 symmetric matrix of HSL color values seeded from the input string.
 */
export function createBlockiesData(seed: string): string[][] {
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

  function createColor(): string {
    const h = Math.floor(rand() * 360);
    const s = Math.floor(rand() * 60 + 40);
    const l = Math.floor((rand() + rand() + rand() + rand()) * 25);
    return `hsl(${h}, ${s}%, ${l}%)`;
  }

  // Canonical ethereum/blockies order: color (primary) -> bgcolor -> spotcolor
  const color = createColor();
  const bgcolor = createColor();
  const spotcolor = createColor();

  const size = 8;
  const dataWidth = Math.ceil(size / 2);
  const mirrorWidth = size - dataWidth;

  const grid: string[][] = [];

  for (let y = 0; y < size; y += 1) {
    const row: number[] = [];
    for (let x = 0; x < dataWidth; x += 1) {
      row[x] = Math.floor(rand() * 2.3);
    }
    const r = row.slice(0, mirrorWidth).reverse();
    const fullRow = row.concat(r);

    grid.push(
      fullRow.map((val) => {
        if (val === 1) return color;
        if (val === 2) return spotcolor;
        return bgcolor;
      })
    );
  }

  return grid;
}

export function DefaultServerThumbnail({
  server,
  hasAction = false,
}: {
  server: BaseServer;
  hasAction?: boolean;
}) {
  const patternId = useId();
  const seed = (server.address || server.name || server.id || "portal").trim();
  const grid = useMemo(() => createBlockiesData(seed), [seed]);
  const isTransport = Boolean(server.tcpAddr || server.udpAddr);

  const displayAddress = useMemo(() => {
    if (!server.address) return null;
    const addr = server.address.trim();
    if (addr.startsWith("0x") && addr.length > 10) {
      return `${addr.slice(0, 6)}…${addr.slice(-4)}`;
    }
    if (addr.length > 12) {
      return `${addr.slice(0, 6)}…${addr.slice(-4)}`;
    }
    return addr;
  }, [server.address]);

  return (
    <div
      className={clsx(
        "absolute inset-0 flex items-center justify-center bg-secondary/60 dark:bg-[#0c1017] select-none overflow-hidden transition-transform duration-300 ease-out motion-safe:group-hover:scale-[1.02]",
        isTransport ? "pb-12" : ""
      )}
      aria-hidden="true"
    >
      {/* 1. Ambient Blurred Backdrop Generated from Blockies Palette */}
      <div className="pointer-events-none absolute inset-0 overflow-hidden">
        <svg
          viewBox="0 0 8 8"
          className="h-full w-full scale-150 blur-3xl opacity-35 dark:opacity-40"
          preserveAspectRatio="none"
        >
          {grid.map((row, y) =>
            row.map((fill, x) => (
              <rect key={`bg-${x}-${y}`} x={x} y={y} width={1} height={1} fill={fill} />
            ))
          )}
        </svg>
      </div>

      {/* 2. Subtle Engineering Dot Grid Wallpaper */}
      <svg
        className="pointer-events-none absolute inset-0 h-full w-full opacity-35 dark:opacity-20"
        xmlns="http://www.w3.org/2000/svg"
      >
        <defs>
          <pattern id={patternId} width="20" height="20" patternUnits="userSpaceOnUse">
            <circle cx="2" cy="2" r="1" fill="currentColor" className="text-foreground/20 dark:text-white/20" />
          </pattern>
        </defs>
        <rect width="100%" height="100%" fill={`url(#${patternId})`} />
      </svg>

      {/* 3. Top-Right Cryptographic Identity Address Chip */}
      {displayAddress && (
        <div
          title={server.address}
          className={clsx(
            "pointer-events-none absolute top-2.5 z-10 inline-flex items-center gap-1.5 rounded-full border border-black/10 dark:border-white/15 bg-background/75 dark:bg-black/60 px-2.5 py-0.5 text-[10px] font-mono font-medium text-foreground/80 dark:text-white/80 shadow-2xs backdrop-blur-md transition-all duration-300",
            hasAction ? "right-12" : "right-2.5"
          )}
        >
          <span className="size-1.5 rounded-full bg-emerald-500 shadow-[0_0_6px_rgba(16,185,129,0.8)]" />
          <span>{displayAddress}</span>
        </div>
      )}

      {/* 4. Centered Blockies App Icon Badge */}
      <div className="relative z-10 size-24 shrink-0 rounded-2xl overflow-hidden shadow-xl border border-black/10 dark:border-white/20 ring-4 ring-black/5 dark:ring-white/10 transition-transform duration-300 motion-safe:group-hover:scale-105">
        <svg
          viewBox="0 0 8 8"
          className="h-full w-full"
          shapeRendering="crispEdges"
        >
          {grid.map((row, y) =>
            row.map((fill, x) => (
              <rect key={`${x}-${y}`} x={x} y={y} width={1} height={1} fill={fill} />
            ))
          )}
        </svg>
      </div>
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
  // The thumbnail that failed to load; a new thumbnail URL gets its own try.
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
      {/* 1. Thumbnail Container (16:9 aspect ratio) */}
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
          <DefaultServerThumbnail
            server={server}
            hasAction={Boolean(action || (server.reputation && isHiddenByVotes(server.reputation.up, server.reputation.down)))}
          />
        )}

        {/* Top-right custom action overlay */}
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

        {/* Payment badge */}
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

        {/* Online LIVE badge */}
        {online && !isTransportService && (
          <span className="absolute bottom-2.5 right-2.5 inline-flex items-center gap-1.5 rounded bg-black/80 px-2 py-0.5 text-[11px] font-bold tracking-wider text-emerald-400 backdrop-blur-xs">
            <span className="size-1.5 rounded-full bg-emerald-400 animate-pulse" />
            LIVE
          </span>
        )}

        {/* Description overlay on hover or focus-within */}
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

        {/* Raw transport endpoints (TCP / UDP) */}
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

      {/* 2. Details Container: Title (left) + Southeast Actions (Up, Down, Comments) (right) */}
      <div className={clsx("mt-2.5 flex items-center justify-between gap-2", isNavigable ? "pointer-events-none" : "")}>
        {/* Title */}
        <h3
          title={name}
          className="min-w-0 flex-1 truncate text-[15px] font-semibold leading-snug text-foreground transition-colors group-hover:text-primary"
        >
          {name}
        </h3>

        {/* Southeast actions: Upvotes, Downvotes, Comments */}
        {showActions && (
          <div className="pointer-events-auto relative z-30 flex shrink-0 items-center gap-1.5">
            {/* Rating Pill: [ 👍 12 | 👎 3 ] */}
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

            {/* Comments Button: [ 💬 5 ] */}
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

      {/* Children slot (e.g. Admin controls) */}
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
