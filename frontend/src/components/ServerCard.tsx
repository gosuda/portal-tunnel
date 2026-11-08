import { useMemo, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import clsx from "clsx";
import { BadgeDollarSign, Info, MessageSquare, ThumbsDown, ThumbsUp, X } from "lucide-react";
import type { BaseServer } from "@/lib/server";
import type { ReputationVoteAction } from "@/types/api";
import { useCopy } from "@/hooks/useCopy";
import { isHiddenByVotes, isReputationWarning } from "@/utils/reputation";

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
    id: serverId, name, description, tags, thumbnail, owner, online,
    firstSeen, tcpAddr, udpAddr, paymentEnabled = false, paymentLabel = "",
  } = server;
  // The thumbnail that failed to load; a new thumbnail URL gets its own try.
  const [failedThumbnail, setFailedThumbnail] = useState<string | null>(null);
  const [isVoting, setIsVoting] = useState(false);
  const [showDetails, setShowDetails] = useState(false);
  const { copiedKey: copiedProtocol, copy } = useCopy(1500);
  const hasDetails = Boolean(description || (tags && tags.length > 0));
  const effectiveThumbnail = failedThumbnail === thumbnail ? "" : thumbnail.trim();
  const resolvedThumbnail =
    effectiveThumbnail || pickPlaceholderThumbnail(name || serverId);
  const normalizedPaymentLabel = paymentLabel.trim();
  const showPaymentBadge = paymentEnabled || normalizedPaymentLabel !== "";
  const effectivePaymentLabel = normalizedPaymentLabel || "Paid app";
  const endpoints = [
    ...(tcpAddr ? [{ protocol: "TCP", address: tcpAddr }] : []),
    ...(udpAddr ? [{ protocol: "UDP", address: udpAddr }] : []),
  ];
  const isTransportService = endpoints.length > 0;
  const isNavigable = navigable && !isTransportService;

  const copyEndpoint = (protocol: string, address: string) =>
    copy(address, protocol);

  const formattedDuration = useMemo(() => {
    if (!firstSeen) return "";
    const start = new Date(firstSeen).getTime();
    if (Number.isNaN(start)) {
      return firstSeen;
    }
    const now = Date.now();
    const diff = Math.max(0, now - start);

    const seconds = Math.floor(diff / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);

    if (days > 0) return `${days}d ago`;
    if (hours > 0) return `${hours}h ago`;
    if (minutes > 0) return `${minutes}m ago`;
    return `${seconds}s ago`;
  }, [firstSeen]);

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
      <div className="relative aspect-video w-full overflow-hidden rounded-xl bg-muted">
        <img
          src={resolvedThumbnail}
          alt=""
          loading="lazy"
          className="absolute inset-0 h-full w-full object-cover transition-transform duration-300 ease-out motion-safe:group-hover:scale-[1.03]"
          onError={effectiveThumbnail ? () => setFailedThumbnail(thumbnail) : undefined}
        />

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

        {/* Touch / Click Disclosure Toggle Button */}
        {hasDetails && (
          <button
            type="button"
            onClick={(event) => {
              event.preventDefault();
              event.stopPropagation();
              setShowDetails((prev) => !prev);
            }}
            aria-label={showDetails ? "Hide description" : "Show description"}
            aria-expanded={showDetails}
            title={showDetails ? "Hide description" : "Show description"}
            className={clsx(
              "pointer-events-auto absolute z-30 flex size-7 items-center justify-center rounded-full text-white/90 backdrop-blur-md transition-all active:scale-95 cursor-pointer shadow-xs",
              isTransportService && showPaymentBadge ? "top-2.5 left-28" : "top-2.5 left-2.5",
              showDetails
                ? "bg-black/90 text-white ring-1 ring-white/30"
                : "bg-black/60 hover:bg-black/80 hover:text-white"
            )}
          >
            {showDetails ? (
              <X className="size-3.5 shrink-0" />
            ) : (
              <Info className="size-3.5 shrink-0" />
            )}
          </button>
        )}

        {/* Description overlay on hover, focus-within, or touch disclosure */}
        {hasDetails && (
          <div
            onClick={
              showDetails
                ? (event) => {
                    event.preventDefault();
                    event.stopPropagation();
                    setShowDetails(false);
                  }
                : undefined
            }
            className={clsx(
              "absolute inset-0 z-20 flex flex-col justify-end bg-gradient-to-t from-black/95 via-black/85 to-black/40 p-3.5 transition-opacity duration-200",
              isTransportService ? "pb-16" : "",
              showDetails
                ? "pointer-events-auto opacity-100 cursor-pointer"
                : "pointer-events-none opacity-0 group-hover:opacity-100 group-focus-within:opacity-100"
            )}
          >
            {description && (
              <>
                <div className="mb-1 flex items-center justify-between">
                  <span className="text-[10px] font-semibold uppercase tracking-wider text-white/60">
                    Description
                  </span>
                  {showDetails && (
                    <span className="text-[10px] text-white/50">Tap to close</span>
                  )}
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
          <div className="absolute inset-x-2.5 bottom-2.5 space-y-1 rounded-lg border border-white/10 bg-black/80 p-2 backdrop-blur-md">
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
                  className="pointer-events-auto relative z-30 shrink-0 rounded bg-white/20 px-2 py-0.5 text-[11px] font-semibold text-white transition-colors hover:bg-primary hover:text-primary-foreground focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-primary"
                >
                  {copiedProtocol === endpoint.protocol ? "Copied!" : `Copy ${endpoint.protocol}`}
                </button>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* 2. Details Container: Title/Metadata + Southeast Actions (Up, Down, Comments) */}
      <div className={clsx("mt-2.5 flex flex-col gap-1.5", isNavigable ? "pointer-events-none" : "")}>
        {/* Title */}
        <h3
          title={name}
          className="line-clamp-2 break-words text-[15px] font-semibold leading-snug text-foreground transition-colors group-hover:text-primary"
        >
          {name}
        </h3>

        {/* Bottom row: Metadata (left) + Southeast stats (right) */}
        <div className="flex items-center justify-between gap-2 text-xs text-muted-foreground">
          {/* Owner and duration */}
          <div className="flex min-w-0 items-center gap-1.5 truncate">
            {owner && (
              <span className="truncate font-medium text-muted-foreground hover:text-foreground">
                {owner}
              </span>
            )}
            {owner && formattedDuration && <span className="shrink-0">•</span>}
            {formattedDuration && (
              <span className="shrink-0">{formattedDuration}</span>
            )}
          </div>

          {/* Southeast actions: Upvotes, Downvotes, Comments */}
          <div className="pointer-events-auto relative z-30 flex shrink-0 items-center gap-1.5">
            {/* Rating Pill: [ 👍 12 | 👎 3 ] */}
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

            {/* Comments Button: [ 💬 5 ] */}
            {onOpenComments ? (
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
            )}
          </div>
        </div>
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
