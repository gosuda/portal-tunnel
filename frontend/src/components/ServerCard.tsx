import { useEffect, useMemo, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import clsx from "clsx";
import { BadgeDollarSign, ThumbsDown, ThumbsUp } from "lucide-react";
import type { ReputationVote } from "@/types/api";
import type { BaseServer } from "@/hooks/useList";
import { useCopy } from "@/hooks/useCopy";

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
  isFavorite?: boolean;
  onToggleFavorite?: (serverId: string) => void;
  action?: ReactNode;
  children?: ReactNode;
  navigable?: boolean;
  onVote?: (hostname: string, vote: ReputationVote) => void | Promise<void>;
}

export function ServerCard({
  server,
  isFavorite = false,
  onToggleFavorite,
  action,
  children,
  navigable = true,
  onVote,
}: ServerCardProps) {
  const {
    id: serverId, name, description, tags, thumbnail, owner, online,
    firstSeen, tcpAddr, udpAddr, paymentEnabled = false, paymentLabel = "",
  } = server;
  const reputation = onVote ? server.reputation : undefined;
  const [thumbnailFailed, setThumbnailFailed] = useState(false);
  const { copiedKey: copiedProtocol, copy } = useCopy(1500);
  const [isVoting, setIsVoting] = useState(false);
  const [voteError, setVoteError] = useState("");
  const effectiveThumbnail = thumbnailFailed ? "" : thumbnail.trim();
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
  const displayTags = [
    ...new Set([...tags, ...endpoints.map((endpoint) => endpoint.protocol)]),
  ];

  useEffect(() => {
    setThumbnailFailed(false);
  }, [thumbnail]);


  const handleFavoriteClick = (event: React.MouseEvent) => {
    event.preventDefault();
    event.stopPropagation();
    onToggleFavorite?.(serverId);
  };

  // Voting must never navigate into the service, even though the whole card
  // can be a <Link>.
  const handleVoteClick = (vote: ReputationVote) => async (event: React.MouseEvent) => {
    event.preventDefault();
    event.stopPropagation();
    if (reputation) {
      if (!onVote || isVoting) return;
      setVoteError("");
      setIsVoting(true);
      try {
        await onVote(reputation.hostname, vote);
      } catch {
        setVoteError("Vote failed. Please try again.");
      } finally {
        setIsVoting(false);
      }
    }
  };

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

    if (days > 0) return `${days}d ${hours % 24}h`;
    if (hours > 0) return `${hours}h ${minutes % 60}m`;
    if (minutes > 0) return `${minutes}m`;
    return `${seconds}s`;
  }, [firstSeen]);

  const cardBody = (
    <article
      data-hero-key={`server-bg-${serverId}`}
      className={clsx(
        "relative w-full overflow-hidden rounded-[12px] group border border-black/10 bg-card shadow-sm dark:border-white/22 transition-shadow hover:shadow-md",
        children ? "h-71.5" : "h-[165px]"
      )}
    >
      <div
        className="absolute inset-0 bg-cover bg-center transition-transform duration-700 group-hover:scale-105"
        style={{
          backgroundImage: `url(${resolvedThumbnail})`,
        }}
      />
      {effectiveThumbnail && (
        <img
          alt=""
          aria-hidden="true"
          className="hidden"
          src={effectiveThumbnail}
          onError={() => setThumbnailFailed(true)}
        />
      )}

      <div className="absolute inset-0 bg-linear-to-t from-black/75 via-black/12 to-transparent" />

      <div
        className={clsx(
          "relative flex h-full flex-col justify-between p-[14px]",
          isNavigable ? "pointer-events-none z-30" : "z-10"
        )}
      >
        <div className="flex items-start justify-between gap-3">
          <div className="flex min-w-0 flex-wrap items-center gap-2">
            <div className="flex h-[32px] items-center gap-[8px] rounded-[8px] border border-white/15 bg-black/45 px-[12px] backdrop-blur-md">
              <div
                className={clsx(
                  "size-[8px] rounded-full",
                  online
                    ? "bg-green-status shadow-[0_0_8px_var(--green-status)]"
                    : "bg-gray-500"
                )}
              />
              <span
                className={clsx(
                  "text-[11px] font-bold uppercase tracking-[0.06em]",
                  online ? "text-white" : "text-white/60"
                )}
              >
                {online ? (isTransportService ? "Live" : "Online") : "Offline"}
                {formattedDuration && online && ` · ${formattedDuration}`}
              </span>
            </div>

            {showPaymentBadge && (
              <div className="inline-flex max-w-[8.5rem] items-center gap-1.5 rounded-md border border-amber-300/25 bg-amber-300/18 px-2.5 py-1 text-[10px] font-bold uppercase tracking-normal text-amber-100 backdrop-blur-sm">
                <BadgeDollarSign className="size-3 shrink-0" />
                <span className="min-w-0 truncate">{effectivePaymentLabel}</span>
              </div>
            )}
          </div>

          {action ?? (
            <button
              onClick={handleFavoriteClick}
              className={clsx(
                "pointer-events-auto relative z-30 flex size-[34px] items-center justify-center rounded-[8px] backdrop-blur-md transition-colors border border-white/15 cursor-pointer",
                isFavorite
                  ? "bg-primary text-primary-foreground"
                  : "bg-black/45 text-white/85 hover:bg-primary hover:text-primary-foreground"
              )}
              aria-label={
                isFavorite ? "Remove from favorites" : "Add to favorites"
              }
            >
              <svg
                xmlns="http://www.w3.org/2000/svg"
                viewBox="0 0 24 24"
                className="w-4 h-4"
                fill={isFavorite ? "currentColor" : "none"}
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
              >
                <polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2" />
              </svg>
            </button>
          )}
        </div>

        <div className="flex flex-col gap-3">
          <div className="flex items-end justify-between gap-3">
            <div className="flex flex-col gap-0.5 flex-1 min-w-0">
              <h3 className="min-w-0 truncate font-display text-[19px] font-extrabold leading-tight text-white">
                {name}
              </h3>

              {voteError && (
                <span role="alert" className="text-[10px] text-red-400">
                  {voteError}
                </span>
              )}

              {description && (
                <p className="text-[12px] text-white/80 line-clamp-1 font-medium">
                  {description}
                </p>
              )}

              {displayTags.length > 0 && (
                <div className="pointer-events-auto relative z-30 mt-1 w-full overflow-x-auto overflow-y-hidden overscroll-x-contain [scrollbar-width:none] [&::-webkit-scrollbar]:hidden">
                  <div className="flex min-w-max gap-1.5">
                    {displayTags.map((tag, index) => (
                      <span
                        key={index}
                        className="rounded-sm bg-primary/16 px-2 py-0.5 text-[10px] font-bold uppercase tracking-normal text-primary border border-primary/24 whitespace-nowrap"
                      >
                        #{tag}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {isTransportService && (
                <div className="min-w-0 space-y-1 text-sm font-medium text-white/90">
                  {endpoints.map((endpoint) => (
                    <div key={endpoint.protocol} className="flex items-center gap-2">
                      <code className="min-w-0 flex-1 truncate font-mono tracking-tight">
                        {endpoint.address}
                      </code>
                      <button
                        type="button"
                        onClick={() => void copyEndpoint(endpoint.protocol, endpoint.address)}
                        className="shrink-0 rounded-md border border-white/20 bg-black/40 px-2 py-1 text-[10px] font-bold text-white transition-colors hover:bg-primary hover:text-primary-foreground focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-primary"
                      >
                        {copiedProtocol === endpoint.protocol
                          ? "Copied!"
                          : `Copy ${endpoint.protocol}`}
                      </button>
                    </div>
                  ))}
                </div>
              )}

              {owner && (
                <span className="text-[10px] font-medium text-white/50">
                  by {owner}
                </span>
              )}
            </div>

            {reputation && (
              <div
                className="pointer-events-auto relative z-30 flex shrink-0 items-center gap-[8px]"
                aria-busy={isVoting}
              >
                <button
                  type="button"
                  onClick={handleVoteClick("up")}
                  disabled={isVoting}
                  aria-label="Recommend"
                  className={clsx(
                    "flex h-[28px] items-center gap-[6px] rounded-[6px] border px-[10px] text-[11px] font-bold backdrop-blur-md transition-colors",
                    isVoting ? "cursor-not-allowed opacity-50" : "cursor-pointer",
                    reputation.viewer_vote === "up"
                      ? "border-primary/60 bg-primary/90 text-primary-foreground"
                      : "border-white/15 bg-black/45 text-white/90 hover:bg-primary hover:text-primary-foreground"
                  )}
                >
                  <ThumbsUp className="size-[13px] shrink-0" />
                  <span>{reputation.up}</span>
                </button>
                <button
                  type="button"
                  onClick={handleVoteClick("down")}
                  disabled={isVoting}
                  aria-label="Do not recommend"
                  className={clsx(
                    "flex h-[28px] items-center gap-[6px] rounded-[6px] border px-[10px] text-[11px] font-bold backdrop-blur-md transition-colors",
                    isVoting ? "cursor-not-allowed opacity-50" : "cursor-pointer",
                    reputation.viewer_vote === "down"
                      ? "border-primary/60 bg-primary/90 text-primary-foreground"
                      : "border-white/15 bg-black/45 text-white/90 hover:bg-primary hover:text-primary-foreground"
                  )}
                >
                  <ThumbsDown className="size-[13px] shrink-0" />
                  <span>{reputation.down}</span>
                </button>
              </div>
            )}
          </div>

          {children}
        </div>
      </div>
    </article>
  );

  return (
    <div className="relative">
      {cardBody}
      {isNavigable && (
        <Link
          to={server.link || "#"}
          state={{
            id: server.id,
            name: server.name,
            description: server.description,
            tags: server.tags,
            thumbnail: resolvedThumbnail,
            owner: server.owner,
            online: server.online,
            serverUrl: server.link,
            paymentEnabled: server.paymentEnabled,
            paymentLabel: server.paymentLabel,
            reputation: server.reputation,
          }}
          aria-label={`Open ${name}`}
          className="absolute inset-0 z-20 cursor-pointer rounded-lg focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-primary"
        />
      )}
    </div>
  );
}
