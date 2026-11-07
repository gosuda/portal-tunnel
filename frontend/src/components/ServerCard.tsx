import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import clsx from "clsx";
import { BadgeDollarSign, Menu, MessageSquare } from "lucide-react";
import type { BaseServer } from "@/hooks/useList";
import { useCopy } from "@/hooks/useCopy";
import { isHiddenByVotes } from "@/utils/reputation";

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
}

export function ServerCard({
  server,
  action,
  children,
  navigable = true,
  onOpenComments,
}: ServerCardProps) {
  const {
    id: serverId, name, description, tags, thumbnail, owner, online,
    firstSeen, tcpAddr, udpAddr, paymentEnabled = false, paymentLabel = "",
  } = server;
  const [thumbnailFailed, setThumbnailFailed] = useState(false);
  const { copiedKey: copiedProtocol, copy } = useCopy(1500);
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
  const detailsRef = useRef<HTMLDetailsElement | null>(null);

  useEffect(() => {
    setThumbnailFailed(false);
  }, [thumbnail]);

  useEffect(() => {
    const handleOutsideClick = (event: PointerEvent) => {
      const details = detailsRef.current;
      if (details?.open && !details.contains(event.target as Node)) {
        details.removeAttribute("open");
      }
    };

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape" && detailsRef.current?.open) {
        detailsRef.current.removeAttribute("open");
      }
    };

    document.addEventListener("pointerdown", handleOutsideClick);
    document.addEventListener("keydown", handleKeyDown);
    return () => {
      document.removeEventListener("pointerdown", handleOutsideClick);
      document.removeEventListener("keydown", handleKeyDown);
    };
  }, []);

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

  const cardBody = (
    <article data-hero-key={`server-bg-${serverId}`} className="relative w-full min-w-0">
      {/* 1. Thumbnail Container (16:9 aspect ratio) */}
      <div className="relative aspect-video w-full overflow-hidden rounded-xl bg-muted">
        <img
          src={resolvedThumbnail}
          alt=""
          loading="lazy"
          className="absolute inset-0 h-full w-full object-cover transition-transform duration-300 ease-out motion-safe:group-hover:scale-[1.03]"
          onError={effectiveThumbnail ? () => setThumbnailFailed(true) : undefined}
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

      {/* 2. Details Container: (Title/Desc) + Right Actions */}
      <div className={clsx("mt-3 flex items-start justify-between gap-3", isNavigable ? "pointer-events-none" : "")}>
        {/* Title and Short Metadata */}
        <div className="flex min-w-0 flex-1 flex-col">
          <h3
            title={name}
            className="line-clamp-2 break-words text-[15px] font-semibold leading-snug text-foreground transition-colors group-hover:text-primary"
          >
            {name}
          </h3>

          {(owner || formattedDuration) && (
            <div className="mt-1 flex items-center gap-1.5 truncate text-xs text-muted-foreground">
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
          )}
        </div>

        {/* Right Actions: Comments + Hamburger Details */}
        <div className="pointer-events-auto relative z-30 flex shrink-0 items-center gap-1.5 pt-0.5">
          {onOpenComments && (
            <button
              type="button"
              data-comments-trigger
              onClick={(event) => {
                event.preventDefault();
                event.stopPropagation();
                onOpenComments(server);
              }}
              aria-label="Comments"
              title="Comments"
              className="flex size-7.5 items-center justify-center rounded-lg border border-border/70 bg-secondary/60 text-foreground/80 transition-colors hover:bg-secondary hover:text-foreground"
            >
              <MessageSquare className="size-3.5" />
            </button>
          )}

          {/* Details menu */}
          <details ref={detailsRef} className="relative z-30 shrink-0">
            <summary
              aria-label={`Actions for ${name}`}
              title={`Actions for ${name}`}
              className="flex size-7.5 cursor-pointer list-none items-center justify-center rounded-lg border border-border/70 bg-secondary/60 text-muted-foreground transition-colors hover:bg-secondary hover:text-foreground [&::-webkit-details-marker]:hidden"
            >
              <Menu className="size-4" />
            </summary>
            <div className="absolute right-0 top-9 z-40 max-h-96 w-64 max-w-[calc(100vw-2rem)] overflow-y-auto rounded-xl border border-border bg-popover p-3 text-popover-foreground shadow-xl [scrollbar-width:thin]">
              {description && (
                <div className="border-b border-border/60 pb-2.5 mb-2.5">
                  <span className="mb-1 block text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
                    Description
                  </span>
                  <p className="text-xs leading-relaxed text-foreground/90 whitespace-pre-wrap break-words">
                    {description}
                  </p>
                </div>
              )}

              {tags && tags.length > 0 && (
                <div className="border-b border-border/60 pb-2.5 mb-2.5">
                  <span className="mb-1.5 block text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
                    Tags
                  </span>
                  <div className="flex flex-wrap gap-1">
                    {tags.map((tag) => (
                      <span
                        key={tag}
                        className="inline-flex items-center rounded-md bg-secondary px-2 py-0.5 text-[11px] font-medium text-secondary-foreground"
                      >
                        #{tag}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {owner && (
                <div className="border-b border-border/60 pb-2.5 mb-2.5">
                  <span className="mb-0.5 block text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
                    Owner
                  </span>
                  <p className="text-xs text-foreground/80">
                    {owner}
                  </p>
                </div>
              )}

              {!description && (!tags || tags.length === 0) && !owner && (
                <div className="border-b border-border/60 pb-2 mb-2 text-xs text-muted-foreground">
                  No additional details.
                </div>
              )}
            </div>
          </details>
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

  return (
    <div className="group relative">
      {cardBody}
      {isNavigable && (
        <Link
          to={server.link || "#"}
          state={{
            id: server.id,
            name: server.name,
            description: server.description,
            tags: server.tags,
            thumbnail: server.thumbnail,
            owner: server.owner,
            online: server.online,
            serverUrl: server.link,
            paymentEnabled: server.paymentEnabled,
            paymentLabel: server.paymentLabel,
            reputation: server.reputation,
          }}
          aria-label={`Open ${name}`}
          className="absolute inset-0 z-20 cursor-pointer rounded-xl focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-primary"
        />
      )}
    </div>
  );
}
