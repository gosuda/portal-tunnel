import { useEffect, useRef, useState } from "react";
import { BadgeDollarSign, Check, Copy, ExternalLink, Globe, MessageSquare, MoreHorizontal, Terminal, ThumbsDown, ThumbsUp } from "lucide-react";
import { WebAppLink, AppThumbnail } from "@/components/list/AppParts";
import { Badge } from "@/components/ui/chip";
import { useCopy } from "@/hooks/useCopy";
import { cn } from "@/lib/utils";
import type { BaseServer } from "@/lib/server";
import type { ReputationVoteAction } from "@/types/api";
import { isHiddenByVotes } from "@/utils/reputation";

export type TileVariant = "wide" | "small";

export interface TileHandlers {
  onOpenComments: (server: BaseServer) => void;
  onVote?: (hostname: string, vote: ReputationVoteAction) => void | Promise<void>;
}

interface AppTileProps extends TileHandlers {
  server: BaseServer;
  variant?: TileVariant;
  className?: string;
}

const MENU_ITEM =
  "interactive flex h-10 w-full items-center gap-2 rounded-md px-2 text-left type-label-medium text-content-emphasis disabled:cursor-default disabled:opacity-50";

export function AppTile({ server, variant = "wide", onOpenComments, onVote, className }: AppTileProps) {
  const {
    id: serverId, name, description, dns, online,
    tcpAddr, udpAddr, paymentEnabled = false, paymentLabel = "", reputation,
  } = server;
  const [isVoting, setIsVoting] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);
  const articleRef = useRef<HTMLElement>(null);
  const { copiedKey, copy } = useCopy(1500);

  const hoverable = variant === "wide";
  const showPaymentBadge = paymentEnabled || paymentLabel.trim() !== "";
  const endpoints = [
    ...(tcpAddr ? [{ protocol: "TCP", address: tcpAddr }] : []),
    ...(udpAddr ? [{ protocol: "UDP", address: udpAddr }] : []),
  ];
  const isTransportService = endpoints.length > 0;
  const hasAddress = isTransportService || dns !== "";

  const up = reputation?.up ?? 0;
  const down = reputation?.down ?? 0;
  const comments = reputation?.comments ?? 0;
  const approvalLabel = up + down === 0 ? "New" : `${Math.round((up / (up + down)) * 100)}%`;
  const viewerVote = reputation?.viewer_vote;

  useEffect(() => {
    if (!menuOpen) return;
    const close = (event: PointerEvent) => {
      if (!articleRef.current?.contains(event.target as Node)) setMenuOpen(false);
    };
    document.addEventListener("pointerdown", close);
    return () => document.removeEventListener("pointerdown", close);
  }, [menuOpen]);

  const handleVote = async (targetVote: "up" | "down") => {
    if (!onVote || isVoting) return;
    setIsVoting(true);
    try {
      const nextVote: ReputationVoteAction = viewerVote === targetVote ? "clear" : targetVote;
      await onVote(serverId || reputation?.hostname || "", nextVote);
    } catch (err) {
      console.error("Failed to vote from card", err);
    } finally {
      setIsVoting(false);
    }
  };

  const face = (
    <>
      <div className={cn("relative w-full overflow-hidden rounded-md bg-surface-200", hasAddress && "rounded-b-none", variant === "small" ? "aspect-square" : "aspect-video")}>
        <AppThumbnail server={server} className="absolute inset-0" />
        <div className="absolute inset-x-2 top-2 flex flex-wrap items-center gap-1 pr-10">
          {isTransportService ? (
            <Badge tone="overlay"><Terminal className="size-3.5" />{endpoints.map((e) => e.protocol).join(" / ")}</Badge>
          ) : (
            online && (
              <Badge tone="overlay" className="text-success">
                <span className="size-1.5 rounded-full bg-success motion-safe:animate-pulse" />
                LIVE
              </Badge>
            )
          )}
          {reputation && isHiddenByVotes(up, down) && <Badge tone="overlay">Hidden by downvotes</Badge>}
        </div>
        {showPaymentBadge && (
          <Badge tone="overlay" className="absolute bottom-2 left-2 max-w-[calc(100%-1rem)]">
            <BadgeDollarSign className="size-3.5 shrink-0 text-success" />
            <span className="truncate">{paymentLabel.trim() || "Paid app"}</span>
          </Badge>
        )}
      </div>
      {isTransportService ? (
        <div className="flex flex-col divide-y divide-stroke overflow-hidden rounded-b-md bg-surface-200">
          {endpoints.map((endpoint) => (
            <div key={endpoint.protocol} className="flex min-w-0 items-center gap-1 pl-2">
              <code className="min-w-0 flex-1 truncate font-mono type-body-small text-content-emphasis" title={endpoint.address}>
                {endpoint.address}
              </code>
              <button
                type="button"
                onClick={() => void copy(endpoint.address, endpoint.protocol)}
                aria-label={`Copy ${endpoint.protocol} address`}
                className="interactive flex size-8 shrink-0 items-center justify-center rounded-md text-content-emphasis"
              >
                {copiedKey === endpoint.protocol ? <Check className="size-4 text-success" /> : <Copy className="size-4" />}
              </button>
            </div>
          ))}
        </div>
      ) : (
        dns !== "" && (
          <div className="flex h-8 min-w-0 items-center gap-1.5 rounded-b-md bg-surface-200 px-2">
            <Globe className="size-3.5 shrink-0 text-content-muted" />
            <code className="min-w-0 flex-1 truncate font-mono type-body-small text-content-emphasis" title={dns}>
              {dns}
            </code>
          </div>
        )
      )}
      <h3
        title={name}
        className={cn("mt-2 text-content-emphasis", variant === "small" ? "line-clamp-2 break-words type-title-medium" : "truncate type-title-large")}
      >
        {name}
      </h3>
      <div className={cn("flex items-center gap-1 text-content-muted", variant === "small" ? "mt-0.5 type-body-small" : "mt-1 h-5 type-body-medium")}>
        <ThumbsUp className={variant === "small" ? "size-3 shrink-0" : "size-4 shrink-0"} />
        <span>{approvalLabel}</span>
      </div>
    </>
  );

  const faceClass = "block rounded-md";

  return (
    <article
      ref={articleRef}
      title={description || undefined}
      onKeyDown={(event) => {
        if (event.key === "Escape") setMenuOpen(false);
      }}
      className={cn("group relative min-w-0", hoverable && "hover:z-20 focus-within:z-20", menuOpen && "z-20", className)}
    >
      {hoverable && (
        <div
          aria-hidden="true"
          className={cn(
            "pointer-events-none absolute -inset-3 rounded-lg bg-surface-300 opacity-0 transition-opacity duration-150 delay-150 ease-standard motion-reduce:transition-none",
            "group-hover:opacity-100 group-hover:delay-100 group-hover:duration-200 group-hover:ease-out-soft",
            "group-focus-within:opacity-100 group-focus-within:delay-0 group-focus-within:duration-200 group-focus-within:ease-out-soft",
            menuOpen && "opacity-100"
          )}
        />
      )}
      <div className="relative">
        {isTransportService ? (
          <div className={faceClass}>{face}</div>
        ) : (
          <WebAppLink server={server} className={faceClass}>{face}</WebAppLink>
        )}

        {hoverable && (
          <>
            <div
              className={cn(
                "absolute right-2 top-2 z-10 opacity-0 transition-opacity duration-150 group-hover:opacity-100 group-focus-within:opacity-100 [@media(hover:none)]:opacity-100 motion-reduce:transition-none",
                menuOpen && "opacity-100"
              )}
            >
              <button
                type="button"
                aria-label={`More options for ${name}`}
                aria-haspopup="true"
                aria-expanded={menuOpen}
                onClick={() => setMenuOpen(!menuOpen)}
                className="interactive flex size-8 items-center justify-center rounded-full bg-surface-0/90 text-content-emphasis"
              >
                <MoreHorizontal className="size-5" />
              </button>
            </div>
            {menuOpen && (
              <div className="absolute right-2 top-11 z-20 w-52 rounded-lg border border-stroke bg-surface-100 p-1">
                {!isTransportService && (
                  <WebAppLink server={server} className={MENU_ITEM}>
                    <ExternalLink className="size-4 shrink-0" />
                    <span className="flex-1">Open</span>
                  </WebAppLink>
                )}
                <button
                  type="button"
                  onClick={() => {
                    setMenuOpen(false);
                    onOpenComments(server);
                  }}
                  aria-label="Comments"
                  className={MENU_ITEM}
                >
                  <MessageSquare className="size-4 shrink-0" />
                  <span className="flex-1">Comments</span>
                  <span className="type-body-small tabular-nums text-content-muted">{comments}</span>
                </button>
                <button
                  type="button"
                  onClick={() => void handleVote("up")}
                  disabled={!onVote || isVoting}
                  aria-label="Recommend app"
                  aria-pressed={viewerVote === "up"}
                  className={cn(MENU_ITEM, viewerVote === "up" && "bg-state-hover")}
                >
                  <ThumbsUp className="size-4 shrink-0" />
                  <span className="flex-1">Recommend</span>
                  <span className="type-body-small tabular-nums text-content-muted">{up}</span>
                </button>
                <button
                  type="button"
                  onClick={() => void handleVote("down")}
                  disabled={!onVote || isVoting}
                  aria-label="Do not recommend app"
                  aria-pressed={viewerVote === "down"}
                  className={cn(MENU_ITEM, viewerVote === "down" && "bg-state-hover")}
                >
                  <ThumbsDown className="size-4 shrink-0" />
                  <span className="flex-1">Do not recommend</span>
                  <span className="type-body-small tabular-nums text-content-muted">{down}</span>
                </button>
              </div>
            )}
          </>
        )}
      </div>
    </article>
  );
}
