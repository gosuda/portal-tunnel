import { useState, type JSX, type ReactNode } from "react";
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
import { DefaultServerThumbnail } from "./ServerThumbnail";

function VoteButton({ direction, pressed, count, disabled, interactive, onSelect }: {
  direction: "up" | "down";
  pressed: boolean;
  count: number;
  disabled: boolean;
  interactive: boolean;
  onSelect: (event: React.MouseEvent, direction: "up" | "down") => void;
}): JSX.Element {
  const recommend = direction === "up";
  return (
    <button
      type="button"
      onClick={(event) => onSelect(event, direction)}
      disabled={disabled}
      aria-label={recommend ? "Recommend app" : "Do not recommend app"}
      aria-pressed={pressed}
      title={`${recommend ? "Recommend" : "Do not recommend"}: ${count}`}
      className={clsx(
        "inline-flex h-full items-center gap-1 rounded-md px-2 text-[11px] font-medium transition-all active:scale-95",
        interactive ? "cursor-pointer" : "cursor-default",
        pressed
          ? recommend
            ? "bg-primary text-primary-foreground shadow-xs font-semibold hover:bg-primary/90"
            : "bg-destructive text-destructive-foreground shadow-xs font-semibold hover:bg-destructive/90"
          : "hover:bg-secondary hover:text-foreground"
      )}
    >
      {recommend ? (
        <ThumbsUp className="size-3.5 shrink-0" />
      ) : (
        <ThumbsDown className="size-3.5 shrink-0" />
      )}
      <span className="tabular-nums">{count}</span>
    </button>
  );
}

function CommentsTrigger({ server, onOpenComments }: {
  server: BaseServer;
  onOpenComments?: (server: BaseServer) => void;
}): JSX.Element | null {
  if (!onOpenComments && server.reputation?.comments === undefined) {
    return null;
  }
  if (!onOpenComments) {
    return (
      <span
        className="inline-flex h-7 items-center gap-1.5 rounded-lg border border-border/70 bg-secondary/50 px-2 text-[11px] font-medium text-muted-foreground shadow-2xs"
        title={`Comments: ${server.reputation?.comments ?? 0}`}
      >
        <MessageSquare className="size-3.5 shrink-0" />
        <span className="tabular-nums">{server.reputation?.comments ?? 0}</span>
      </span>
    );
  }
  return (
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
  );
}

function TransportEndpointsPanel({ endpoints, copiedProtocol, onCopy }: {
  endpoints: { protocol: string; address: string }[];
  copiedProtocol: string | null;
  onCopy: (protocol: string, address: string) => void;
}): JSX.Element {
  return (
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
            onClick={() => void onCopy(endpoint.protocol, endpoint.address)}
            className="pointer-events-auto relative z-30 shrink-0 rounded bg-white/20 px-2 py-0.5 text-[11px] font-semibold text-white transition-colors hover:bg-primary hover:text-primary-foreground focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-primary cursor-pointer active:scale-95"
          >
            {copiedProtocol === endpoint.protocol ? "Copied!" : `Copy ${endpoint.protocol}`}
          </button>
        </div>
      ))}
    </div>
  );
}

function ServerHoverDetails({ description, tags, isTransportService, endpointCount }: {
  description?: string;
  tags?: string[];
  isTransportService: boolean;
  endpointCount: number;
}): JSX.Element {
  return (
    <div
      className={clsx(
        "pointer-events-none absolute inset-0 z-20 flex flex-col justify-end bg-gradient-to-t from-black/95 via-black/85 to-black/40 p-3.5 opacity-0 transition-opacity duration-200 group-hover:opacity-100 group-focus-within:opacity-100",
        isTransportService ? (endpointCount > 1 ? "pb-24" : "pb-18") : ""
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
  );
}
function buildEndpoints(tcpAddr: string | undefined, udpAddr: string | undefined): { protocol: string; address: string }[] {
  return [
    ...(tcpAddr ? [{ protocol: "TCP", address: tcpAddr }] : []),
    ...(udpAddr ? [{ protocol: "UDP", address: udpAddr }] : []),
  ];
}

function resolveVoteRequest(server: BaseServer, targetVote: "up" | "down"): { targetHost: string; nextVote: ReputationVoteAction } {
  const targetHost = server.id || server.reputation?.hostname || "";
  const nextVote: ReputationVoteAction = server.reputation?.viewer_vote === targetVote ? "clear" : targetVote;
  return { targetHost, nextVote };
}

function resolveDetailPath(server: BaseServer, serverId: string, isWarning: boolean): string {
  if (isWarning && serverId) {
    return `/server/${encodeURIComponent(serverId)}`;
  }
  return server.link || "#";
}

function CoverPanel({ server, effectiveThumbnail, action, showPaymentBadge, effectivePaymentLabel, isTransportService, hasDetails, description, tags, endpoints, copiedProtocol, onCopyEndpoint, onThumbnailError }: { server: BaseServer; effectiveThumbnail: string; action: ReactNode; showPaymentBadge: boolean; effectivePaymentLabel: string; isTransportService: boolean; hasDetails: boolean; description: string | undefined; tags: string[] | undefined; endpoints: { protocol: string; address: string }[]; copiedProtocol: string | null; onCopyEndpoint: (protocol: string, address: string) => void; onThumbnailError: () => void }): JSX.Element {
  return (
    <div className="relative aspect-video w-full overflow-hidden rounded-xl border border-border/70 dark:border-white/10 bg-muted shadow-2xs transition-all duration-300 ease-out group-hover:scale-[1.02] group-hover:border-border group-hover:shadow-md">
      {effectiveThumbnail ? (
        <img
          src={effectiveThumbnail}
          alt=""
          loading="lazy"
          className="absolute inset-0 h-full w-full object-cover transition-transform duration-300 ease-out motion-safe:group-hover:scale-[1.03]"
          onError={onThumbnailError}
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
      {server.online && !isTransportService && (
        <span className="absolute bottom-2.5 right-2.5 inline-flex items-center gap-1.5 rounded bg-black/80 px-2 py-0.5 text-[11px] font-bold tracking-wider text-emerald-400 backdrop-blur-xs">
          <span className="size-1.5 rounded-full bg-emerald-400 animate-pulse" />
          LIVE
        </span>
      )}
      {hasDetails && (
        <ServerHoverDetails
          description={description}
          tags={tags}
          isTransportService={isTransportService}
          endpointCount={endpoints.length}
        />
      )}
      {isTransportService && (
        <TransportEndpointsPanel
          endpoints={endpoints}
          copiedProtocol={copiedProtocol}
          onCopy={onCopyEndpoint}
        />
      )}
    </div>
  );
}

function VoteControls({ server, isVoting, onVote, onSelect }: { server: BaseServer; isVoting: boolean; onVote: ((hostname: string, vote: ReputationVoteAction) => void | Promise<void>) | undefined; onSelect: (event: React.MouseEvent, direction: "up" | "down") => void }): JSX.Element | null {
  if (!onVote && !server.reputation) {
    return null;
  }
  return (
    <div className="inline-flex h-7 items-center rounded-lg border border-border/70 bg-secondary/50 p-0.5 text-xs text-muted-foreground shadow-2xs backdrop-blur-xs">
      <VoteButton
        direction="up"
        pressed={server.reputation?.viewer_vote === "up"}
        count={server.reputation?.up ?? 0}
        disabled={!onVote || isVoting}
        interactive={Boolean(onVote)}
        onSelect={onSelect}
      />
      <div className="my-1 h-3 w-px bg-border/70" />
      <VoteButton
        direction="down"
        pressed={server.reputation?.viewer_vote === "down"}
        count={server.reputation?.down ?? 0}
        disabled={!onVote || isVoting}
        interactive={Boolean(onVote)}
        onSelect={onSelect}
      />
    </div>
  );
}

function TitleRow({ server, name, showActions, isNavigable, isVoting, onVote, onOpenComments, onSelectVote }: { server: BaseServer; name: string; showActions: boolean; isNavigable: boolean; isVoting: boolean; onVote: ((hostname: string, vote: ReputationVoteAction) => void | Promise<void>) | undefined; onOpenComments: ((server: BaseServer) => void) | undefined; onSelectVote: (event: React.MouseEvent, direction: "up" | "down") => void }): JSX.Element {
  return (
    <div className={clsx("mt-2.5 flex items-center justify-between gap-2", isNavigable ? "pointer-events-none" : "")}>
      <h3
        title={name}
        className="min-w-0 flex-1 truncate text-[15px] font-semibold leading-snug text-foreground transition-colors group-hover:text-primary"
      >
        {name}
      </h3>
      {showActions && (
        <div className="pointer-events-auto relative z-30 flex shrink-0 items-center gap-1.5">
          <VoteControls server={server} isVoting={isVoting} onVote={onVote} onSelect={onSelectVote} />
          <CommentsTrigger server={server} onOpenComments={onOpenComments} />
        </div>
      )}
    </div>
  );
}

function LinkOverlay({ isNavigable, isWarning, detailPath, server, name }: { isNavigable: boolean; isWarning: boolean; detailPath: string; server: BaseServer; name: string }): JSX.Element | null {
  if (!isNavigable) {
    return null;
  }
  if (isWarning) {
    return (
      <Link
        to={detailPath}
        state={server}
        aria-label={`Open ${name}`}
        className="absolute inset-0 z-10 cursor-pointer rounded-xl focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-primary"
      />
    );
  }
  return (
    <a
      href={server.link || "#"}
      aria-label={`Open ${name}`}
      className="absolute inset-0 z-10 cursor-pointer rounded-xl focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-primary"
    />
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
}: ServerCardProps): JSX.Element {
  const {
    id: serverId, name, description, tags, thumbnail,
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
  const endpoints = buildEndpoints(tcpAddr, udpAddr);
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
      const { targetHost, nextVote } = resolveVoteRequest(server, targetVote);
      await onVote(targetHost, nextVote);
    } catch (err) {
      console.error("Failed to vote from card", err);
    } finally {
      setIsVoting(false);
    }
  };

  const handleSelectVote = (event: React.MouseEvent, direction: "up" | "down") => void handleVote(event, direction);
  const handleThumbnailError = () => setFailedThumbnail(thumbnail);
  const isWarning = isReputationWarning(server.reputation);
  const detailPath = resolveDetailPath(server, serverId, isWarning);

  return (
    <div className="group relative" title={description || undefined}>
      <article className="relative w-full min-w-0">
        <CoverPanel server={server} effectiveThumbnail={effectiveThumbnail} action={action} showPaymentBadge={showPaymentBadge} effectivePaymentLabel={effectivePaymentLabel} isTransportService={isTransportService} hasDetails={hasDetails} description={description} tags={tags} endpoints={endpoints} copiedProtocol={copiedProtocol} onCopyEndpoint={copyEndpoint} onThumbnailError={handleThumbnailError} />
        <TitleRow server={server} name={name} showActions={showActions} isNavigable={isNavigable} isVoting={isVoting} onVote={onVote} onOpenComments={onOpenComments} onSelectVote={handleSelectVote} />
        {children && (
          <div className="pointer-events-auto relative z-30 mt-3 border-t border-border pt-3">
            {children}
          </div>
        )}
      </article>
      <LinkOverlay isNavigable={isNavigable} isWarning={isWarning} detailPath={detailPath} server={server} name={name} />
    </div>
  );
}
