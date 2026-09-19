import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import clsx from "clsx";
import { BadgeDollarSign } from "lucide-react";
import type { BaseServer } from "@/hooks/useList";

interface ServerCardProps {
  server: BaseServer;
  isFavorite?: boolean;
  onToggleFavorite?: (serverId: string) => void;
  action?: ReactNode;
  children?: ReactNode;
  navigable?: boolean;
}

export function ServerCard({
  server,
  isFavorite = false,
  onToggleFavorite,
  action,
  children,
  navigable = true,
}: ServerCardProps) {
  const {
    id: serverId, name, description, tags, thumbnail, owner, online,
    firstSeen, tcpAddr, udpAddr, paymentEnabled = false, paymentLabel = "",
  } = server;
  const [thumbnailFailed, setThumbnailFailed] = useState(false);
  const [copiedProtocol, setCopiedProtocol] = useState<string | null>(null);
  const copyTimeoutRef = useRef<number | undefined>(undefined);
  const effectiveThumbnail = thumbnailFailed ? "" : thumbnail;
  const normalizedPaymentLabel = paymentLabel.trim();
  const showPaymentBadge = paymentEnabled || normalizedPaymentLabel !== "";
  const effectivePaymentLabel = normalizedPaymentLabel || "Paid app";
  const endpoints = [
    ...(tcpAddr ? [{ protocol: "TCP", address: tcpAddr }] : []),
    ...(udpAddr ? [{ protocol: "UDP", address: udpAddr }] : []),
  ];
  const isTransportService = endpoints.length > 0;
  const displayTags = [
    ...new Set([...tags, ...endpoints.map((endpoint) => endpoint.protocol)]),
  ];

  useEffect(() => {
    setThumbnailFailed(false);
  }, [thumbnail]);

  useEffect(() => () => window.clearTimeout(copyTimeoutRef.current), []);

  const handleFavoriteClick = (event: React.MouseEvent) => {
    event.preventDefault();
    event.stopPropagation();
    onToggleFavorite?.(serverId);
  };

  const copyEndpoint = async (protocol: string, address: string) => {
    if (!navigator.clipboard) return;

    try {
      await navigator.clipboard.writeText(address);
      setCopiedProtocol(protocol);
      window.clearTimeout(copyTimeoutRef.current);
      copyTimeoutRef.current = window.setTimeout(() => setCopiedProtocol(null), 1500);
    } catch {
      // Clipboard access can be denied outside a secure, user-initiated context.
    }
  };

  const formattedDuration = useMemo(() => {
    if (!firstSeen) return "";
    const start = new Date(firstSeen).getTime();
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
        "relative w-full overflow-hidden rounded-lg group border border-border bg-card shadow-sm transition-shadow hover:shadow-md dark:border-white/10",
        children ? "h-71.5" : "h-[174.5px]"
      )}
    >
      <div
        className="absolute inset-0 bg-cover bg-center transition-transform duration-700 group-hover:scale-105"
        style={{
          backgroundImage: effectiveThumbnail
            ? `url(${effectiveThumbnail})`
            : "linear-gradient(135deg, var(--card) 0%, var(--background) 100%)",
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

      <div className="absolute inset-0 bg-linear-to-t from-black/86 via-black/58 to-black/18" />

      <div className="relative z-10 flex h-full flex-col justify-between p-5">
        <div className="flex items-start justify-between gap-3">
          <div className="flex min-w-0 flex-wrap items-center gap-2">
            <div className="flex items-center gap-2 rounded-md bg-black/45 px-2.5 py-1 backdrop-blur-sm border border-white/8">
              <div
                className={clsx(
                  "size-2 rounded-full",
                  online
                    ? "bg-primary"
                    : "bg-gray-500"
                )}
              />
              <span
                className={clsx(
                  "text-[10px] font-bold uppercase tracking-wider",
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
                "flex size-8 items-center justify-center rounded-md backdrop-blur-md transition-colors border border-white/8 cursor-pointer",
                isFavorite
                  ? "bg-primary text-black"
                  : "bg-black/40 text-white/70 hover:bg-primary hover:text-black"
              )}
              aria-label={
                isFavorite ? "Remove from favorites" : "Add to favorites"
              }
            >
              <svg
                xmlns="http://www.w3.org/2000/svg"
                viewBox="0 0 24 24"
                className="w-4.5 h-4.5"
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
            <div className="flex flex-col gap-1.5 flex-1 min-w-0">
              <h3 className="font-display text-xl font-bold leading-tight text-white truncate">
                {name}
              </h3>

              {description && (
                <p className="text-xs text-white/70 line-clamp-1 font-medium">
                  {description}
                </p>
              )}

              {displayTags.length > 0 && (
                <div className="mt-1 w-full overflow-x-auto overflow-y-hidden overscroll-x-contain [scrollbar-width:none] [&::-webkit-scrollbar]:hidden">
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
                        className="shrink-0 rounded-md border border-white/20 bg-black/40 px-2 py-1 text-[10px] font-bold text-white transition-colors hover:bg-primary hover:text-black focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-primary"
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

            {!children && effectiveThumbnail && (
              <div className="shrink-0">
                <div className="size-10 overflow-hidden rounded-md border border-white/20 shadow-sm">
                  <img
                    alt={`${name} avatar`}
                    className="h-full w-full object-cover"
                    src={effectiveThumbnail}
                    onError={() => setThumbnailFailed(true)}
                  />
                </div>
              </div>
            )}
          </div>

          {children}
        </div>
      </div>
    </article>
  );

  return navigable && endpoints.length === 0 ? (
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
      }}
      className="relative cursor-pointer block"
    >
      {cardBody}
    </Link>
  ) : (
    <div className="relative">{cardBody}</div>
  );
}
