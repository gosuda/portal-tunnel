import { SsgoiTransition } from "@ssgoi/react";
import { useEffect, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { BadgeDollarSign } from "lucide-react";
import { Button } from "@/components/ui/button";
import { openExternal } from "@/lib/navigate";
import type { ReputationSummary } from "@/types/api";
import { REPUTATION_ACK_PREFIX } from "@/types/storage";

interface ServerDetailState {
  id: string;
  name: string;
  description: string;
  tags: string[];
  thumbnail: string;
  owner: string;
  online: boolean;
  serverUrl: string;
  paymentEnabled?: boolean;
  paymentLabel?: string;
  reputation?: ReputationSummary;
}

export function ServerDetail() {
  const location = useLocation();
  const navigate = useNavigate();
  const server = location.state as ServerDetailState;

  // A warned service stops auto-opening until the visitor acknowledges it for
  // this browser session (per-tab, like the isPush bfcache flag).
  const [acknowledged, setAcknowledged] = useState(() => {
    try {
      return (
        server?.reputation?.warning === true &&
        sessionStorage.getItem(`${REPUTATION_ACK_PREFIX}${server.id}`) === "1"
      );
    } catch {
      return false;
    }
  });
  const warningActive =
    server?.reputation?.warning === true && !acknowledged;

  const acknowledgeWarning = () => {
    if (!server) return;
    try {
      sessionStorage.setItem(`${REPUTATION_ACK_PREFIX}${server.id}`, "1");
    } catch {
      // Storage can be unavailable (quota/private browsing); the ack is
      // best-effort and this visit still proceeds without it.
    }
    setAcknowledged(true);
  };

  const handleOpenAnyway = () => {
    if (!server) return;
    acknowledgeWarning();
    openExternal(server.serverUrl);
  };

  // Detect back navigation using pageshow event
  useEffect(() => {
    const handlePageShow = () => {
      // Navigate to home if restored from bfcache or has push flag in localStorage
      const hasPushFlag = localStorage.getItem("isPush") === "true";

      if (hasPushFlag) {
        localStorage.removeItem("isPush");
        navigate("/", { replace: true });
      }
    };

    window.addEventListener("pageshow", handlePageShow);

    return () => {
      window.removeEventListener("pageshow", handlePageShow);
    };
  }, [navigate]);

  useEffect(() => {
    if (typeof localStorage === "undefined") return;
    if (!server) {
      navigate("/");
      return;
    }

    // Check localStorage immediately (before pageshow)
    const hasPushFlag = localStorage.getItem("isPush") === "true";

    if (hasPushFlag) {
      // If flag already exists, go home (double-check with pageshow handler)
      localStorage.removeItem("isPush");
      navigate("/");
      return;
    }

    // A community-warning interstitial holds the redirect until the visitor
    // chooses; every other case keeps the original 500ms auto-open.
    if (warningActive) {
      return;
    }

    // Redirect after animation
    const timer = setTimeout(() => {
      openExternal(server.serverUrl);
    }, 500);

    return () => {
      clearTimeout(timer);
    };
  }, [server, navigate, warningActive]);

  // If no server data, show nothing (will redirect)
  if (!server) {
    return null;
  }

  const {
    id,
    thumbnail,
    name,
    online,
    description,
    tags,
    owner,
    paymentEnabled,
    paymentLabel = "",
  } = server;
  const normalizedPaymentLabel = paymentLabel.trim();
  const showPaymentBadge = paymentEnabled || normalizedPaymentLabel !== "";

  // Base size multiplier (1 = default, 2 = 2x size)
  const basicSize = 2.5;

  return (
    <SsgoiTransition id={`/server/${id}`}>
      <div
        data-hero-key={`server-bg-${id}`}
        className="fixed inset-0 bg-center bg-no-repeat bg-cover w-screen h-screen"
        style={{ ...(thumbnail && { backgroundImage: `url(${thumbnail})` }) }}
      >
        {/* Content overlay - Full screen */}
        <div className="absolute inset-0 flex items-center justify-center p-6 md:p-12">
          <div className="w-full h-full max-w-7xl bg-background/78 backdrop-blur-sm rounded-lg flex flex-col gap-6 p-8 md:p-12 items-start text-start">
            <div className="w-full h-full flex flex-col justify-center gap-6 md:gap-8">
              <div
                className="flex flex-col"
                style={{ gap: `${1 * basicSize}%` }}
              >
                <div
                  className="flex items-center"
                  style={{ gap: `${0.8 * basicSize}%` }}
                >
                  <div
                    className={`rounded-full ${
                      online ? "bg-green-status" : "bg-red-500"
                    }`}
                    style={{
                      width: `${1 * basicSize}vw`,
                      height: `${1 * basicSize}vw`,
                    }}
                  />
                  <p
                    className={`font-medium leading-normal ${
                      online ? "text-green-status" : "text-red-500"
                    }`}
                    style={{ fontSize: `${1.8 * basicSize}vw` }}
                  >
                    {online ? "Online" : "Offline"}
                  </p>
                </div>
                {showPaymentBadge && (
                  <div className="inline-flex w-fit max-w-full items-center gap-2 rounded-md border border-amber-400/25 bg-amber-400/10 px-4 py-2 font-display text-amber-700 dark:text-amber-100">
                    <BadgeDollarSign className="h-5 w-5 shrink-0" />
                    <span className="truncate text-base font-bold uppercase tracking-wide">
                      {normalizedPaymentLabel || "Paid app"}
                    </span>
                  </div>
                )}
                <p
                  className="text-foreground font-bold leading-tight"
                  style={{ fontSize: `${6 * basicSize}vw` }}
                >
                  {name}
                </p>
                {description && (
                  <p
                    className="text-text-muted font-normal leading-normal max-w-4xl"
                    style={{ fontSize: `${2.5 * basicSize}vw` }}
                  >
                    {description}
                  </p>
                )}
                {tags && tags.length > 0 && (
                  <div
                    className="flex flex-wrap"
                    style={{
                      gap: `${0.8 * basicSize}vw`,
                      marginTop: `${0.5 * basicSize}%`,
                    }}
                  >
                    {tags.map((tag, index) => (
                      <span
                        key={index}
                        className="bg-secondary text-primary font-medium rounded-lg"
                        style={{
                          padding: `${0.6 * basicSize}vw ${1.2 * basicSize}vw`,
                          fontSize: `${1.5 * basicSize}vw`,
                        }}
                      >
                        {tag}
                      </span>
                    ))}
                  </div>
                )}
                {owner && (
                  <p
                    className="text-text-muted font-normal leading-normal"
                    style={{
                      fontSize: `${1.8 * basicSize}vw`,
                      marginTop: `${1 * basicSize}%`,
                    }}
                  >
                    by {owner}
                  </p>
                )}
                {server.reputation && (server.reputation.up > 0 || server.reputation.down > 0) && !warningActive && (
                  <dl
                    data-testid="reputation-counts"
                    className="flex gap-4 text-xs font-medium text-text-muted"
                  >
                    <div className="flex flex-col gap-0.5">
                      <dt className="text-[10px] font-bold uppercase tracking-wider text-text-muted">Up</dt>
                      <dd>{server.reputation?.up ?? 0}</dd>
                    </div>
                    <div className="flex flex-col gap-0.5">
                      <dt className="text-[10px] font-bold uppercase tracking-wider text-text-muted">Down</dt>
                      <dd>{server.reputation?.down ?? 0}</dd>
                    </div>
                    <div className="flex flex-col gap-0.5">
                      <dt className="text-[10px] font-bold uppercase tracking-wider text-text-muted">Total</dt>
                      <dd>{server.reputation?.total ?? 0}</dd>
                    </div>
                  </dl>
                )}
              </div>
            </div>
          </div>
        </div>

        {warningActive && (
          <div className="absolute inset-0 z-20 flex items-center justify-center p-6">
            <div
              role="alertdialog"
              aria-labelledby="reputation-warning-title"
              aria-describedby="reputation-warning-description"
              className="flex w-full max-w-md flex-col gap-4 rounded-lg border border-border bg-background/95 p-6 text-start shadow-xl backdrop-blur-md"
            >
              <h2
                id="reputation-warning-title"
                className="font-display text-xl font-bold text-foreground"
              >
                Before you continue
              </h2>
              <p
                id="reputation-warning-description"
                className="text-sm leading-normal text-text-muted"
              >
                Some visitors reported issues with this service recently. This
                is anonymous community feedback and may not reflect its current
                state.
              </p>
              {server.reputation?.identity_changed_recently && (
                <p className="text-sm leading-normal text-text-muted">
                  This service recently changed its identity.
                </p>
              )}
              <dl
                data-testid="reputation-counts"
                className="flex gap-6 text-sm font-medium text-foreground"
              >
                <div className="flex flex-col gap-0.5">
                  <dt className="text-[10px] font-bold uppercase tracking-wider text-text-muted">
                    Up
                  </dt>
                  <dd>{server.reputation?.up ?? 0}</dd>
                </div>
                <div className="flex flex-col gap-0.5">
                  <dt className="text-[10px] font-bold uppercase tracking-wider text-text-muted">
                    Down
                  </dt>
                  <dd>{server.reputation?.down ?? 0}</dd>
                </div>
                <div className="flex flex-col gap-0.5">
                  <dt className="text-[10px] font-bold uppercase tracking-wider text-text-muted">
                    Total
                  </dt>
                  <dd>{server.reputation?.total ?? 0}</dd>
                </div>
              </dl>
              <div className="flex justify-end gap-3">
                <Button
                  variant="secondary"
                  className="cursor-pointer"
                  onClick={() => navigate(-1)}
                >
                  Back
                </Button>
                <Button className="cursor-pointer" onClick={handleOpenAnyway}>
                  Open anyway
                </Button>
              </div>
            </div>
          </div>
        )}
      </div>
    </SsgoiTransition>
  );
}
