import { SsgoiTransition } from "@ssgoi/react";
import { useEffect } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { AlertTriangle, BadgeDollarSign, ThumbsDown, ThumbsUp } from "lucide-react";
import { Button } from "@/components/ui/button";
import type { ReputationSummary } from "@/types/api";

// Directory presentation policy; the relay only stores vote aggregates.
function isReputationWarning(summary: ReputationSummary | undefined): boolean {
  return summary !== undefined && summary.total >= 5 && summary.down >= 3 && summary.down * 100 >= summary.total * 70;
}

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
  const server = location.state as ServerDetailState | null;

  const showGate = isReputationWarning(server?.reputation);

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

    if (showGate) {
      // Flagged service: hold the automatic open until the visitor decides.
      return;
    }

    // Redirect after animation
    const timer = setTimeout(() => {
      localStorage.setItem("isPush", "true");
      window.location.assign(server.serverUrl);
    }, 500);

    return () => {
      clearTimeout(timer);
    };
  }, [server, navigate, showGate]);

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
    reputation,
  } = server;
  const normalizedPaymentLabel = paymentLabel.trim();
  const showPaymentBadge = paymentEnabled || normalizedPaymentLabel !== "";

  const openService = () => {
    localStorage.setItem("isPush", "true");
    window.location.assign(server.serverUrl);
  };

  const handleBack = () => {
    navigate(-1);
  };

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
          {showGate ? (
            <div className="w-full max-w-2xl bg-background/85 backdrop-blur-sm rounded-lg border border-border p-8 md:p-10 flex flex-col gap-5 items-start text-start">
              <div className="flex items-center gap-3 text-amber-600 dark:text-amber-300">
                <AlertTriangle className="size-7 shrink-0" />
                <h1 className="font-display text-xl font-bold leading-tight">
                  Community ratings warning
                </h1>
              </div>
              <p className="text-text-muted leading-relaxed">
                This service has received a high proportion of negative
                community ratings. This is community feedback only — Portal has
                not independently reviewed this service.
              </p>
              {reputation && (
                <div className="flex flex-wrap items-center gap-4 text-sm font-medium">
                  <span className="flex items-center gap-1.5">
                    <ThumbsUp className="size-4 text-primary" />
                    {reputation.up} recommend
                  </span>
                  <span className="flex items-center gap-1.5">
                    <ThumbsDown className="size-4 text-red-500" />
                    {reputation.down} do not recommend
                  </span>
                  {typeof reputation.total === "number" && (
                    <span className="text-text-muted">
                      {reputation.total} ratings so far
                    </span>
                  )}
                </div>
              )}
              <div className="flex gap-3 w-full">
                <Button
                  variant="secondary"
                  onClick={handleBack}
                  className="cursor-pointer"
                >
                  Back
                </Button>
                <Button onClick={openService} className="cursor-pointer">
                  Open anyway
                </Button>
              </div>
            </div>
          ) : (
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
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </SsgoiTransition>
  );
}
