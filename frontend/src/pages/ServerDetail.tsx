import { SsgoiTransition } from "@ssgoi/react";
import { useEffect } from "react";
import { Navigate, useLocation, useNavigate } from "react-router-dom";
import { AlertTriangle, ThumbsDown, ThumbsUp } from "lucide-react";
import { Button } from "@/components/ui/button";
import type { BaseServer } from "@/lib/server";
import { isReputationWarning } from "@/utils/reputation";

const LEFT_FOR_SERVICE_KEY = "isPush";

function leaveForService(url: string): void {
  try {
    sessionStorage.setItem(LEFT_FOR_SERVICE_KEY, "true");
  } catch {
    // Storage can be unavailable in restricted contexts; open the service anyway.
  }
  window.location.assign(url);
}

function consumeLeftForService(): boolean {
  try {
    const left = sessionStorage.getItem(LEFT_FOR_SERVICE_KEY) === "true";
    sessionStorage.removeItem(LEFT_FOR_SERVICE_KEY);
    return left;
  } catch {
    return false;
  }
}

export function ServerDetail() {
  const location = useLocation();
  const navigate = useNavigate();
  const server = location.state as BaseServer | null;

  const showGate = isReputationWarning(server?.reputation);

  useEffect(() => {
    const handlePageShow = () => {
      if (consumeLeftForService()) {
        navigate("/", { replace: true });
      }
    };
    window.addEventListener("pageshow", handlePageShow);
    return () => window.removeEventListener("pageshow", handlePageShow);
  }, [navigate]);

  useEffect(() => {
    if (consumeLeftForService()) {
      navigate("/", { replace: true });
    }
  }, [navigate]);

  if (!server || !showGate) {
    return <Navigate to="/" replace />;
  }

  const { id, reputation } = server;

  const openService = () => leaveForService(server.link);

  const handleBack = () => {
    navigate(-1);
  };

  return (
    <SsgoiTransition id={`/server/${id}`}>
      <div className="fixed inset-0 z-50 flex items-center justify-center bg-background/90 p-6 backdrop-blur-sm md:p-12">
        <div className="w-full max-w-2xl bg-card border border-border p-8 md:p-10 rounded-xl shadow-2xl flex flex-col gap-5 items-start text-start">
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
      </div>
    </SsgoiTransition>
  );
}
