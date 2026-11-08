import { useEffect } from "react";
import { Navigate, useLocation, useNavigate } from "react-router-dom";
import { ArrowLeft, ExternalLink, Home, ShieldAlert, ThumbsDown, ThumbsUp } from "lucide-react";
import { AppShell, SidebarItem } from "@/components/shell/AppShell";
import { Button } from "@/components/ui/button";
import { ROUTE_PATHS } from "@/lib/apiPaths";
import type { BaseServer } from "@/lib/server";
import { isReputationWarning } from "@/utils/reputation";

const LEFT_FOR_SERVICE_KEY = "isPush";

function leaveForService(url: string): void {
  try {
    sessionStorage.setItem(LEFT_FOR_SERVICE_KEY, "true");
  } catch {}
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

function useReturnHomeAfterLeavingForService(): void {
  const navigate = useNavigate();
  useEffect(() => {
    const returnHome = () => {
      if (consumeLeftForService()) navigate(ROUTE_PATHS.home, { replace: true });
    };
    returnHome();
    window.addEventListener("pageshow", returnHome);
    return () => window.removeEventListener("pageshow", returnHome);
  }, [navigate]);
}

export function ServerDetail() {
  const location = useLocation();
  const navigate = useNavigate();
  const server = location.state as BaseServer | null;

  const isFlagged = isReputationWarning(server?.reputation);

  useReturnHomeAfterLeavingForService();

  if (!server || !isFlagged) {
    return <Navigate to={ROUTE_PATHS.home} replace />;
  }

  const { reputation } = server;

  return (
    <AppShell sidebar={<SidebarItem icon={<Home className="size-5" />} label="Home" href={ROUTE_PATHS.home} />}>
      <div className="mx-auto flex w-full max-w-[2400px] justify-center px-4 pb-12 pt-8 md:px-6 md:pt-16">
        <section aria-labelledby="gate-title" className="flex w-full max-w-xl flex-col gap-5 rounded-lg border border-stroke bg-surface-100 p-6 md:p-8">
          <div className="flex items-center gap-3 text-warning">
            <ShieldAlert className="size-8 shrink-0" />
            <h1 id="gate-title" className="text-xl font-bold leading-tight text-content-emphasis">
              Community ratings warning
            </h1>
          </div>
          <div className="min-w-0">
            <p className="truncate font-semibold text-content-emphasis">{server.name}</p>
            <p className="truncate text-xs text-content-muted">{server.dns}</p>
          </div>
          <p className="text-content">
            This service has received a high proportion of negative community ratings. This is community feedback
            only — Portal has not independently reviewed this service.
          </p>
          {reputation && (
            <div className="flex flex-wrap items-center gap-x-4 gap-y-2 rounded-md bg-surface-200 px-4 py-3 text-sm font-semibold text-content-emphasis">
              <span className="flex items-center gap-1.5">
                <ThumbsUp className="size-4 text-primary" />
                {reputation.up} recommend
              </span>
              <span className="flex items-center gap-1.5">
                <ThumbsDown className="size-4 text-danger" />
                {reputation.down} do not recommend
              </span>
              <span className="font-normal text-content-muted">
                {reputation.total} ratings so far · {Math.round((reputation.down * 100) / reputation.total)}% negative
              </span>
            </div>
          )}
          <div className="flex flex-col-reverse gap-3 sm:flex-row sm:justify-end">
            <Button onClick={() => navigate(-1)}>
              <ArrowLeft className="size-4" />
              Back
            </Button>
            <Button variant="primary" onClick={() => leaveForService(server.link)}>
              Open anyway
              <ExternalLink className="size-4" />
            </Button>
          </div>
        </section>
      </div>
    </AppShell>
  );
}
