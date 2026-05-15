import { useEffect, useState } from "react";
import { Loader2, LogOut, Wallet } from "lucide-react";
import { Button } from "@/components/ui/button";
import { ThemeToggleButton } from "@/components/ThemeToggleButton";
import { useAuth } from "@/hooks/useAuth";
import { apiClient } from "@/lib/apiClient";
import { API_PATHS } from "@/lib/apiPaths";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { getReleaseVersion } from "@/lib/releaseVersion";

interface HeaderProps {
  title?: string;
  isAdmin?: boolean;
  onAuthChange?: () => void | Promise<void>;
  showQuickStartLink?: boolean;
}

interface DomainStatusResponse {
  ens?: {
    verified?: boolean;
  };
}

const repoURL = "https://github.com/gosuda/portal-tunnel";

function formatWalletAddress(address: string): string {
  const trimmed = address.trim();
  if (trimmed.length <= 12) {
    return trimmed;
  }
  return `${trimmed.slice(0, 6)}...${trimmed.slice(-4)}`;
}

export function Header({
  title = "PORTAL",
  isAdmin,
  onAuthChange,
  showQuickStartLink = true,
}: HeaderProps) {
  const releaseVersion = getReleaseVersion();
  const [ensVerified, setENSVerified] = useState(false);
  const {
    isAuthenticated,
    isLoading,
    walletAddress,
    login,
    logout,
  } = useAuth(isAdmin ? "admin" : "auto");
  const [authError, setAuthError] = useState("");

  const handleWalletLogin = async () => {
    setAuthError("");
    const result = await login();
    if (!result.success) {
      setAuthError(result.error || "Wallet login failed.");
      return;
    }
    await onAuthChange?.();
  };

  const handleLogout = async () => {
    setAuthError("");
    await logout();
    await onAuthChange?.();
  };

  const walletLabel = isAuthenticated && walletAddress
    ? formatWalletAddress(walletAddress)
    : "Wallet";
  const walletTooltip = authError || (
    isAuthenticated && walletAddress ? walletAddress : "Connect wallet"
  );

  useEffect(() => {
    let cancelled = false;

    void (async () => {
      try {
        const status = await apiClient.get<DomainStatusResponse>(
          API_PATHS.sdk.domain
        );
        if (!cancelled) {
          setENSVerified(status?.ens?.verified === true);
        }
      } catch {
        if (!cancelled) {
          setENSVerified(false);
        }
      }
    })();

    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <header className="flex flex-wrap items-center justify-between gap-x-4 gap-y-3 py-2 lg:flex-nowrap">
      <div className="flex min-w-0 flex-1 flex-wrap items-center gap-x-4 gap-y-2 text-foreground sm:gap-x-6 lg:gap-x-7">
        <div className="min-w-0 text-foreground">
          <div className="flex min-w-0 items-center gap-1.5 sm:gap-2">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center">
              <svg
                xmlns="http://www.w3.org/2000/svg"
                width="27"
                height="27"
                viewBox="0 0 906.26 1457.543"
                className="h-6 w-6 text-primary"
              >
                <path
                  fill="currentColor"
                  d="M254.854 137.158c-34.46 84.407-88.363 149.39-110.934 245.675 90.926-187.569 308.397-483.654 554.729-348.685 135.487 74.216 194.878 270.78 206.058 467.566 21.924 385.996-190.977 853.604-467.585 943.057-174.879 56.543-307.375-86.447-364.527-198.115-176.498-344.82 2.041-910.077 182.259-1109.498zm198.13 7.918C202.61 280.257 4.622 968.542 207.322 1270.414c51.713 77.029 194.535 160.648 285.294 71.318-209.061 31.529-288.389-176.143-301.145-340.765 31.411 147.743 139.396 326.12 309.075 253.588 251.957-107.723 376.778-648.46 269.433-966.817 22.394 134.616 15.572 317.711-47.551 412.087 86.655-230.615 7.903-704.478-269.444-554.749z"
                />
              </svg>
            </div>

            <div className="flex min-w-0 flex-wrap items-center gap-2.5">
              <h2 className="min-w-0 wrap-break-word text-xl leading-none font-extrabold tracking-tight text-foreground sm:text-2xl">
                {title}
              </h2>
              {releaseVersion && (
                <span className="inline-flex h-6 items-center rounded-full bg-secondary px-2.5 text-xs font-semibold text-text-muted">
                  {releaseVersion}
                </span>
              )}
              {ensVerified && (
                <span className="inline-flex h-6 items-center rounded-full bg-primary/12 px-2.5 text-xs font-semibold text-primary ring-1 ring-primary/20">
                  ENS verified
                </span>
              )}
            </div>
          </div>
        </div>
        {!isAdmin && (
          <nav className="hidden items-center gap-4 pl-2 text-sm font-semibold text-text-muted xl:flex xl:pl-3 2xl:gap-6 2xl:text-base">
            {showQuickStartLink && (
              <a
                href="#quick-start"
                className="whitespace-nowrap transition-colors hover:text-foreground"
              >
                Quick Start
              </a>
            )}
            <a
              href="#live-servers"
              className="whitespace-nowrap transition-colors hover:text-foreground"
            >
              Live apps
            </a>
            <a
              href="#public-relays"
              className="whitespace-nowrap transition-colors hover:text-foreground"
            >
              Public relays
            </a>
          </nav>
        )}
      </div>

      <div className="flex shrink-0 flex-wrap items-center gap-2 sm:gap-3">
        {!isAdmin && (
          <a
            href={repoURL}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex h-12 w-12 shrink-0 items-center justify-center rounded-full border border-border/70 bg-background/90 text-foreground shadow-sm transition-all hover:-translate-y-0.5 hover:border-primary/40 hover:text-primary"
            aria-label="View source on GitHub"
          >
            <svg
              height="22"
              width="22"
              viewBox="0 0 24 24"
              fill="currentColor"
              className="opacity-85 transition-opacity hover:opacity-100"
            >
              <path d="M12 1C5.923 1 1 5.923 1 12c0 4.867 3.149 8.979 7.521 10.436.55.096.756-.233.756-.522 0-.262-.013-1.128-.013-2.049-2.764.509-3.479-.674-3.699-1.292-.124-.317-.66-1.293-1.127-1.554-.385-.207-.936-.715-.014-.729.866-.014 1.485.797 1.691 1.128.99 1.663 2.571 1.196 3.204.907.096-.715.385-1.196.701-1.471-2.448-.275-5.005-1.224-5.005-5.432 0-1.196.426-2.186 1.128-2.956-.111-.275-.496-1.402.11-2.915 0 0 .921-.288 3.024 1.128a10.193 10.193 0 0 1 2.75-.371c.936 0 1.871.123 2.75.371 2.104-1.43 3.025-1.128 3.025-1.128.605 1.513.221 2.64.111 2.915.701.77 1.127 1.747 1.127 2.956 0 4.222-2.571 5.157-5.019 5.432.399.344.743 1.004.743 2.035 0 1.471-.014 2.654-.014 3.025 0 .289.206.632.756.522C19.851 20.979 23 16.854 23 12c0-6.077-4.922-11-11-11Z" />
            </svg>
          </a>
        )}

        <ThemeToggleButton className="inline-flex shrink-0" />

        <TooltipProvider>
          <Tooltip>
            <TooltipTrigger asChild>
              <Button
                variant={isAuthenticated ? "secondary" : "outline"}
                onClick={isAuthenticated ? undefined : handleWalletLogin}
                disabled={isLoading}
                className={`h-12 rounded-full border-border/70 bg-background/90 px-3 text-foreground shadow-sm transition-all hover:bg-background disabled:cursor-not-allowed sm:px-4 ${
                  isAuthenticated
                    ? "cursor-default"
                    : "cursor-pointer hover:-translate-y-0.5 hover:border-primary/40 hover:text-primary"
                }`}
                aria-label={isAuthenticated ? "Wallet connected" : "Connect wallet"}
              >
                {isLoading ? (
                  <Loader2 className="h-5 w-5 animate-spin" />
                ) : (
                  <Wallet className="h-5 w-5" />
                )}
                <span className="max-w-28 truncate font-mono text-xs sm:max-w-36">
                  {walletLabel}
                </span>
              </Button>
            </TooltipTrigger>
            <TooltipContent>
              <p>{walletTooltip}</p>
            </TooltipContent>
          </Tooltip>
        </TooltipProvider>

        {isAuthenticated && (
          <TooltipProvider>
            <Tooltip>
              <TooltipTrigger asChild>
                <Button
                  variant="outline"
                  size="icon"
                  onClick={handleLogout}
                  className="h-12 w-12 cursor-pointer rounded-full border-border/70 bg-background/90 text-foreground shadow-sm transition-all hover:-translate-y-0.5 hover:border-destructive/40 hover:bg-background hover:text-destructive"
                  aria-label="Logout"
                >
                  <LogOut className="h-5 w-5" />
                </Button>
              </TooltipTrigger>
              <TooltipContent>
                <p>Logout</p>
              </TooltipContent>
            </Tooltip>
          </TooltipProvider>
        )}
      </div>
    </header>
  );
}
