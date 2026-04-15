import {
  useEffect,
  useId,
  useMemo,
  useState,
  type KeyboardEvent,
} from "react";
import { Check, Copy, RefreshCw, X } from "lucide-react";
import { Input } from "@/components/ui/input";
import { apiClient } from "@/lib/apiClient";
import { API_PATHS } from "@/lib/apiPaths";
import { cn } from "@/lib/utils";
import {
  buildTunnelPreviewURL,
  buildTunnelStatusHostname,
  normalizeAbsoluteHTTPURL,
} from "@/lib/tunnelCommand";
import {
  DEFAULT_HOST,
  readCurrentOrigin,
  useTunnelCommand,
} from "@/hooks/useTunnelCommand";

interface TunnelCommandFormProps {
  className?: string;
  theme?: "light" | "terminal";
  mode?: "full" | "hero";
}

type TunnelStatus = "waiting" | "registered" | "alive";

interface TunnelStatusResponse {
  hostname: string;
  registered: boolean;
  service_alive: boolean;
}

export function TunnelCommandForm({
  className,
  theme = "light",
  mode = "full",
}: TunnelCommandFormProps) {
  if (mode === "hero") {
    return <HeroTunnelCommandForm className={className} theme={theme} />;
  }

  return <FullTunnelCommandForm className={className} theme={theme} />;
}

function HeroTunnelCommandForm({
  className,
  theme,
}: Required<Pick<TunnelCommandFormProps, "theme">> &
  Pick<TunnelCommandFormProps, "className">) {
  const isTerminal = theme === "terminal";
  const {
    currentOrigin,
    nameSeed,
    target,
    setTarget,
    copied,
    os,
    setOs,
    generatedName,
    effectiveName,
    installBlock,
    runBlock,
    handleCopy,
    handleNameChange,
    handleShuffleName,
  } = useTunnelCommand();

  const [tunnelStatus, setTunnelStatus] = useState<TunnelStatus>("waiting");

  const previewURL = useMemo(
    () => buildTunnelPreviewURL(currentOrigin, effectiveName, target, nameSeed),
    [currentOrigin, effectiveName, nameSeed, target]
  );
  const statusHostname = useMemo(
    () =>
      buildTunnelStatusHostname(currentOrigin, effectiveName, target, nameSeed),
    [currentOrigin, effectiveName, nameSeed, target]
  );

  useEffect(() => {
    if (statusHostname === "") {
      return;
    }

    let cancelled = false;

    const poll = async () => {
      try {
        const params = new URLSearchParams({ hostname: statusHostname });
        const statusResponse = await apiClient.get<TunnelStatusResponse>(
          `${API_PATHS.tunnel.status}?${params.toString()}`
        );
        if (cancelled) {
          return;
        }

        if (!statusResponse.registered) {
          setTunnelStatus("waiting");
          return;
        }

        setTunnelStatus(statusResponse.service_alive ? "alive" : "registered");
      } catch {
        if (!cancelled) {
          setTunnelStatus("waiting");
        }
      }
    };

    setTunnelStatus("waiting");
    void poll();
    const interval = window.setInterval(() => {
      void poll();
    }, 1500);

    return () => {
      cancelled = true;
      window.clearInterval(interval);
    };
  }, [statusHostname]);

  const tunnelStatusTone = {
    alive: isTerminal ? "bg-green-400" : "bg-green-600",
    registered: isTerminal ? "bg-sky-400" : "bg-sky-600",
    waiting: isTerminal ? "bg-slate-500" : "bg-slate-400",
  }[tunnelStatus];
  const tunnelStatusHeadline = {
    alive: "This URL is live now",
    registered: "URL reserved",
    waiting: "Waiting for Connection",
  }[tunnelStatus];
  const isPreviewURLDisabled = tunnelStatus === "waiting";
  const heroSectionLabelClass = cn(
    "text-[13px] font-semibold tracking-[0.04em] sm:text-sm",
    isTerminal ? "text-slate-100" : "text-foreground/85"
  );
  const heroURLClass = cn(
    "block overflow-x-auto whitespace-nowrap font-mono text-[15px] font-medium sm:text-base",
    isTerminal ? "text-sky-300" : "text-primary"
  );
  const platformButtonGroupClass = cn(
    "flex shrink-0 rounded-lg border p-0.5",
    isTerminal
      ? "border-white/6 bg-white/[0.035]"
      : "border-border bg-border"
  );
  const platformButtonClass = (selected: boolean) =>
    cn(
      "min-w-[72px] whitespace-nowrap rounded-md px-2.5 py-1.5 text-[11px] font-semibold transition-colors",
      selected
        ? isTerminal
          ? "bg-white/[0.08] text-slate-200"
          : "bg-background text-foreground/85"
        : isTerminal
          ? "text-slate-500 hover:text-slate-300"
          : "text-text-muted hover:text-foreground"
    );
  const heroControlLabelClass = cn(
    "shrink-0 text-[9px] font-semibold uppercase tracking-[0.16em]",
    isTerminal ? "text-slate-500" : "text-text-muted"
  );
  const heroControlInputClass = cn(
    "h-auto border-0 bg-transparent px-0 py-0 text-[13px] shadow-none focus-visible:ring-0",
    isTerminal
      ? "text-slate-200 placeholder:text-slate-600"
      : "text-foreground/85 placeholder:text-muted-foreground"
  );
  const heroShuffleButtonClass = cn(
    "inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-md transition-colors",
    isTerminal
      ? "text-slate-500 hover:bg-white/[0.06] hover:text-slate-200"
      : "text-text-muted hover:bg-foreground/5 hover:text-foreground"
  );
  return (
    <div className={cn("space-y-5", className)}>
      <div className="space-y-2">
        <div className="space-y-1.5">
          <p className={heroSectionLabelClass}>
            1. Start your local app
            <span
              className={cn(
                "ml-1 normal-case tracking-normal",
                isTerminal ? "text-slate-400" : "text-text-muted"
              )}
            >
              (e.g.
              <span
                className={cn(
                  "mx-1 font-mono",
                  isTerminal ? "text-slate-200" : "text-foreground"
                )}
              >
                localhost:3000
              </span>
              )
            </span>
          </p>
        </div>
      </div>

      <div className="space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <p className={heroSectionLabelClass}>2. Run this command</p>
          <div className={platformButtonGroupClass}>
            <button
              type="button"
              onClick={() => setOs("unix")}
              className={platformButtonClass(os === "unix")}
            >
              Linux
            </button>
            <button
              type="button"
              onClick={() => setOs("windows")}
              className={platformButtonClass(os === "windows")}
            >
              Windows
            </button>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-x-4 gap-y-2 sm:flex-nowrap">
          <div className="flex shrink-0 items-center gap-2">
            <span className={heroControlLabelClass}>Port</span>
            <Input
              type="text"
              value={target}
              onChange={(event) => setTarget(event.target.value)}
              placeholder={DEFAULT_HOST}
              aria-label="Local port or address"
              className={cn(heroControlInputClass, "w-[19 font-mono")}
            />
          </div>
          <div className="ml-auto flex min-w-0 items-center justify-end gap-2 sm:w-88">
            <span className={heroControlLabelClass}>Name</span>
            <Input
              type="text"
              onChange={handleNameChange}
              placeholder={generatedName}
              aria-label="Public name"
              className={cn(heroControlInputClass, "min-w-0 flex-1")}
            />
            <button
              type="button"
              onClick={handleShuffleName}
              className={heroShuffleButtonClass}
              aria-label="Shuffle public name"
              title="Shuffle public name"
            >
              <RefreshCw className="h-4 w-4" aria-hidden="true" />
            </button>
          </div>
        </div>
        <div
          className={cn(
            "relative min-h-37 rounded-xl border px-4 py-4 pr-14 font-mono text-sm leading-7",
            isTerminal
              ? "border-white/10 bg-black/55 text-white shadow-[inset_0_1px_0_rgba(255,255,255,0.05)]"
              : "border-border/80 bg-border/90 text-foreground"
          )}
        >
          <button
            type="button"
            onClick={handleCopy}
            className={cn(
              "absolute top-4 right-4 inline-flex h-8 w-8 items-center justify-center rounded-lg transition-colors",
              isTerminal
                ? "text-emerald-300/75 hover:bg-emerald-400/10 hover:text-emerald-200"
                : "text-emerald-600 hover:bg-emerald-500/10 hover:text-emerald-700"
            )}
            aria-label="Copy command"
            title={copied ? "Copied" : "Copy"}
          >
            {copied ? (
              <Check className="h-4 w-4" />
            ) : (
              <Copy className="h-4 w-4" />
            )}
          </button>
          <pre className="overflow-x-auto whitespace-pre-wrap break-all">
            <span className="block">{installBlock}</span>
            <span className="mt-2 block">{runBlock}</span>
          </pre>
        </div>
      </div>

      <div className="space-y-2 pt-1">
        <p className={heroSectionLabelClass}>3. Open this public URL</p>
        <div
          className={cn(
            "space-y-3 rounded-xl border px-3.5 py-3",
            isTerminal
              ? "border-white/8 bg-white/4.5"
              : "border-border bg-white"
          )}
        >
          <div
            className={cn(
              "flex items-center gap-2 text-[13px] font-semibold",
              isTerminal ? "text-slate-300" : "text-foreground"
            )}
          >
            <span
              className={cn("h-2 w-2 rounded-full", tunnelStatusTone)}
              aria-hidden="true"
            />
            <span>{tunnelStatusHeadline}</span>
          </div>
          {isPreviewURLDisabled ? (
            <span
              aria-disabled="true"
              className={cn(heroURLClass, "cursor-not-allowed opacity-70")}
            >
              {previewURL}
            </span>
          ) : (
            <a
              href={previewURL}
              target="_blank"
              rel="noopener noreferrer"
              className={cn(heroURLClass, "underline-offset-4 hover:underline")}
            >
              {previewURL}
            </a>
          )}
        </div>
      </div>
    </div>
  );
}

function FullTunnelCommandForm({
  className,
  theme,
}: Required<Pick<TunnelCommandFormProps, "theme">> &
  Pick<TunnelCommandFormProps, "className">) {
  const inputId = useId();
  const isTerminal = theme === "terminal";
  const currentOrigin = readCurrentOrigin();

  const [relayUrls, setRelayUrls] = useState<string[]>(() => [
    currentOrigin,
  ]);
  const [discoveryEnabled, setDiscoveryEnabled] = useState(true);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [urlInput, setUrlInput] = useState("");
  const [enableUDP, setEnableUDP] = useState(false);
  const [udpPort, setUDPPort] = useState("");
  const [thumbnailURL, setThumbnailURL] = useState("");

  const normalizedThumbnailURL = useMemo(
    () => normalizeAbsoluteHTTPURL(thumbnailURL),
    [thumbnailURL]
  );
  const thumbnailError = useMemo(() => {
    if (thumbnailURL.trim() === "" || normalizedThumbnailURL !== "") {
      return "";
    }

    return "Thumbnail must be an absolute http:// or https:// URL.";
  }, [normalizedThumbnailURL, thumbnailURL]);

  const {
    target,
    setTarget,
    name,
    copied,
    os,
    setOs,
    generatedName,
    installBlock,
    runBlock,
    handleCopy,
    handleNameChange,
  } = useTunnelCommand({
    relayUrls,
    discovery: discoveryEnabled,
    thumbnailURL: normalizedThumbnailURL,
    enableUDP,
    udpPort,
  });

  const addRelayURL = (url: string) => {
    const trimmed = url.trim();
    if (!trimmed || relayUrls.includes(trimmed)) {
      return;
    }

    try {
      new URL(trimmed);
      setRelayUrls((prev) => [...prev, trimmed]);
      setUrlInput("");
    } catch {
      // Ignore invalid relay URL input.
    }
  };

  const removeRelayURL = (url: string) => {
    if (!discoveryEnabled && relayUrls.length <= 1) {
      return;
    }
    setRelayUrls((prev) => prev.filter((candidate) => candidate !== url));
  };

  const handleURLKeyDown = (event: KeyboardEvent<HTMLInputElement>) => {
    if (event.key === "Enter") {
      event.preventDefault();
      addRelayURL(urlInput);
      return;
    }

    if (event.key === "Backspace" && urlInput === "" && relayUrls.length > 0) {
      setRelayUrls((prev) => prev.slice(0, -1));
    }
  };
  const sectionLabelClass = isTerminal
    ? "text-sm font-medium text-slate-200"
    : "text-sm font-medium text-foreground dark:text-zinc-100";
  const helpTextClass = isTerminal
    ? "text-xs text-slate-400"
    : "text-xs leading-5 text-muted-foreground dark:text-zinc-500";
  const inlineFieldClass = isTerminal
    ? "flex items-center overflow-hidden rounded-xl border border-white/10 bg-white/5"
    : "flex items-center overflow-hidden rounded-md border border-border/80 bg-secondary/55 focus-within:border-ring focus-within:ring-1 focus-within:ring-ring/30 dark:border-white/10 dark:bg-[#272727]";
  const inlinePrefixClass = isTerminal
    ? "shrink-0 border-r border-white/10 px-3 text-xs font-medium uppercase tracking-[0.12em] text-slate-400"
    : "shrink-0 border-r border-border px-3 text-[0.82rem] font-medium uppercase tracking-[0.08em] text-text-muted dark:border-black/25 dark:text-zinc-400";
  const inlineInputClass = isTerminal
    ? "h-10 border-0 bg-transparent px-3 text-sm text-white placeholder:text-slate-500 shadow-none focus-visible:ring-0"
    : "h-9 border-0 bg-transparent px-3 text-sm font-semibold text-foreground placeholder:text-text-muted shadow-none focus-visible:ring-0 dark:text-zinc-100 dark:placeholder:text-zinc-500";
  const relayFieldClass = isTerminal
    ? "flex min-h-12 flex-wrap items-center gap-2 rounded-xl border border-white/10 bg-white/5 px-2.5 py-2"
    : "flex min-h-10 flex-wrap items-center gap-2 rounded-md border border-border bg-background px-2 py-2 shadow-sm focus-within:border-ring focus-within:ring-1 focus-within:ring-ring/25 dark:border-white/10 dark:bg-transparent";
  const relayChipClass = isTerminal
    ? "inline-flex items-center gap-1 rounded-md bg-white/10 px-2.5 py-1.5 text-xs font-medium text-slate-100"
    : "inline-flex items-center gap-1 rounded-md bg-secondary px-2.5 py-1 text-xs font-semibold text-secondary-foreground dark:bg-[#22312c] dark:text-[#dceee4]";
  const relayChipRemoveClass = isTerminal
    ? "hover:bg-white/10"
    : "text-text-muted hover:bg-background/80 dark:text-[#cfe3d8] dark:hover:bg-black/20";
  const advancedInputClass = isTerminal
    ? "h-10 rounded-lg border-white/10 bg-white/5 text-white placeholder:text-slate-500"
    : "h-10 rounded-md border border-border bg-background text-foreground placeholder:text-muted-foreground shadow-sm dark:border-white/10 dark:bg-[#171717] dark:text-zinc-100 dark:placeholder:text-zinc-500";
  const osGroupClass = isTerminal
    ? "flex rounded-xl bg-white/8 p-1"
    : "flex rounded-md bg-border p-1 dark:bg-[#272727]";
  const osButtonClass = (selected: boolean) =>
    cn(
      "flex-1 rounded-sm px-3 py-2 text-sm font-semibold transition-colors",
      isTerminal
        ? selected
          ? "bg-white/8 text-slate-200"
          : "text-slate-400 hover:text-slate-300"
        : selected
          ? "bg-card text-foreground shadow-sm ring-1 ring-border/80 dark:bg-[#0b0b0b] dark:text-zinc-100 dark:ring-transparent"
          : "text-muted-foreground hover:text-foreground dark:text-zinc-500 dark:hover:text-zinc-300"
    );
  const commandPanelClass = isTerminal
    ? "relative rounded-xl border border-white/10 bg-black/30"
    : "relative rounded-md bg-secondary/55 shadow-sm ring-1 ring-border/70 dark:bg-[#272727] dark:ring-transparent";
  const commandPreClass = isTerminal
    ? "overflow-x-auto whitespace-pre-wrap break-all p-4 pr-12 font-mono text-sm leading-7 text-white"
    : "overflow-x-auto whitespace-pre-wrap break-all p-3 pr-12 font-mono text-sm leading-7 text-foreground dark:text-zinc-100";

  return (
    <div className={cn("space-y-4 py-1", className)}>
      <div className="space-y-2">
        <label
          htmlFor={`${inputId}-host`}
          className={sectionLabelClass}
        >
          Host
        </label>
        <div className={inlineFieldClass}>
          <span className={inlinePrefixClass}>HOST=</span>
          <Input
            id={`${inputId}-host`}
            type="text"
            value={target}
            onChange={(event) => setTarget(event.target.value)}
            placeholder={DEFAULT_HOST}
            className={inlineInputClass}
          />
        </div>
        <p className={helpTextClass}>
          The hostname or IP:Port where your service is running
        </p>
      </div>

      <div className="space-y-2">
        <label
          htmlFor={`${inputId}-name`}
          className={sectionLabelClass}
        >
          Service Name
        </label>
        <div className={inlineFieldClass}>
          <span className={inlinePrefixClass}>NAME=</span>
          <Input
            id={`${inputId}-name`}
            type="text"
            value={name}
            onChange={handleNameChange}
            placeholder={generatedName}
            className={inlineInputClass}
          />
        </div>
        <p className={helpTextClass}>A unique identifier for your tunnel</p>
      </div>

      <div className="space-y-2">
        <label className={sectionLabelClass}>
          Relay URLs
        </label>
        <div className={relayFieldClass}>
          {relayUrls.map((url) => (
            <span
              key={url}
              className={relayChipClass}
            >
              {url}
              <button
                type="button"
                onClick={() => removeRelayURL(url)}
                className={cn(
                  "ml-1 rounded-sm p-0.5",
                  !discoveryEnabled && relayUrls.length <= 1
                    ? "cursor-not-allowed opacity-40"
                    : relayChipRemoveClass
                )}
                aria-label={`Remove ${url}`}
                disabled={!discoveryEnabled && relayUrls.length <= 1}
              >
                <X className="h-3 w-3" />
              </button>
            </span>
          ))}

          <input
            type="text"
            value={urlInput}
            onChange={(event) => setUrlInput(event.target.value)}
            onKeyDown={handleURLKeyDown}
            placeholder="Add relay URL..."
            className={cn(
              "min-w-[140px] flex-1 bg-transparent text-sm outline-none",
              isTerminal
                ? "text-white placeholder:text-slate-500"
                : "text-foreground placeholder:text-muted-foreground dark:text-zinc-100 dark:placeholder:text-zinc-500"
            )}
          />
        </div>
        <p className={helpTextClass}>
          Press Enter to add. Multiple relay servers for redundancy.
        </p>
      </div>

      <div className="space-y-2">
        <label className={sectionLabelClass}>Operating System</label>
        <div className={osGroupClass}>
          <button
            type="button"
            onClick={() => setOs("unix")}
            className={osButtonClass(os === "unix")}
          >
            Linux / macOS
          </button>
          <button
            type="button"
            onClick={() => setOs("windows")}
            className={osButtonClass(os === "windows")}
          >
            Windows (PowerShell)
          </button>
        </div>
      </div>

      <div className="space-y-2">
        <label className={sectionLabelClass}>
          Generated Command
        </label>
        <div className={commandPanelClass}>
          <pre className={commandPreClass}>
            <span className="block">{installBlock}</span>
            <span className="mt-2 block">{runBlock}</span>
          </pre>
          <button
            type="button"
            onClick={handleCopy}
            className={cn(
              "absolute right-2 top-1/2 -translate-y-1/2 rounded-md p-2 transition-colors",
              isTerminal ? "hover:bg-white/10" : "hover:bg-background/70 dark:hover:bg-black/20"
            )}
            aria-label="Copy command"
          >
            {copied ? (
              <Check className={cn("h-4 w-4", isTerminal ? "text-green-400" : "text-emerald-400")} />
            ) : (
              <Copy className={cn("h-4 w-4", isTerminal ? "text-slate-400" : "text-text-muted dark:text-zinc-500")} />
            )}
          </button>
        </div>
      </div>

      {!isTerminal && (
        <div className="pt-1">
          <button
            type="button"
            onClick={() => setShowAdvanced((current) => !current)}
            className="text-xs font-medium text-muted-foreground transition-colors hover:text-foreground dark:text-zinc-500 dark:hover:text-zinc-300"
          >
            {showAdvanced ? "Hide advanced options" : "Advanced options"}
          </button>
          {showAdvanced && (
            <div className="mt-3 space-y-4 rounded-md border border-border bg-muted/45 px-4 py-4 dark:border-white/8 dark:bg-[#101010]">
              <label className="flex items-center gap-2 text-sm text-foreground dark:text-zinc-300">
                <input
                  type="checkbox"
                  checked={discoveryEnabled}
                  onChange={(event) => {
                    const nextEnabled = event.target.checked;
                    setDiscoveryEnabled(nextEnabled);
                    if (!nextEnabled && relayUrls.length === 0) {
                      setRelayUrls([currentOrigin]);
                    }
                  }}
                  className="h-4 w-4"
                />
                <span>Enable relay discovery</span>
              </label>

              <div className="space-y-2">
                <label className="flex items-center gap-2 text-sm text-foreground dark:text-zinc-300">
                  <input
                    type="checkbox"
                    checked={enableUDP}
                    onChange={(event) => {
                      const nextEnabled = event.target.checked;
                      setEnableUDP(nextEnabled);
                      if (!nextEnabled) {
                        setUDPPort("");
                      }
                    }}
                    className="h-4 w-4"
                  />
                  <span>Enable UDP transport</span>
                </label>
                {enableUDP && (
                  <div className="space-y-1.5">
                    <Input
                      id={`${inputId}-udp-port`}
                      type="text"
                      value={udpPort}
                      onChange={(event) => setUDPPort(event.target.value)}
                      placeholder={target.trim() || DEFAULT_HOST}
                      className={advancedInputClass}
                    />
                    <p className={helpTextClass}>
                      Local UDP port to forward. Defaults to the same as Host.
                    </p>
                  </div>
                )}
              </div>

              <div className="space-y-2">
                <label
                  htmlFor={`${inputId}-thumbnail`}
                  className="text-sm font-medium text-foreground dark:text-zinc-300"
                >
                  Thumbnail URL
                </label>
                <Input
                  id={`${inputId}-thumbnail`}
                  type="url"
                  value={thumbnailURL}
                  onChange={(event) => setThumbnailURL(event.target.value)}
                  placeholder="https://cdn.example.com/thumb.png"
                  className={advancedInputClass}
                />
                {normalizedThumbnailURL && (
                  <div className="flex h-20 w-20 items-center justify-center overflow-hidden rounded-md border border-border bg-background dark:border-white/10 dark:bg-[#171717]">
                    <img
                      src={normalizedThumbnailURL}
                      alt="Thumbnail preview"
                      className="h-full w-full object-cover"
                    />
                  </div>
                )}
                {thumbnailError && (
                  <p className="text-xs text-destructive">{thumbnailError}</p>
                )}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
