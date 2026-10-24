import { useId, useMemo, useState } from "react";
import { Check, ChevronRight, Copy, Lock } from "lucide-react";
import { Input } from "@/components/ui/input";
import {
  TunnelAuthSection,
  describeAuth,
} from "@/components/TunnelAuthSection";
import {
  Chip,
  ChipField,
  Notice,
  TUNNEL_FORM_STYLES,
  type TunnelFormTheme,
} from "@/components/TunnelFormParts";
import type { Lease } from "@/types/api";
import { cn } from "@/lib/utils";
import {
  authBlocksUDP,
  buildTunnelPreviewURL,
  buildServiceStatusHostname,
  normalizeAbsoluteHTTPURL,
  type TunnelAuthIssue,
  type TunnelCommandOS,
} from "@/lib/tunnelCommand";
import {
  DEFAULT_HOST,
  readCurrentOrigin,
  useTunnelCommand,
} from "@/hooks/useTunnelCommand";
import type { ShareKind } from "@/lib/shareLink";

const SHARE_KIND_LABEL: Record<ShareKind, string> = {
  url: "URL",
  file: "File",
  port: "Port",
};

const SHARE_PLACEHOLDER = "file:///Users/me/site/index.html or 3000";

type TunnelCommandFormProps = {
  className?: string;
  theme?: TunnelFormTheme;
} & (
  | { mode: "hero"; leases: Lease[] | null }
  | { mode?: "full"; leases?: never }
);

type ServiceStatus = "waiting" | "registered" | "alive";

export function TunnelCommandForm({
  className,
  theme = "light",
  mode,
  leases,
}: TunnelCommandFormProps) {
  if (mode === "hero") {
    return (
      <HeroTunnelCommandForm
        className={className}
        theme={theme}
        leases={leases}
      />
    );
  }

  return (
    <FullTunnelCommandForm
      className={className}
      theme={theme}
    />
  );
}

function HeroTunnelCommandForm({
  className,
  theme,
  leases,
}: Required<Pick<TunnelCommandFormProps, "theme">> &
  Pick<TunnelCommandFormProps, "className"> & {
    leases: Lease[] | null;
  }) {
  const isTerminal = theme === "terminal";
  const authPanelId = useId();
  const [tunnelTarget, setTunnelTarget] = useState<TunnelCommandOS>("unix");
  const [authOpen, setAuthOpen] = useState(false);
  const {
    currentOrigin,
    relayUrls,
    discovery,
    target,
    setTarget,
    name,
    copied,
    os,
    effectiveName,
    auth,
    setAuth,
    authIssues,
    shareKind,
    installBlock,
    runBlock,
    handleCopy,
    handleNameChange,
  } = useTunnelCommand({
    os: tunnelTarget,
  });

  const previewURL = useMemo(
    () => buildTunnelPreviewURL(currentOrigin, effectiveName),
    [currentOrigin, effectiveName]
  );
  const statusHostname = useMemo(
    () => buildServiceStatusHostname(currentOrigin, effectiveName),
    [currentOrigin, effectiveName]
  );

  const lease = statusHostname === "" ? undefined : leases?.find(
    (candidate) => candidate.hostname.trim().toLowerCase() === statusHostname
  );
  const serviceStatus: ServiceStatus = !lease
    ? "waiting"
    : lease.ready > 0 ? "alive" : "registered";

  const serviceStatusTone = {
    alive: "bg-green-status",
    registered: "bg-primary",
    waiting: "bg-text-muted",
  }[serviceStatus];
  const serviceStatusHeadline = {
    alive: "This URL is live now",
    registered: "URL reserved",
    waiting: "Waiting for Connection",
  }[serviceStatus];
  const isPreviewURLDisabled = serviceStatus === "waiting";
  const heroSectionLabelClass = cn(
    "text-[13px] font-semibold tracking-normal sm:text-sm",
    isTerminal ? "text-slate-100" : "text-foreground/85"
  );
  const heroURLClass = cn(
    "block overflow-x-auto whitespace-nowrap font-mono text-[15px] font-medium sm:text-base",
    isTerminal ? "text-sky-300" : "text-primary"
  );
  const platformButtonGroupClass = cn(
    "flex shrink-0 rounded-md border p-0.5",
    isTerminal
      ? "border-white/6 bg-white/[0.035]"
      : "border-border bg-border"
  );
  const platformButtonClass = (selected: boolean) =>
    cn(
      "min-w-[72px] whitespace-nowrap rounded-sm px-2.5 py-1.5 text-[11px] font-semibold transition-colors",
      selected
        ? isTerminal
          ? "bg-white/[0.08] text-slate-200"
          : "bg-background text-foreground/85"
        : isTerminal
          ? "text-slate-500 hover:text-slate-300"
          : "text-text-muted hover:text-foreground"
    );
  const heroControlLabelClass = cn(
    "shrink-0 text-[9px] font-semibold uppercase tracking-normal",
    isTerminal ? "text-slate-500" : "text-text-muted"
  );
  const heroExampleClass = cn(
    "mx-1 font-mono",
    isTerminal ? "text-slate-200" : "text-foreground"
  );
  const heroControlInputClass = cn(
    "h-auto border-0 bg-transparent px-0 py-0 text-[13px] shadow-none focus-visible:ring-0",
    isTerminal
      ? "text-slate-200 placeholder:text-slate-600"
      : "text-foreground/85 placeholder:text-muted-foreground"
  );
  return (
    <div className={cn("space-y-5", className)}>
      <div className="space-y-2">
        <div className="space-y-1.5">
          <p className={heroSectionLabelClass}>
            1. Paste what you want to share
          </p>
          <p
            className={cn(
              "text-[12px] leading-5",
              isTerminal ? "text-slate-400" : "text-text-muted"
            )}
          >
            A local port such as
            <span className={heroExampleClass}>3000</span>, a running URL such as
            <span className={heroExampleClass}>http://localhost:3000</span>, or a
            file path such as
            <span className={heroExampleClass}>
              file:///Users/me/site/index.html
            </span>
            — file paths are served as a static site straight from that folder,
            so nothing needs to be running locally.
          </p>
        </div>
      </div>

      <div className="space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <p className={heroSectionLabelClass}>2. Run this command</p>
          <div className={platformButtonGroupClass}>
            <button
              type="button"
              onClick={() => setTunnelTarget("unix")}
              className={platformButtonClass(os === "unix")}
            >
              Linux
            </button>
            <button
              type="button"
              onClick={() => setTunnelTarget("windows")}
              className={platformButtonClass(os === "windows")}
            >
              Windows
            </button>
          </div>
        </div>
        <div className="space-y-2">
          <div className="flex min-w-0 items-center gap-2">
            <span className={heroControlLabelClass}>Share</span>
            <Input
              type="text"
              value={target}
              onChange={(event) => setTarget(event.target.value)}
              placeholder={SHARE_PLACEHOLDER}
              aria-label="Link, file path, or local port to share"
              className={cn(heroControlInputClass, "min-w-0 flex-1 font-mono")}
            />
            {target.trim() !== "" && (
              <span
                className={cn(
                  "shrink-0 rounded px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-normal",
                  isTerminal
                    ? "bg-white/8 text-slate-400"
                    : "bg-muted text-text-muted"
                )}
                title="Detected share type"
              >
                {SHARE_KIND_LABEL[shareKind]}
              </span>
            )}
          </div>
          <div className="flex min-w-0 items-center gap-2">
            <span className={heroControlLabelClass}>Name</span>
            <Input
              type="text"
              value={name}
              onChange={handleNameChange}
              placeholder="optional"
              aria-label="Public name (optional)"
              className={cn(heroControlInputClass, "min-w-0 flex-1")}
            />
          </div>
          <p className={cn("text-xs", isTerminal ? "text-slate-400" : "text-text-muted")}>
            Choose a name for a short public URL without an Ethereum address.
          </p>
          <button
            type="button"
            onClick={() => setAuthOpen((open) => !open)}
            aria-expanded={authOpen}
            aria-controls={authPanelId}
            className={cn(
              "flex w-full min-w-0 items-center gap-2 rounded-md border border-dashed px-3 py-2 text-left text-[13px] transition-colors",
              isTerminal
                ? "border-white/15 text-slate-300 hover:border-primary/60"
                : "border-border text-foreground hover:border-primary/50"
            )}
          >
            <Lock className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
            <span className={heroControlLabelClass}>Who can open it?</span>
            <span className="ml-auto min-w-0 truncate font-semibold">
              {describeAuth(auth)}
            </span>
            <ChevronRight
              aria-hidden="true"
              className={cn(
                "h-4 w-4 shrink-0 transition-transform",
                authOpen && "rotate-90"
              )}
            />
          </button>
          {authOpen && (
            <div id={authPanelId} className="pt-1">
              <TunnelAuthSection
                auth={auth}
                onChange={setAuth}
                issues={authIssues}
                relayUrls={relayUrls}
                discovery={discovery}
                name={effectiveName}
                os={os}
                theme={theme}
                compact
              />
            </div>
          )}
        </div>
        <div>
          <div
            className={cn(
              "relative min-h-37 rounded-lg border px-4 py-4 pr-14 font-mono text-sm leading-7",
              isTerminal
                ? "border-white/10 bg-black/55 text-white shadow-[inset_0_1px_0_rgba(255,255,255,0.05)]"
                : "border-border/80 bg-border/90 text-foreground"
            )}
          >
            <button
              type="button"
              onClick={handleCopy}
              disabled={authIssues.length > 0}
              className={cn(
                "absolute top-4 right-4 inline-flex h-8 w-8 items-center justify-center rounded-md transition-colors disabled:cursor-not-allowed disabled:opacity-40",
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
          <NotReady issues={authIssues} theme={theme} />
        </div>
      </div>

      <div className="space-y-2 pt-1">
        <p className={heroSectionLabelClass}>
          {effectiveName !== "" ? "3. Open this public URL" : "3. Open the URL printed by Portal"}
        </p>
        <div
          className={cn(
            "space-y-3 rounded-lg border px-3.5 py-3",
            isTerminal
              ? "border-white/8 bg-white/4.5"
              : "border-border bg-white"
          )}
        >
          {effectiveName !== "" ? (
            <>
              <div
                className={cn(
                  "flex items-center gap-2 text-[13px] font-semibold",
                  isTerminal ? "text-slate-300" : "text-foreground"
                )}
              >
                <span
                  className={cn("h-2 w-2 rounded-full", serviceStatusTone)}
                  aria-hidden="true"
                />
                <span>{serviceStatusHeadline}</span>
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
            </>
          ) : (
            <div className="space-y-1">
              <p
                className={cn(
                  "text-[13px] font-medium leading-relaxed sm:text-sm",
                  isTerminal ? "text-slate-200" : "text-foreground"
                )}
              >
                Open the URL printed by Portal
              </p>
              <p
                className={cn(
                  "text-xs leading-relaxed sm:text-[13px]",
                  isTerminal ? "text-slate-400" : "text-muted-foreground"
                )}
              >
                Set a name above to request a short URL. Portal prints it when available, alongside the identity-bound URL that includes your Ethereum address.
              </p>
            </div>
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
  const [tunnelTarget, setTunnelTarget] = useState<TunnelCommandOS>("unix");
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
    effectiveName,
    auth,
    setAuth,
    authIssues,
    shareKind,
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
    os: tunnelTarget,
  });
  const udpBlocked = authBlocksUDP(auth);

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

  // Shared text and input styles come from the table; the classes below are
  // this form's own layout.
  const formStyles = TUNNEL_FORM_STYLES[theme];
  const inlineFieldClass = isTerminal
    ? "flex items-center overflow-hidden rounded-lg border border-white/10 bg-white/5"
    : "flex items-center overflow-hidden rounded-md border border-border/80 bg-secondary/55 focus-within:border-ring focus-within:ring-1 focus-within:ring-ring/30 dark:border-white/10 dark:bg-secondary/60";
  const inlinePrefixClass = isTerminal
    ? "shrink-0 border-r border-white/10 px-3 text-xs font-medium uppercase tracking-normal text-slate-400"
    : "shrink-0 border-r border-border px-3 text-[0.82rem] font-medium uppercase tracking-normal text-text-muted dark:border-border dark:text-zinc-400";
  const inlineInputClass = isTerminal
    ? "h-10 border-0 bg-transparent px-3 text-sm text-white placeholder:text-slate-500 shadow-none focus-visible:ring-0"
    : "h-9 border-0 bg-transparent px-3 text-sm font-semibold text-foreground placeholder:text-text-muted shadow-none focus-visible:ring-0 dark:text-zinc-100 dark:placeholder:text-zinc-500";
  const osGroupClass = isTerminal
    ? "flex rounded-lg bg-white/8 p-1"
    : "flex rounded-md bg-border p-1 dark:bg-secondary/60";
  const osButtonClass = (selected: boolean) =>
    cn(
      "flex-1 rounded-sm px-3 py-2 text-sm font-semibold transition-colors",
      isTerminal
        ? selected
          ? "bg-white/8 text-slate-200"
          : "text-slate-400 hover:text-slate-300"
        : selected
          ? "bg-card text-foreground shadow-sm ring-1 ring-border/80 dark:bg-background dark:text-zinc-100 dark:ring-transparent"
          : "text-muted-foreground hover:text-foreground dark:text-zinc-500 dark:hover:text-zinc-300"
    );
  const commandPanelClass = isTerminal
    ? "relative rounded-lg border border-white/10 bg-black/30"
    : "relative rounded-md bg-secondary/55 shadow-sm ring-1 ring-border/70 dark:bg-secondary/60 dark:ring-transparent";
  const commandPreClass = isTerminal
    ? "overflow-x-auto whitespace-pre-wrap break-all p-4 pr-12 font-mono text-sm leading-7 text-white"
    : "overflow-x-auto whitespace-pre-wrap break-all p-3 pr-12 font-mono text-sm leading-7 text-foreground dark:text-zinc-100";

  return (
    <div className={cn("space-y-4 py-1", className)}>
      <div className="space-y-2">
        <label className={formStyles.section}>Platform</label>
        <div className={osGroupClass}>
          <button
            type="button"
            onClick={() => setTunnelTarget("unix")}
            className={osButtonClass(os === "unix")}
          >
            Linux / macOS
          </button>
          <button
            type="button"
            onClick={() => setTunnelTarget("windows")}
            className={osButtonClass(os === "windows")}
          >
            Windows
          </button>
        </div>
      </div>

      <div className="space-y-2">
        <div className="flex items-center gap-2">
          <label htmlFor={`${inputId}-host`} className={formStyles.section}>
            Share
          </label>
          {target.trim() !== "" && (
            <span
              className={cn(
                "rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-normal",
                isTerminal
                  ? "bg-white/8 text-slate-400"
                  : "bg-muted text-text-muted"
              )}
              title="Detected share type"
            >
              {SHARE_KIND_LABEL[shareKind]}
            </span>
          )}
        </div>
        <div className={inlineFieldClass}>
          <span className={inlinePrefixClass}>SHARE=</span>
          <Input
            id={`${inputId}-host`}
            type="text"
            value={target}
            onChange={(event) => setTarget(event.target.value)}
            placeholder={SHARE_PLACEHOLDER}
            aria-label="Local port, URL, or file path to share"
            className={inlineInputClass}
          />
        </div>
        <p className={formStyles.help}>
          Paste what you want to share: a local port (3000), a running URL
          (http://localhost:3000), or a file path
          (file:///Users/me/site/index.html). File paths are served as a static
          site from that folder, so nothing needs to be running locally.
        </p>
      </div>

      <div className="space-y-2">
        <label
          htmlFor={`${inputId}-name`}
          className={formStyles.section}
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
            placeholder="optional"
            className={inlineInputClass}
          />
        </div>
        <p className={formStyles.help}>A unique identifier for your tunnel (optional)</p>
      </div>

      <div className="space-y-2">
        <label className={formStyles.section}>
          Relay URLs
        </label>
        <ChipField
          theme={theme}
          draft={urlInput}
          placeholder="Add relay URL..."
          onDraftChange={setUrlInput}
          onCommit={() => addRelayURL(urlInput)}
          onRemoveLast={() => {
            if (relayUrls.length > 0) {
              setRelayUrls((prev) => prev.slice(0, -1));
            }
          }}
          chips={relayUrls.map((url) => (
            <Chip
              key={url}
              theme={theme}
              text={url}
              removeLabel={`Remove ${url}`}
              removeDisabled={!discoveryEnabled && relayUrls.length <= 1}
              onRemove={() => removeRelayURL(url)}
            />
          ))}
        />
        <p className={formStyles.help}>
          Press Enter to add. Multiple relay servers for redundancy.
        </p>
      </div>

      <div className="space-y-2">
        <div className="flex items-baseline justify-between gap-2">
          <p className={formStyles.section}>Who can open it?</p>
          <span className={formStyles.help}>Default: no sign-in</span>
        </div>
        <TunnelAuthSection
          auth={auth}
          onChange={setAuth}
          issues={authIssues}
          relayUrls={relayUrls}
          discovery={discoveryEnabled}
          name={effectiveName}
          os={os}
          theme={theme}
        />
      </div>

      <div className="space-y-2">
        <label className={formStyles.section}>
          Generated Command
        </label>
        <div>
          <div className={commandPanelClass}>
            <pre className={commandPreClass}>
              <span className="block">{installBlock}</span>
              <span className="mt-2 block">{runBlock}</span>
            </pre>
            <button
              type="button"
              onClick={handleCopy}
              disabled={authIssues.length > 0}
              className={cn(
                "absolute right-2 top-1/2 -translate-y-1/2 rounded-md p-2 transition-colors disabled:cursor-not-allowed disabled:opacity-40",
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
          <NotReady issues={authIssues} theme={theme} />
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
            <div className="mt-3 space-y-4 rounded-md border border-border bg-muted/45 px-4 py-4 dark:border-white/8 dark:bg-background/70">
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
                    checked={enableUDP && !udpBlocked}
                    disabled={udpBlocked}
                    onChange={(event) => {
                      const nextEnabled = event.target.checked;
                      setEnableUDP(nextEnabled);
                      if (!nextEnabled) {
                        setUDPPort("");
                      }
                    }}
                    className="h-4 w-4"
                  />
                  <span>
                    Enable UDP transport
                    {udpBlocked && (
                      <span className={cn("block", formStyles.help)}>
                        Not available with sign-in: Portal can only check
                        visitors on web traffic.
                      </span>
                    )}
                  </span>
                </label>
                {enableUDP && !udpBlocked && (
                  <div className="space-y-1.5">
                    <Input
                      id={`${inputId}-udp-port`}
                      type="text"
                      value={udpPort}
                      onChange={(event) => setUDPPort(event.target.value)}
                      placeholder={target.trim() || DEFAULT_HOST}
                      className={formStyles.input}
                    />
                    <p className={formStyles.help}>
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
                  className={formStyles.input}
                />
                {normalizedThumbnailURL && (
                  <div className="flex h-20 w-20 items-center justify-center overflow-hidden rounded-md border border-border bg-background dark:border-white/10 dark:bg-background">
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

/** Owns its top spacing, so the empty region adds no gap under the command. */
function NotReady({
  issues,
  theme,
}: {
  issues: TunnelAuthIssue[];
  theme: TunnelFormTheme;
}) {
  // Always mounted: a live region announces text that appears inside it.
  return (
    <div role="status" className={cn(issues.length > 0 && "pt-2")}>
      {issues.length > 0 && (
        <Notice tone="warn" theme={theme}>
          Not ready to copy: {issues.map((issue) => issue.message).join(" · ")}
        </Notice>
      )}
    </div>
  );
}
