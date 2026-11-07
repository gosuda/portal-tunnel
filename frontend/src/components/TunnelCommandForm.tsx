import { useId, useMemo, useState } from "react";
import { Check, ChevronDown, Copy, Settings2 } from "lucide-react";
import { Input } from "@/components/ui/input";
import { TunnelAuthSection } from "@/components/TunnelAuthSection";
import {
  Chip,
  ChipField,
  Notice,
  TUNNEL_FORM_STYLES,
} from "@/components/TunnelFormParts";
import { cn } from "@/lib/utils";
import {
  authBlocksUDP,
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

const TARGET_KIND_LABEL: Record<ShareKind, string> = {
  url: "URL",
  file: "File",
  port: "Port",
};

const TARGET_PLACEHOLDER = "Port, URL, or file path";

export function TunnelCommandForm() {
  const inputId = useId();
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
  const formStyles = TUNNEL_FORM_STYLES;
  const inlineFieldClass = "flex items-center overflow-hidden rounded-md border border-border/80 bg-secondary/55 focus-within:border-ring focus-within:ring-1 focus-within:ring-ring/30 dark:border-white/10 dark:bg-secondary/60";
  const inlineInputClass = "h-9 border-0 bg-transparent px-3 text-sm font-semibold text-foreground placeholder:text-text-muted shadow-none focus-visible:ring-0 dark:text-zinc-100 dark:placeholder:text-zinc-500";
  const osGroupClass = "flex rounded-md bg-border p-1 dark:bg-secondary/60";
  const osButtonClass = (selected: boolean) =>
    cn(
      "flex-1 rounded-sm px-3 py-2 text-sm font-semibold transition-colors",
      selected
        ? "bg-card text-foreground shadow-sm ring-1 ring-border/80 dark:bg-background dark:text-zinc-100 dark:ring-transparent"
        : "text-muted-foreground hover:text-foreground dark:text-zinc-500 dark:hover:text-zinc-300"
    );
  const commandPanelClass = "relative rounded-md bg-secondary/55 shadow-sm ring-1 ring-border/70 dark:bg-secondary/60 dark:ring-transparent";
  const commandPreClass = "overflow-x-auto whitespace-pre-wrap break-all p-3 pr-12 font-mono text-sm leading-7 text-foreground dark:text-zinc-100";

  return (
    <div className="space-y-4 py-1">
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
            Target
          </label>
          {target.trim() !== "" && (
            <span
              className="rounded bg-muted px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-normal text-text-muted"
              title="Detected target type"
            >
              {TARGET_KIND_LABEL[shareKind]}
            </span>
          )}
        </div>
        <div className={inlineFieldClass}>
          <Input
            id={`${inputId}-host`}
            type="text"
            value={target}
            onChange={(event) => setTarget(event.target.value)}
            placeholder={TARGET_PLACEHOLDER}
            aria-label="Local port, URL, or file path to expose"
            className={inlineInputClass}
          />
        </div>
        <div className="flex flex-wrap gap-1.5" aria-label="Accepted targets">
          {[
            ["Port", "3000"],
            ["URL", "localhost:3000"],
            ["File", "index.html"],
          ].map(([kind, example]) => (
            <span key={kind} className="rounded-full border border-border/70 px-2 py-0.5 text-[11px] text-muted-foreground">
              {kind}<span className="mx-1 opacity-60">·</span>{example}
            </span>
          ))}
        </div>
      </div>

      <div className="space-y-2">
        <label
          htmlFor={`${inputId}-name`}
          className={formStyles.section}
        >
          Name <span className="ml-1 text-xs font-normal text-muted-foreground">optional</span>
        </label>
        <div className={inlineFieldClass}>
          <Input
            id={`${inputId}-name`}
            type="text"
            value={name}
            onChange={handleNameChange}
            placeholder="my-app"
            className={inlineInputClass}
          />
        </div>
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
              className="absolute right-2 top-1/2 -translate-y-1/2 rounded-md p-2 transition-colors hover:bg-background/70 disabled:cursor-not-allowed disabled:opacity-40 dark:hover:bg-black/20"
              aria-label="Copy command"
            >
              {copied ? (
                <Check className="h-4 w-4 text-emerald-400" />
              ) : (
                <Copy className="h-4 w-4 text-text-muted dark:text-zinc-500" />
              )}
            </button>
          </div>
          <NotReady issues={authIssues} />
        </div>
      </div>

      <div className="pt-1">
        <button
          type="button"
          onClick={() => setShowAdvanced((current) => !current)}
          aria-expanded={showAdvanced}
          className="flex w-full items-center gap-2 rounded-lg border border-border bg-secondary/60 px-3 py-2.5 text-left text-sm font-semibold text-foreground transition-colors hover:bg-secondary focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-primary"
        >
          <Settings2 className="size-4" aria-hidden="true" />
          <span className="flex-1">Advanced options</span>
          <ChevronDown className={cn("size-4 transition-transform", showAdvanced && "rotate-180")} aria-hidden="true" />
        </button>
        {showAdvanced && (
          <div className="mt-3 space-y-4 rounded-md border border-border bg-muted/45 px-4 py-4 dark:border-white/8 dark:bg-background/70">
            <div className="space-y-2">
              <p className={formStyles.section}>Access</p>
              <TunnelAuthSection
                auth={auth}
                onChange={setAuth}
                issues={authIssues}
                relayUrls={relayUrls}
                discovery={discoveryEnabled}
                name={effectiveName}
                os={os}
              />
            </div>
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
              <label className={formStyles.section}>Relay URLs</label>
              <ChipField
                draft={urlInput}
                placeholder="Relay URL (press Enter)"
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
                    text={url}
                    removeLabel={`Remove ${url}`}
                    removeDisabled={!discoveryEnabled && relayUrls.length <= 1}
                    onRemove={() => removeRelayURL(url)}
                  />
                ))}
              />
            </div>

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
                    Local UDP port to forward. Defaults to the same as Target.
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
    </div>
  );
}

/** Owns its top spacing, so the empty region adds no gap under the command. */
function NotReady({ issues }: { issues: TunnelAuthIssue[] }) {
  // Always mounted: a live region announces text that appears inside it.
  return (
    <div role="status" className={cn(issues.length > 0 && "pt-2")}>
      {issues.length > 0 && (
        <Notice tone="warn">
          Not ready to copy: {issues.map((issue) => issue.message).join(" · ")}
        </Notice>
      )}
    </div>
  );
}
