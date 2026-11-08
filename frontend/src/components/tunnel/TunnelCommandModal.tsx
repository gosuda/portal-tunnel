import { useId, useState, type ReactNode } from "react";
import {
  Check,
  ChevronDown,
  Copy,
  Globe,
  Image as ImageIcon,
  Lock,
  Network,
  Terminal,
  type LucideIcon,
} from "lucide-react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/chip";
import { Input } from "@/components/ui/input";
import { AuthSection } from "./AuthSection";
import { ChipInput, Hint, LABEL, Notice, Segmented } from "./fields";
import { DEFAULT_HOST, useTunnelCommand } from "@/hooks/useTunnelCommand";
import { readCurrentOrigin } from "@/lib/origin";
import type { ShareKind } from "@/lib/shareLink";
import {
  authBlocksUDP,
  normalizeAbsoluteHTTPURL,
  type TunnelAuthIssue,
  type TunnelCommandOS,
} from "@/lib/tunnelCommand";

const TARGET_KIND_LABEL: Record<ShareKind, string> = {
  url: "URL",
  file: "File",
  port: "Port",
};

const OS_OPTIONS = [
  { id: "unix", label: "Linux / macOS" },
  { id: "windows", label: "Windows" },
] as const;

export function TunnelCommandModal({ trigger }: { trigger: ReactNode }) {
  return (
    <Dialog>
      <DialogTrigger asChild>{trigger}</DialogTrigger>
      <DialogContent className="h-[92dvh] gap-0 overflow-hidden p-0 min-[600px]:h-[min(760px,90dvh)] min-[600px]:w-[min(1040px,calc(100vw-2rem))]">
        <div className="shrink-0 border-b border-stroke px-6 py-4 pr-16">
          <DialogTitle className="flex items-center gap-2">
            <Terminal className="size-5" aria-hidden="true" />
            Launch App
          </DialogTitle>
          <DialogDescription className="sr-only">
            Configure the app tunnel command.
          </DialogDescription>
        </div>
        <TunnelForm />
      </DialogContent>
    </Dialog>
  );
}

function TunnelForm() {
  const id = useId();
  const currentOrigin = readCurrentOrigin();
  const [os, setOS] = useState<TunnelCommandOS>("unix");
  const [relayUrls, setRelayUrls] = useState<string[]>(() => [currentOrigin]);
  const [discoveryEnabled, setDiscoveryEnabled] = useState(true);
  const [urlInput, setUrlInput] = useState("");
  const [enableUDP, setEnableUDP] = useState(false);
  const [udpPort, setUDPPort] = useState("");
  const [thumbnailURL, setThumbnailURL] = useState("");

  const normalizedThumbnailURL = normalizeAbsoluteHTTPURL(thumbnailURL);
  const thumbnailError =
    thumbnailURL.trim() !== "" && normalizedThumbnailURL === ""
      ? "Thumbnail must be an absolute http:// or https:// URL."
      : "";

  const {
    target,
    setTarget,
    name,
    copied,
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
    os,
  });
  const udpBlocked = authBlocksUDP(auth);
  const lastRelayLocked = !discoveryEnabled && relayUrls.length <= 1;

  const addRelayURL = (url: string) => {
    const trimmed = url.trim();
    if (!trimmed || relayUrls.includes(trimmed)) {
      return;
    }
    try {
      new URL(trimmed);
    } catch {
      return;
    }
    setRelayUrls((prev) => [...prev, trimmed]);
    setUrlInput("");
  };

  const preview = (
    <CommandPreview
      os={os}
      onOSChange={setOS}
      installBlock={installBlock}
      runBlock={runBlock}
      issues={authIssues}
      copied={copied}
      onCopy={handleCopy}
    />
  );

  return (
    <div className="flex min-h-0 flex-1 flex-col min-[900px]:flex-row">
      <div className="min-h-0 flex-1 space-y-4 overflow-y-auto overscroll-contain px-6 py-5">
        <div className="min-[900px]:hidden">{preview}</div>

        <div className="space-y-4">
          <div className="space-y-1.5">
            <div className="flex items-center gap-2">
              <label htmlFor={`${id}-target`} className={LABEL}>
                Target
              </label>
              {target.trim() !== "" && (
                <Badge title="Detected target type">
                  {TARGET_KIND_LABEL[shareKind]}
                </Badge>
              )}
            </div>
            <Input
              id={`${id}-target`}
              type="text"
              value={target}
              onChange={(event) => setTarget(event.target.value)}
              placeholder="Port, URL, or file path"
              aria-label="Local port, URL, or file path to expose"
              autoComplete="off"
              spellCheck={false}
            />
            <Hint>Accepted: port 3000 · URL localhost:3000 · file index.html</Hint>
          </div>

          <div className="space-y-1.5">
            <label htmlFor={`${id}-name`} className={LABEL}>
              Name <span className="font-normal text-content-muted">(optional)</span>
            </label>
            <Input
              id={`${id}-name`}
              type="text"
              value={name}
              onChange={handleNameChange}
              placeholder="my-app"
              autoComplete="off"
              spellCheck={false}
            />
          </div>
        </div>

        <Section title="Access" icon={Lock}>
          <AuthSection
            auth={auth}
            onChange={setAuth}
            issues={authIssues}
            relayUrls={relayUrls}
            discovery={discoveryEnabled}
            name={effectiveName}
            os={os}
          />
        </Section>

        <Section title="Relays" icon={Globe}>
          <label className="flex cursor-pointer items-center gap-2.5 text-sm text-content-emphasis">
            <input
              type="checkbox"
              checked={discoveryEnabled}
              onChange={(event) => {
                setDiscoveryEnabled(event.target.checked);
                if (!event.target.checked && relayUrls.length === 0) {
                  setRelayUrls([currentOrigin]);
                }
              }}
              className="size-4"
            />
            Enable relay discovery
          </label>
          <div className="space-y-1.5">
            <label htmlFor={`${id}-relay`} className={LABEL}>
              Relay URLs
            </label>
            <ChipInput
              id={`${id}-relay`}
              draft={urlInput}
              placeholder="Relay URL (press Enter)"
              onDraftChange={setUrlInput}
              onCommit={() => addRelayURL(urlInput)}
              onRemoveLast={() => setRelayUrls((prev) => prev.slice(0, -1))}
              chips={relayUrls.map((url) => ({
                text: url,
                removeLabel: `Remove ${url}`,
                removeDisabled: lastRelayLocked,
                onRemove: () =>
                  setRelayUrls((prev) =>
                    prev.filter((candidate) => candidate !== url)
                  ),
              }))}
            />
          </div>
        </Section>

        <Section title="Transport" icon={Network}>
          <label className="flex cursor-pointer items-start gap-2.5 text-sm text-content-emphasis">
            <input
              type="checkbox"
              checked={enableUDP && !udpBlocked}
              disabled={udpBlocked}
              onChange={(event) => {
                setEnableUDP(event.target.checked);
                if (!event.target.checked) {
                  setUDPPort("");
                }
              }}
              className="mt-0.5 size-4"
            />
            <span>
              Enable UDP transport
              {udpBlocked && (
                <Hint>
                  Not available with sign-in: Portal can only check visitors on
                  web traffic.
                </Hint>
              )}
            </span>
          </label>
          {enableUDP && !udpBlocked && (
            <div className="space-y-1.5">
              <label htmlFor={`${id}-udp`} className={LABEL}>
                UDP port
              </label>
              <Input
                id={`${id}-udp`}
                type="text"
                value={udpPort}
                onChange={(event) => setUDPPort(event.target.value)}
                placeholder={target.trim() || DEFAULT_HOST}
              />
              <Hint>Local UDP port to forward. Defaults to the same as Target.</Hint>
            </div>
          )}
        </Section>

        <Section title="Thumbnail" icon={ImageIcon}>
          <div className="space-y-1.5">
            <label htmlFor={`${id}-thumb`} className={LABEL}>
              Thumbnail URL
            </label>
            <Input
              id={`${id}-thumb`}
              type="url"
              value={thumbnailURL}
              onChange={(event) => setThumbnailURL(event.target.value)}
              placeholder="https://cdn.example.com/thumb.png"
            />
            {thumbnailError && <Notice tone="error">{thumbnailError}</Notice>}
          </div>
          {normalizedThumbnailURL && (
            <img
              src={normalizedThumbnailURL}
              alt="Thumbnail preview"
              className="aspect-video w-48 rounded-md border border-stroke object-cover"
            />
          )}
        </Section>
      </div>

      <aside className="hidden w-[400px] shrink-0 flex-col overflow-y-auto border-l border-stroke bg-surface-0 p-5 min-[900px]:flex">
        {preview}
      </aside>

      <div className="shrink-0 border-t border-stroke bg-surface-100 p-3 min-[900px]:hidden">
        <Button
          variant="primary"
          size="lg"
          className="w-full"
          disabled={authIssues.length > 0}
          onClick={handleCopy}
        >
          {copied ? <Check className="size-5" /> : <Copy className="size-5" />}
          {copied ? "Copied" : "Copy command"}
        </Button>
      </div>
    </div>
  );
}

function Section({
  title,
  icon: Icon,
  children,
}: {
  title: string;
  icon: LucideIcon;
  children: ReactNode;
}) {
  return (
    <details className="group rounded-lg border border-stroke">
      <summary className="interactive flex h-12 cursor-pointer list-none items-center gap-2 rounded-lg px-4 text-sm font-bold text-content-emphasis [&::-webkit-details-marker]:hidden">
        <Icon className="size-4" aria-hidden="true" />
        <span className="flex-1">{title}</span>
        <ChevronDown
          className="size-4 motion-safe:transition-transform group-open:rotate-180"
          aria-hidden="true"
        />
      </summary>
      <div className="space-y-4 px-4 pb-4 pt-1">{children}</div>
    </details>
  );
}

function CommandPreview({
  os,
  onOSChange,
  installBlock,
  runBlock,
  issues,
  copied,
  onCopy,
}: {
  os: TunnelCommandOS;
  onOSChange: (os: TunnelCommandOS) => void;
  installBlock: string;
  runBlock: string;
  issues: TunnelAuthIssue[];
  copied: boolean;
  onCopy: () => void;
}) {
  return (
    <div className="space-y-3 min-[900px]:sticky min-[900px]:top-0">
      <h3 className="text-sm font-bold text-content-emphasis">Command</h3>
      <Segmented
        label="Platform"
        options={OS_OPTIONS}
        value={os}
        onChange={onOSChange}
      />
      <pre className="whitespace-pre-wrap break-all rounded-lg bg-surface-200 p-3 font-mono text-[13px] leading-6 text-content-emphasis">
        <span className="block">{installBlock}</span>
        <span className="mt-2 block">{runBlock}</span>
      </pre>
      <Button
        variant="primary"
        className="hidden w-full min-[900px]:inline-flex"
        disabled={issues.length > 0}
        onClick={onCopy}
      >
        {copied ? <Check className="size-4" /> : <Copy className="size-4" />}
        {copied ? "Copied" : "Copy command"}
      </Button>
      <div role="status">
        {issues.length > 0 && (
          <Notice tone="warn">
            Not ready to copy: {issues.map((issue) => issue.message).join(" · ")}
          </Notice>
        )}
      </div>
    </div>
  );
}
