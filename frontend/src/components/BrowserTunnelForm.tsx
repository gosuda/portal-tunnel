import { useId } from "react";
import { Loader2, Square, Wifi } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";
import type { BrowserTunnelController } from "@/hooks/useBrowserTunnel";

type BrowserTunnelFormProps = {
  tunnel: BrowserTunnelController;
  theme?: "light" | "terminal";
};

export function BrowserTunnelForm({
  tunnel,
  theme = "light",
}: BrowserTunnelFormProps) {
  const isTerminal = theme === "terminal";
  const titleId = useId();
  const {
    name,
    setName,
    body,
    setBody,
    state,
    publicURL,
    error,
    start,
    stop,
  } = tunnel;

  const busy = state === "starting" || state === "stopping";
  return (
    <section
      aria-labelledby={titleId}
      className="w-full pt-1 text-left"
    >
      <div className="flex items-start gap-3">
        <div className="mt-0.5 rounded-md bg-primary/10 p-2 text-primary">
          <Wifi className="h-5 w-5" aria-hidden="true" />
        </div>
        <div>
          <p className="text-xs font-semibold uppercase tracking-normal text-primary">
            Browser connector
          </p>
          <h2
            id={titleId}
            className={cn(
              "mt-1 text-xl font-bold",
              isTerminal ? "text-slate-100" : "text-foreground"
            )}
          >
            Publish a response from this tab
          </h2>
          <p
            className={cn(
              "mt-1 text-sm leading-6",
              isTerminal ? "text-slate-400" : "text-text-muted"
            )}
          >
            HTTPS only. The tunnel runs in this browser and stops when this page closes.
          </p>
        </div>
      </div>

      <div className="mt-5 space-y-3">
        <Input
          value={name}
          onChange={(event) => setName(event.target.value)}
          disabled={busy || state === "ready"}
          aria-label="Browser tunnel name"
          placeholder="Public tunnel name"
          className={cn(
            isTerminal &&
              "border-white/10 bg-white/5 text-white placeholder:text-slate-500"
          )}
        />
        <Input
          value={body}
          onChange={(event) => setBody(event.target.value)}
          disabled={busy || state === "ready"}
          aria-label="Browser tunnel response"
          placeholder="Response body"
          className={cn(
            isTerminal &&
              "border-white/10 bg-white/5 text-white placeholder:text-slate-500"
          )}
        />
      </div>

      <div className="mt-4 flex flex-wrap items-center gap-3">
        {state === "ready" ? (
          <Button type="button" variant="secondary" onClick={stop} disabled={busy}>
            <Square className="h-4 w-4" />
            Stop
          </Button>
        ) : (
          <Button type="button" onClick={start} disabled={busy || name.trim() === ""}>
            {state === "starting" && <Loader2 className="h-4 w-4 animate-spin" />}
            {state === "starting" ? "Starting…" : "Start in browser"}
          </Button>
        )}
        <span
          className={cn(
            "text-sm",
            isTerminal ? "text-slate-400" : "text-text-muted"
          )}
          aria-live="polite"
        >
          {state === "idle" && "Not running"}
          {state === "starting" && "Connecting to this relay…"}
          {state === "stopping" && "Stopping…"}
          {state === "ready" && "Tunnel ready"}
          {state === "error" && "Tunnel stopped"}
        </span>
      </div>

      {publicURL && (
        <a
          href={publicURL}
          target="_blank"
          rel="noopener noreferrer"
          className={cn(
            "mt-4 block overflow-x-auto whitespace-nowrap rounded-md px-3 py-2 font-mono text-sm font-semibold underline-offset-4 hover:underline",
            isTerminal ? "bg-white/5 text-sky-300" : "bg-secondary/60 text-primary"
          )}
        >
          {publicURL}
        </a>
      )}
      {error && <p className="mt-4 text-sm font-medium text-destructive">{error}</p>}
    </section>
  );
}
