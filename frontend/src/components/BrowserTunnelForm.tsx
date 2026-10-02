import { useEffect, useState } from "react";
import { Loader2, Square, Wifi } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { apiClient } from "@/lib/apiClient";
import { RELAY_API_PATHS } from "@/lib/apiPaths";
import { loadBrowserTunnel } from "@/lib/browserTunnel";
import type { DomainResponse } from "@/types/api";

type TunnelState = "idle" | "starting" | "ready" | "stopping" | "error";

function initialName(): string {
  return `browser-${crypto.randomUUID().slice(0, 8)}`;
}

export function BrowserTunnelForm() {
  const [name, setName] = useState(initialName);
  const [body, setBody] = useState("Hello from this browser.");
  const [state, setState] = useState<TunnelState>("idle");
  const [publicURL, setPublicURL] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    return () => {
      void window.portalTunnel?.stop();
    };
  }, []);

  const start = async () => {
    setState("starting");
    setPublicURL("");
    setError("");
    try {
      const domain = await apiClient.get<DomainResponse>(RELAY_API_PATHS.sdk.domain);
      const runtime = await loadBrowserTunnel(
        domain.release_version ?? "",
        RELAY_API_PATHS.install.wasmExec,
        RELAY_API_PATHS.install.browserWasm
      );
      const result = await runtime.start({
        name: name.trim(),
        relayURL: window.location.origin,
        body,
      });
      setPublicURL(result.publicURL);
      setState("ready");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Could not start the browser tunnel.");
      setState("error");
    }
  };

  const stop = async () => {
    setState("stopping");
    setError("");
    try {
      await window.portalTunnel?.stop();
      setPublicURL("");
      setState("idle");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Could not stop the browser tunnel.");
      setState("error");
    }
  };

  const busy = state === "starting" || state === "stopping";
  return (
    <section
      id="browser-tunnel"
      aria-labelledby="browser-tunnel-title"
      className="mx-auto mt-6 w-full max-w-150 rounded-lg border border-border/80 bg-background p-5 text-left shadow-sm sm:p-6"
    >
      <div className="flex items-start gap-3">
        <div className="mt-0.5 rounded-md bg-primary/10 p-2 text-primary">
          <Wifi className="h-5 w-5" aria-hidden="true" />
        </div>
        <div>
          <p className="text-xs font-semibold uppercase tracking-normal text-primary">
            Browser connector
          </p>
          <h2 id="browser-tunnel-title" className="mt-1 text-xl font-bold text-foreground">
            Publish a response from this tab
          </h2>
          <p className="mt-1 text-sm leading-6 text-text-muted">
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
        />
        <Input
          value={body}
          onChange={(event) => setBody(event.target.value)}
          disabled={busy || state === "ready"}
          aria-label="Browser tunnel response"
          placeholder="Response body"
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
        <span className="text-sm text-text-muted" aria-live="polite">
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
          className="mt-4 block overflow-x-auto whitespace-nowrap rounded-md bg-secondary/60 px-3 py-2 font-mono text-sm font-semibold text-primary underline-offset-4 hover:underline"
        >
          {publicURL}
        </a>
      )}
      {error && <p className="mt-4 text-sm font-medium text-destructive">{error}</p>}
    </section>
  );
}
