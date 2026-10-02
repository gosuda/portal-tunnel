import { useEffect, useRef, useState } from "react";
import { apiClient } from "@/lib/apiClient";
import { RELAY_API_PATHS } from "@/lib/apiPaths";
import { loadBrowserTunnel } from "@/lib/browserTunnel";
import { buildDefaultExposeName, normalizeExposeName } from "@/lib/exposeName";
import type { DomainResponse } from "@/types/api";

export type BrowserTunnelState =
  | "idle"
  | "starting"
  | "ready"
  | "stopping"
  | "error";

export type BrowserTunnelController = {
  name: string;
  setName: (name: string) => void;
  body: string;
  setBody: (body: string) => void;
  state: BrowserTunnelState;
  publicURL: string;
  error: string;
  start: () => Promise<void>;
  stop: () => Promise<void>;
};

function initialName(): string {
  const seed =
    typeof crypto.randomUUID === "function"
      ? crypto.randomUUID()
      : `${Date.now()}-${Math.random()}`;
  return buildDefaultExposeName("browser", seed);
}

export function useBrowserTunnel(): BrowserTunnelController {
  const mounted = useRef(true);
  const operationInProgress = useRef(false);
  const [name, setName] = useState(initialName);
  const [body, setBody] = useState("Hello from this browser.");
  const [state, setState] = useState<BrowserTunnelState>("idle");
  const [publicURL, setPublicURL] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      void window.portalTunnel?.stop();
    };
  }, []);

  const start = async () => {
    if (operationInProgress.current) {
      return;
    }
    operationInProgress.current = true;
    setState("starting");
    setPublicURL("");
    setError("");
    try {
      const tunnelName = normalizeExposeName(name);
      if (tunnelName === "") {
        throw new Error("A valid tunnel name is required.");
      }
      const domain = await apiClient.get<DomainResponse>(
        RELAY_API_PATHS.sdk.domain
      );
      const runtime = await loadBrowserTunnel(domain.release_version ?? "");
      if (!mounted.current) {
        await runtime.stop();
        return;
      }
      const result = await runtime.start({
        name: tunnelName,
        relayURL: window.location.origin,
        body,
      });
      if (!mounted.current) {
        await runtime.stop();
        return;
      }
      setPublicURL(result.publicURL);
      setState("ready");
    } catch (cause) {
      if (!mounted.current) {
        return;
      }
      setError(
        cause instanceof Error
          ? cause.message
          : "Could not start the browser tunnel."
      );
      setState("error");
    } finally {
      operationInProgress.current = false;
    }
  };

  const stop = async () => {
    if (operationInProgress.current) {
      return;
    }
    operationInProgress.current = true;
    setState("stopping");
    setError("");
    try {
      await window.portalTunnel?.stop();
      if (!mounted.current) {
        return;
      }
      setPublicURL("");
      setState("idle");
    } catch (cause) {
      if (!mounted.current) {
        return;
      }
      setError(
        cause instanceof Error
          ? cause.message
          : "Could not stop the browser tunnel."
      );
      setState("error");
    } finally {
      operationInProgress.current = false;
    }
  };

  return {
    name,
    setName,
    body,
    setBody,
    state,
    publicURL,
    error,
    start,
    stop,
  };
}
