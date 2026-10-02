type GoRuntime = {
  importObject: WebAssembly.Imports;
  run(instance: WebAssembly.Instance): Promise<void>;
};

type GoRuntimeConstructor = new () => GoRuntime;

type PortalTunnelRuntime = {
  start(options: {
    name: string;
    relayURL: string;
    body: string;
  }): Promise<{ publicURL: string }>;
  stop(): Promise<void>;
};

declare global {
  interface Window {
    Go?: GoRuntimeConstructor;
    portalTunnel?: PortalTunnelRuntime;
  }
}

let loadingRuntime: Promise<PortalTunnelRuntime> | undefined;
let loadedVersion = "";

function versionedURL(path: string, releaseVersion: string): string {
  const url = new URL(path, window.location.origin);
  url.searchParams.set("version", releaseVersion);
  return url.toString();
}

function loadScript(src: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const script = document.createElement("script");
    script.src = src;
    script.async = true;
    script.addEventListener("load", () => resolve(), { once: true });
    script.addEventListener(
      "error",
      () => reject(new Error("Could not load the Go WASM runtime.")),
      { once: true }
    );
    document.head.append(script);
  });
}

async function waitForRuntime(): Promise<PortalTunnelRuntime> {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    if (window.portalTunnel) {
      return window.portalTunnel;
    }
    await new Promise((resolve) => window.setTimeout(resolve, 10));
  }
  throw new Error("The browser tunnel runtime did not start.");
}

export function loadBrowserTunnel(
  releaseVersion: string,
  wasmExecPath: string,
  wasmPath: string
): Promise<PortalTunnelRuntime> {
  const version = releaseVersion.trim();
  if (version === "") {
    return Promise.reject(new Error("The relay did not report a release version."));
  }
  if (loadingRuntime) {
    if (loadedVersion !== version) {
      return Promise.reject(
        new Error("Reload this page before starting a different tunnel release.")
      );
    }
    return loadingRuntime;
  }

  loadedVersion = version;
  const pending = (async () => {
    await loadScript(versionedURL(wasmExecPath, version));
    if (!window.Go) {
      throw new Error("The Go WASM runtime is unavailable.");
    }
    const go = new window.Go();
    const response = await fetch(versionedURL(wasmPath, version), {
      cache: "force-cache",
    });
    if (!response.ok) {
      throw new Error(`Could not load the browser connector (${response.status}).`);
    }
    const module = await WebAssembly.instantiateStreaming(response, go.importObject);
    void go.run(module.instance);
    return waitForRuntime();
  })();
  loadingRuntime = pending.catch((error: unknown) => {
    loadingRuntime = undefined;
    loadedVersion = "";
    throw error;
  });
  return loadingRuntime;
}
