"use strict";

const fs = require("fs");
const path = require("path");
const util = require("util");

const [wasmPath, wasmExecPath, relayURL, name] = process.argv.slice(2);
globalThis.require = require;
globalThis.fs = fs;
globalThis.path = path;
globalThis.TextEncoder = util.TextEncoder;
globalThis.TextDecoder = util.TextDecoder;
globalThis.performance ??= require("perf_hooks").performance;
globalThis.crypto ??= require("crypto");

if (typeof WebSocket === "undefined") {
  throw new Error("browser smoke requires Node.js with global WebSocket support");
}

require(path.resolve(wasmExecPath));

async function waitForPortalTunnel() {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    if (globalThis.portalTunnel) {
      return globalThis.portalTunnel;
    }
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error("portalTunnel was not installed by the WASM artifact");
}

async function main() {
  const go = new Go();
  go.argv = [wasmPath];
  go.env = { ...process.env, TMPDIR: require("os").tmpdir() };
  const module = await WebAssembly.instantiate(fs.readFileSync(wasmPath), go.importObject);
  void go.run(module.instance);
  const runtime = await waitForPortalTunnel();
  const ready = await runtime.start({
    name,
    relayURL,
    body: "portal-browser-smoke-ok",
  });
  process.stdout.write(`PORTAL_READY ${JSON.stringify(ready)}\n`);
  process.stdin.resume();
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
