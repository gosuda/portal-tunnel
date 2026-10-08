import * as assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  buildCommand,
  resolveTunnelInstallerURL,
  validateRelayUrl,
} from "../command";

describe("Portal commands", () => {
  it("validateRelayUrl accepts only https URLs", () => {
    assert.strictEqual(validateRelayUrl("https://relay.example.com"), undefined);
    assert.strictEqual(validateRelayUrl("http://relay.example.com"), "Portal relay URLs must use https://");
    assert.strictEqual(validateRelayUrl("not-a-url"), "Enter a valid https:// URL");
  });

  it("resolveTunnelInstallerURL maps supported platforms to release installers", () => {
    assert.strictEqual(
      resolveTunnelInstallerURL("darwin", "x64"),
      "https://github.com/gosuda/portal-tunnel/releases/latest/download/install.sh"
    );
    assert.strictEqual(
      resolveTunnelInstallerURL("win32", "arm64"),
      "https://github.com/gosuda/portal-tunnel/releases/latest/download/install.ps1"
    );
    assert.strictEqual(resolveTunnelInstallerURL("linux", "ia32"), undefined);
    assert.strictEqual(resolveTunnelInstallerURL("freebsd", "x64"), undefined);
  });

  it("buildCommand omits --name when empty and runs the unix release installer", () => {
    const command = buildCommand({
      host: "localhost:3000",
      name: "",
      relayList: "https://relay.example.com",
      thumbnail: "",
    }, {
      platform: "linux",
      arch: "x64",
    });

    assert.match(command, /curl -fsSL https:\/\/github\.com\/gosuda\/portal-tunnel\/releases\/latest\/download\/install\.sh -o "\$PORTAL_INSTALLER"/);
    assert.match(command, /sh "\$PORTAL_INSTALLER"/);
    assert.match(command, /PORTAL_BIN="\$\(command -v portal 2>\/dev\/null \|\| true\)"/);
    assert.match(command, /"\$PORTAL_BIN" expose localhost:3000 --relays https:\/\/relay\.example\.com/);
    assert.ok(!command.includes("--name"));
  });

  it("buildCommand can use the default public registry without --relays", () => {
    const command = buildCommand({
      host: "localhost:3000",
      name: "",
      relayList: "",
      thumbnail: "",
    }, {
      platform: "linux",
      arch: "x64",
    });

    assert.ok(!command.includes("--relays"));
    assert.ok(!command.includes("--name"));
    assert.match(command, /"\$PORTAL_BIN" expose localhost:3000/);
  });

  it("buildCommand runs the PowerShell release installer on windows", () => {
    const command = buildCommand({
      host: "localhost:3000",
      name: "my-app",
      relayList: "https://relay.example.com",
      thumbnail: "https://example.com/thumb.png",
    }, {
      platform: "win32",
      arch: "x64",
    });

    assert.match(command, /irm https:\/\/github\.com\/gosuda\/portal-tunnel\/releases\/latest\/download\/install\.ps1 \| iex/);
    assert.match(command, /\$PortalBin = Join-Path \$env:LOCALAPPDATA 'portal\\bin\\portal\.exe'/);
    assert.match(command, /& \$PortalBin expose localhost:3000 --name my-app --relays https:\/\/relay\.example\.com --thumbnail https:\/\/example\.com\/thumb\.png/);
  });
});
