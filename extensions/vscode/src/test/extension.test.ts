import * as assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  buildCommand,
  resolveTunnelInstallerURL,
  validateRelayUrl,
  validateHost,
} from "../command";

describe("Portal commands", () => {
  it("validateRelayUrl accepts only https URLs", () => {
    assert.strictEqual(validateRelayUrl("https://relay.example.com"), undefined);
    assert.strictEqual(validateRelayUrl("http://relay.example.com"), "Portal relay URLs must use https://");
    assert.strictEqual(validateRelayUrl("not-a-url"), "Enter a valid https:// URL");
  });

  it("validateHost accepts supported local targets", () => {
    for (const host of [
      "3000",
      "localhost:3000",
      "127.0.0.1:8080",
      "[::1]:8080",
      "::1",
      "https://[::1]:8443/",
      "http://localhost:3000/",
    ]) {
      assert.strictEqual(validateHost(host), undefined, host);
    }
  });

  it("validateHost rejects option injection and malformed targets", () => {
    for (const host of [
      "--serve=.",
      " --serve=. ",
      "-h",
      "8080 --serve=.",
      "file:///tmp/index.html",
      "http://localhost:3000/secrets",
      "http://user@localhost:3000",
      "localhost:65536",
      "localhost:0",
      "0",
      "https://%2d%2dserve=.",
    ]) {
      assert.notStrictEqual(validateHost(host), undefined, host);
    }
  });

  it("buildCommand rejects a flag-like host instead of launching it", () => {
    for (const platform of ["linux", "win32"] as const) {
      assert.throws(
        () => buildCommand({
          host: "--serve=.",
          name: "",
          relayList: "https://relay.example.com",
          thumbnail: "",
        }, { platform, arch: "x64" }),
        /Invalid tunnel host/
      );
    }
  });

  it("buildCommand keeps a complex target after the option terminator", () => {
    const opts = {
      host: "http://[::1]:8080/",
      name: "my-app",
      relayList: "",
      thumbnail: "",
    };
    const unix = buildCommand(opts, { platform: "linux", arch: "x64" });
    const windows = buildCommand(opts, { platform: "win32", arch: "x64" });

    assert.ok(unix.includes("\"$PORTAL_BIN\" expose --name my-app -- 'http://[::1]:8080/'"));
    assert.ok(windows.includes("& $PortalBin expose --name my-app -- 'http://[::1]:8080/'"));
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
    assert.match(command, /"\$PORTAL_BIN" expose --relays https:\/\/relay\.example\.com -- localhost:3000/);
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
    assert.match(command, /"\$PORTAL_BIN" expose -- localhost:3000/);
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
    assert.match(command, /& \$PortalBin expose --name my-app --relays https:\/\/relay\.example\.com --thumbnail https:\/\/example\.com\/thumb\.png -- localhost:3000/);
  });
});
