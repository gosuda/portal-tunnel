import { describe, expect, it } from "vitest";

import {
  buildTunnelCommand,
  buildTunnelDisplayCommand,
  buildTunnelPreviewURL,
} from "@/lib/tunnelCommand";

describe("tunnelCommand", () => {
  it("keeps copied unix commands flat and directly pasteable", () => {
    const options = {
      currentOrigin: "https://localhost",
      target: "3000",
      name: "My App",
      nameSeed: "web_portal",
      relayUrls: ["https://localhost"],
      discovery: true,
      thumbnailURL: "",
      os: "unix" as const,
    };

    const command = buildTunnelCommand(options);

    expect(command).toBe(
      [
        "curl -ksSL https://localhost/api/install.sh | bash",
        "portal expose 3000 --name my-app --relays https://localhost",
      ].join("\n")
    );
    expect(command).not.toContain(" \\\n");
    expect(command).not.toContain("\n  --name");
  });

  it("keeps display and copied commands flat", () => {
    const options = {
      currentOrigin: "https://relay.example.com",
      target: "localhost:3000",
      name: "my-app",
      nameSeed: "web_portal",
      relayUrls: ["https://relay.example.com"],
      discovery: false,
      thumbnailURL: "https://example.com/thumb.png",
      os: "windows" as const,
    };

    expect(buildTunnelCommand(options)).toBe(
      [
        `$ProgressPreference = 'SilentlyContinue'`,
        `irm https://relay.example.com/api/install.ps1 | iex`,
        `portal expose localhost:3000 --name my-app --relays https://relay.example.com --discovery=false --thumbnail https://example.com/thumb.png`,
      ].join("\n")
    );
    expect(buildTunnelDisplayCommand(options)).toBe(
      [
        `$ProgressPreference = 'SilentlyContinue'`,
        `irm https://relay.example.com/api/install.ps1 | iex`,
        `portal expose localhost:3000 --name my-app --relays https://relay.example.com --discovery=false --thumbnail https://example.com/thumb.png`,
      ].join("\n")
    );
  });

  it("serves a static path with --serve for file share links", () => {
    const options = {
      currentOrigin: "https://localhost",
      target: "",
      name: "my-app",
      nameSeed: "web_portal",
      relayUrls: ["https://localhost"],
      discovery: true,
      thumbnailURL: "",
      os: "unix" as const,
      shareKind: "file" as const,
      servePath: "/Users/me/site/main.html",
    };

    expect(buildTunnelCommand(options)).toBe(
      [
        "curl -ksSL https://localhost/api/install.sh | bash",
        "portal expose --serve /Users/me/site/main.html --name my-app --relays https://localhost",
      ].join("\n")
    );
  });

  it("quotes serve paths that contain spaces per OS", () => {
    const base = {
      currentOrigin: "https://relay.example.com",
      target: "",
      name: "my-app",
      nameSeed: "web_portal",
      relayUrls: ["https://relay.example.com"],
      discovery: true,
      thumbnailURL: "",
      shareKind: "file" as const,
    };

    expect(
      buildTunnelCommand({
        ...base,
        os: "unix",
        servePath: "/Users/me/my site/main.html",
      })
    ).toContain("portal expose --serve '/Users/me/my site/main.html' --name my-app");

    expect(
      buildTunnelCommand({
        ...base,
        os: "windows",
        servePath: "C:\\Users\\me\\site\\main.html",
      })
    ).toContain(`portal expose --serve 'C:\\Users\\me\\site\\main.html' --name my-app`);
  });

  it("uses the relay root host for preview URLs instead of a placeholder host", () => {
    expect(
      buildTunnelPreviewURL(
        "https://localhost",
        "my-app",
        "3000",
        "web_portal"
      )
    ).toBe("https://my-app.localhost");

    expect(
      buildTunnelPreviewURL(
        "https://portal.example.com",
        "my-app",
        "3000",
        "web_portal"
      )
    ).toBe("https://my-app.portal.example.com");
  });
});
