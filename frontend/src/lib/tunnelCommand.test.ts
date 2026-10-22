import { describe, expect, it } from "vitest";

import {
  buildAuthIssueCommand,
  buildAuthRedirectURL,
  buildTunnelCommand,
  buildTunnelPreviewURL,
  classifyAuthAllow,
  validateTunnelAuth,
  type TunnelAuthOptions,
} from "@/lib/tunnelCommand";

describe("tunnelCommand", () => {
  it("keeps copied unix commands flat and directly pasteable", () => {
    const options = {
      currentOrigin: "https://localhost",
      target: "3000",
      name: "My App",
      relayUrls: ["https://localhost"],
      discovery: true,
      thumbnailURL: "",
      os: "unix" as const,
    };

    const command = buildTunnelCommand(options);

    expect(command).toBe(
      [
        `curl -ksSL https://localhost/api/install.sh | bash && export PATH="$HOME/.local/bin:$HOME/bin:$PATH"`,
        "portal expose 3000 --name my-app --relays https://localhost",
      ].join("\n")
    );
    expect(command).not.toContain(" \\\n");
    expect(command).not.toContain("\n  --name");
  });

  it("keeps Windows commands flat with their install prelude", () => {
    const options = {
      currentOrigin: "https://relay.example.com",
      target: "localhost:3000",
      name: "my-app",
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
  });

  it("serves a static path with --serve for file share links", () => {
    const options = {
      currentOrigin: "https://localhost",
      target: "",
      name: "my-app",
      relayUrls: ["https://localhost"],
      discovery: true,
      thumbnailURL: "",
      os: "unix" as const,
      shareKind: "file" as const,
      servePath: "/Users/me/site/main.html",
    };

    expect(buildTunnelCommand(options)).toBe(
      [
        `curl -ksSL https://localhost/api/install.sh | bash && export PATH="$HOME/.local/bin:$HOME/bin:$PATH"`,
        "portal expose --serve /Users/me/site/main.html --name my-app --relays https://localhost",
      ].join("\n")
    );
  });

  it("quotes serve paths that contain spaces per OS", () => {
    const base = {
      currentOrigin: "https://relay.example.com",
      target: "",
      name: "my-app",
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
        "my-app"
      )
    ).toBe("https://my-app.localhost");

    expect(
      buildTunnelPreviewURL(
        "https://portal.example.com",
        "my-app"
      )
    ).toBe("https://my-app.portal.example.com");
  });

  it("omits --name and returns empty preview URL when name is blank", () => {
    const options = {
      currentOrigin: "https://localhost",
      target: "3000",
      name: "",
      relayUrls: ["https://localhost"],
      discovery: true,
      thumbnailURL: "",
      os: "unix" as const,
    };

    const command = buildTunnelCommand(options);
    expect(command).toBe(
      [
        `curl -ksSL https://localhost/api/install.sh | bash && export PATH="$HOME/.local/bin:$HOME/bin:$PATH"`,
        "portal expose 3000 --relays https://localhost",
      ].join("\n")
    );
    expect(command).not.toContain("--name");

    expect(buildTunnelPreviewURL("https://localhost", "")).toBe("");
    expect(buildTunnelPreviewURL("https://portal.example.com", "   ")).toBe("");
  });
});

describe("tunnelCommand sign-in", () => {
  const base = {
    currentOrigin: "https://relay.example.com",
    target: "3000",
    name: "my-app",
    relayUrls: ["https://relay.example.com"],
    discovery: true,
    thumbnailURL: "",
    os: "unix" as const,
  };
  const none: TunnelAuthOptions = {
    method: "none",
    allow: [],
    identityHeaders: false,
    oidcIssuer: "",
    oidcClientId: "",
  };
  const runLine = (command: string) => command.split("\n").slice(1).join("\n");

  it("adds no auth flags unless a method is chosen", () => {
    const command = buildTunnelCommand({
      ...base,
      auth: { ...none, allow: ["alice"], identityHeaders: true },
    });

    expect(runLine(command)).toBe(
      "portal expose 3000 --name my-app --relays https://relay.example.com"
    );
  });

  it("prints the private link, wallet and identity header flags", () => {
    expect(
      runLine(
        buildTunnelCommand({
          ...base,
          auth: { ...none, method: "credential", allow: ["alice", "bob"] },
        })
      )
    ).toBe(
      "portal expose 3000 --name my-app --relays https://relay.example.com --auth credential --auth-allow alice --auth-allow bob"
    );

    const wallet = "0x1234567890abcdef1234567890abcdef12345678";
    expect(
      runLine(
        buildTunnelCommand({
          ...base,
          auth: {
            ...none,
            method: "siwe",
            allow: [wallet],
            identityHeaders: true,
          },
        })
      )
    ).toBe(
      `portal expose 3000 --name my-app --relays https://relay.example.com --auth siwe --auth-allow ${wallet} --auth-identity-headers`
    );
  });

  it("keeps the OIDC client secret out of the command and on its own line", () => {
    const auth: TunnelAuthOptions = {
      ...none,
      method: "oidc",
      allow: ["alice@example.com", "@example.com"],
      oidcIssuer: "https://accounts.google.com",
      oidcClientId: "abc.apps.googleusercontent.com",
    };
    const unix = buildTunnelCommand({ ...base, auth }).split("\n");
    const windows = buildTunnelCommand({ ...base, os: "windows", auth }).split(
      "\n"
    );

    expect(unix[1]).toBe("export AUTH_OIDC_CLIENT_SECRET='<paste secret here>'");
    expect(unix[2]).toBe(
      "portal expose 3000 --name my-app --relays https://relay.example.com --auth oidc --auth-oidc-issuer https://accounts.google.com --auth-oidc-client-id abc.apps.googleusercontent.com --auth-allow 'alice@example.com' --auth-allow '@example.com'"
    );
    expect(windows[2]).toBe(
      "$env:AUTH_OIDC_CLIENT_SECRET = '<paste secret here>'"
    );
    expect(windows[3]).toContain("--auth-allow 'alice@example.com'");
    expect(unix.join("\n")).not.toContain("--auth-oidc-client-secret");
  });

  it("serves a static folder behind a private link", () => {
    expect(
      runLine(
        buildTunnelCommand({
          ...base,
          target: "",
          name: "my-site",
          shareKind: "file",
          servePath: "/Users/me/site",
          auth: { ...none, method: "credential" },
        })
      )
    ).toBe(
      "portal expose --serve /Users/me/site --name my-site --relays https://relay.example.com --auth credential"
    );
  });

  it("drops UDP when sign-in is on, because the tunnel refuses the pair", () => {
    const command = buildTunnelCommand({
      ...base,
      enableUDP: true,
      udpPort: "9000",
      auth: { ...none, method: "credential" },
    });

    expect(command).not.toContain("--udp");
    expect(
      buildTunnelCommand({ ...base, enableUDP: true, udpPort: "9000" })
    ).toContain("--udp --udp-addr 9000");
  });

  it("classifies allowlist entries the way the tunnel accepts them", () => {
    const kind = (method: Parameters<typeof classifyAuthAllow>[0], entry: string) => {
      const check = classifyAuthAllow(method, entry);
      return check.ok ? check.kind : "invalid";
    };

    expect(kind("credential", "alice")).toBe("link name");
    expect(kind("siwe", "0x1234567890abcdef1234567890abcdef12345678")).toBe("wallet");
    expect(kind("siwe", "0x1234")).toBe("invalid");
    expect(kind("siwe", "1234567890abcdef1234567890abcdef12345678")).toBe("invalid");
    expect(kind("oidc", "alice@example.com")).toBe("person");
    expect(kind("oidc", "@example.com")).toBe("domain");
    expect(kind("oidc", "sub:AbC123")).toBe("account id");
    expect(kind("oidc", "SUB:AbC123")).toBe("account id");
    expect(kind("oidc", "sub:")).toBe("invalid");
    expect(kind("oidc", "alice")).toBe("invalid");
    expect(kind("oidc", "alice@")).toBe("invalid");
    expect(kind("oidc", "alice@exämple.com")).toBe("invalid");
  });

  it("lists what keeps an OIDC command from running as shown", () => {
    const oidc: TunnelAuthOptions = { ...none, method: "oidc" };

    expect(validateTunnelAuth(oidc, "")).toEqual([
      "Add who may sign in",
      "The issuer must be an https:// address",
      "Add the client ID",
      "Add a Name: the provider needs the exact redirect address",
    ]);
    expect(
      validateTunnelAuth(
        {
          ...oidc,
          allow: ["alice@example.com"],
          oidcIssuer: "https://accounts.google.com",
          oidcClientId: "abc",
        },
        "my-app"
      )
    ).toEqual([]);
    expect(
      validateTunnelAuth(
        {
          ...oidc,
          allow: ["alice"],
          oidcIssuer: "http://login.example.com",
          oidcClientId: "abc",
        },
        "my-app"
      )
    ).toEqual([
      "The issuer must be an https:// address",
      "Fix the highlighted entries",
    ]);
  });

  it("accepts open private-link and wallet lists but flags malformed entries", () => {
    expect(validateTunnelAuth({ ...none, method: "credential" }, "")).toEqual([]);
    expect(validateTunnelAuth({ ...none, method: "siwe" }, "")).toEqual([]);
    expect(
      validateTunnelAuth({ ...none, method: "siwe", allow: ["0x12"] }, "")
    ).toEqual(["Fix the highlighted entries"]);
    expect(validateTunnelAuth(none, "")).toEqual([]);
  });

  it("derives the redirect address and the invite command from the name", () => {
    expect(buildAuthRedirectURL("https://portal.example.com", "my-app")).toBe(
      "https://my-app.portal.example.com/_portal/auth/callback"
    );
    expect(buildAuthRedirectURL("https://portal.example.com", "")).toBe("");

    const invite = {
      origin: "https://portal.example.com",
      name: "my-app",
      subject: "alice",
      expires: "720h",
      os: "unix" as const,
    };
    expect(buildAuthIssueCommand(invite)).toBe(
      "portal auth issue my-app.portal.example.com --subject alice --expires 720h"
    );
    expect(buildAuthIssueCommand({ ...invite, subject: "Alice Smith" })).toBe(
      "portal auth issue my-app.portal.example.com --subject 'Alice Smith' --expires 720h"
    );
    expect(buildAuthIssueCommand({ ...invite, name: "" })).toBe("");
    expect(buildAuthIssueCommand({ ...invite, subject: " " })).toBe("");
  });
});
