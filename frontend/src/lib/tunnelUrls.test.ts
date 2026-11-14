import { describe, expect, it } from "vitest";

import { AUTH_CALLBACK_PATH, AUTH_SAML_ACS_PATH } from "@/lib/apiPaths";
import ruleVectors from "@/lib/authRuleVectors.json";
import {
  applicationAuthHost,
  buildAuthIssueCommand,
  buildAuthRedirectURLs,
  buildTunnelPreviewURL,
} from "./tunnelUrls";

describe("tunnelUrls", () => {
  it("binds a private link to the host the gateway reads", () => {
    for (const row of ruleVectors.host) {
      expect(applicationAuthHost(row.address), `address ${JSON.stringify(row.address)}`).toBe(row.host);
    }
  });

  it("gives a redirect address for the short URL on every relay in the command", () => {
    expect(
      buildAuthRedirectURLs(
        [
          "https://portal.example.com",
          "https://relay.example.org/",
          "https://portal.example.com/",
        ],
        "my-app",
        AUTH_CALLBACK_PATH
      )
    ).toEqual([
      "https://my-app.portal.example.com/_portal/auth/callback",
      "https://my-app.relay.example.org/_portal/auth/callback",
    ]);
    expect(
      buildAuthRedirectURLs(
        ["https://relay.example.net:8443", "http://other.example.net:443"],
        "my-app",
        AUTH_CALLBACK_PATH
      )
    ).toEqual([
      "https://my-app.relay.example.net:8443/_portal/auth/callback",
      "https://my-app.other.example.net/_portal/auth/callback",
    ]);
    expect(
      buildAuthRedirectURLs(["https://portal.example.com"], "my-app", AUTH_SAML_ACS_PATH)
    ).toEqual(["https://my-app.portal.example.com/_portal/auth/saml/acs"]);
    expect(buildAuthRedirectURLs(["https://portal.example.com"], "", AUTH_CALLBACK_PATH)).toEqual([]);
    expect(buildAuthRedirectURLs([], "my-app", AUTH_CALLBACK_PATH)).toEqual([]);
  });

  it("binds an invite to the host of the URL the visitor is sent", () => {
    const invite = {
      address: "https://my-app.portal.example.com:443",
      subject: "alice",
      expires: "720h",
      os: "unix" as const,
    };
    expect(buildAuthIssueCommand(invite)).toBe(
      "portal auth issue my-app.portal.example.com --subject alice --expires 720h"
    );
    expect(
      buildAuthIssueCommand({ ...invite, address: "https://other.relay.example.org/" })
    ).toBe("portal auth issue other.relay.example.org --subject alice --expires 720h");
    expect(buildAuthIssueCommand({ ...invite, address: "My-App.localhost:4017" })).toBe(
      "portal auth issue my-app.localhost:4017 --subject alice --expires 720h"
    );
    expect(buildAuthIssueCommand({ ...invite, subject: "Alice Smith" })).toBe(
      "portal auth issue my-app.portal.example.com --subject 'Alice Smith' --expires 720h"
    );
    expect(buildAuthIssueCommand({ ...invite, subject: " " })).toBe("");
    for (const address of [
      "",
      "http://my-app.portal.example.com",
      "https://my-app.portal.example.com/app",
      "https://my-app.portal.example.com/?x=1",
      "https://user@my-app.portal.example.com",
    ]) {
      expect(buildAuthIssueCommand({ ...invite, address })).toBe("");
    }
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
});
