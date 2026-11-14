import { describe, expect, it } from "vitest";

import ruleVectors from "@/lib/authRuleVectors.json";
import { buildTunnelCommand } from "./tunnelCommand";
import {
  DEFAULT_TUNNEL_AUTH,
  addAuthAllow,
  authBlocksUDP,
  buildSecretCommand,
  classifyAuthAllow,
  isListedSubject,
  validateTunnelAuth,
  type TunnelAuthOptions,
} from "./tunnelAuth";

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
    samlMetadataURL: "",
    samlEntityId: "",
    samlSubjectAttribute: "",
    emailSMTPAddr: "",
    emailSMTPUsername: "",
    emailFrom: "",
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

  it("prints the OIDC flags without the client secret, which is never in the copied command", () => {
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

    expect(unix).toHaveLength(2);
    expect(unix[1]).toBe(
      "portal expose 3000 --name my-app --relays https://relay.example.com --auth oidc --auth-oidc-issuer https://accounts.google.com --auth-oidc-client-id abc.apps.googleusercontent.com --auth-email-list 'alice@example.com' --auth-email-list '@example.com'"
    );
    expect(windows).toHaveLength(3);
    expect(windows[2]).toContain("--auth-email-list 'alice@example.com'");
    expect(unix.join("\n")).not.toMatch(/SECRET|secret/);
    expect(windows.join("\n")).not.toMatch(/SECRET|secret/);
  });

  it("prints the SAML flags, and the optional ones only when set", () => {
    const auth: TunnelAuthOptions = {
      ...none,
      method: "saml",
      allow: ["@example.com"],
      samlMetadataURL: "https://idp.example/realms/main/protocol/saml/descriptor",
    };
    expect(runLine(buildTunnelCommand({ ...base, auth }))).toBe(
      "portal expose 3000 --name my-app --relays https://relay.example.com --auth saml --auth-saml-metadata-url https://idp.example/realms/main/protocol/saml/descriptor --auth-email-list '@example.com'"
    );
    expect(
      runLine(
        buildTunnelCommand({
          ...base,
          auth: { ...auth, allow: [], samlEntityId: " urn:portal:app ", samlSubjectAttribute: "email" },
        })
      )
    ).toBe(
      "portal expose 3000 --name my-app --relays https://relay.example.com --auth saml --auth-saml-metadata-url https://idp.example/realms/main/protocol/saml/descriptor --auth-saml-entity-id urn:portal:app --auth-saml-subject-attribute email --auth-email-list <email, @domain or sub:id>"
    );
  });

  it("lists what keeps a SAML command from running as shown", () => {
    const saml: TunnelAuthOptions = { ...none, method: "saml" };
    const blocking = (auth: TunnelAuthOptions) =>
      validateTunnelAuth(auth).map((issue) => issue.field);

    expect(blocking(saml)).toEqual(["allow", "metadataURL"]);
    expect(
      blocking({ ...saml, allow: ["alice@example.com"], samlMetadataURL: "https://idp.example/metadata" })
    ).toEqual([]);
  });

  it("prints the email flags without the SMTP password, which is never in the copied command", () => {
    const auth: TunnelAuthOptions = {
      ...none,
      method: "email",
      allow: ["alice@example.com", "@example.com"],
      emailSMTPAddr: "smtp.example.com:587",
      emailFrom: "Portal <login@example.com>",
      emailSMTPUsername: "login@example.com",
    };
    const command = runLine(buildTunnelCommand({ ...base, auth }));
    expect(command).toBe(
      "portal expose 3000 --name my-app --relays https://relay.example.com --auth email --auth-smtp-addr smtp.example.com:587 --auth-smtp-from 'Portal <login@example.com>' --auth-smtp-username 'login@example.com' --auth-email-list 'alice@example.com' --auth-email-list '@example.com'"
    );
    expect(command).not.toMatch(/PASSWORD|password/);
    expect(
      runLine(
        buildTunnelCommand({
          ...base,
          auth: { ...none, method: "email" },
        })
      )
    ).toBe(
      "portal expose 3000 --name my-app --relays https://relay.example.com --auth email --auth-smtp-addr <host:port> --auth-smtp-from <sender> --auth-email-list <email or @domain>"
    );
  });

  it("lists what keeps an email command from running as shown", () => {
    const email: TunnelAuthOptions = { ...none, method: "email" };
    const blocking = (auth: TunnelAuthOptions) =>
      validateTunnelAuth(auth).map((issue) => issue.field);

    expect(blocking(email)).toEqual(["allow", "smtpAddr", "from"]);
    expect(
      blocking({
        ...email,
        allow: ["alice@example.com"],
        emailSMTPAddr: "smtp.example.com:465",
        emailFrom: "login@example.com",
      })
    ).toEqual([]);
    expect(
      blocking({
        ...email,
        allow: ["sub:alice"],
        emailSMTPAddr: "smtp.example.com",
        emailFrom: "login@example.com",
      })
    ).toEqual(["smtpAddr", "entries"]);
  });

  it("reads a secret at a prompt instead of through a placeholder", () => {
    expect(buildSecretCommand("oidc", "unix")).toBe(
      "printf 'OIDC client secret: '; stty -echo; read -r AUTH_OIDC_CLIENT_SECRET; stty echo; echo; export AUTH_OIDC_CLIENT_SECRET"
    );
    expect(buildSecretCommand("oidc", "windows")).toBe(
      "$secret = Read-Host 'OIDC client secret' -AsSecureString; $env:AUTH_OIDC_CLIENT_SECRET = [System.Net.NetworkCredential]::new('', $secret).Password"
    );
    expect(buildSecretCommand("email", "unix")).toBe(
      "printf 'SMTP password: '; stty -echo; read -r AUTH_SMTP_PASSWORD; stty echo; echo; export AUTH_SMTP_PASSWORD"
    );
    expect(buildSecretCommand("email", "windows")).toBe(
      "$secret = Read-Host 'SMTP password' -AsSecureString; $env:AUTH_SMTP_PASSWORD = [System.Net.NetworkCredential]::new('', $secret).Password"
    );
    expect(buildSecretCommand("oidc", "unix")).not.toContain("<");
  });

  it("quotes free-text entries so PowerShell reads every quote literally", () => {
    const auth: TunnelAuthOptions = {
      ...none,
      method: "credential",
      allow: ["O'Brien", "O’Brien", "‘a‚ b‛"],
    };

    expect(runLine(buildTunnelCommand({ ...base, os: "windows", auth }))).toContain(
      "--auth credential --auth-allow 'O''Brien' --auth-allow 'O’’Brien' --auth-allow '‘‘a‚‚ b‛‛'"
    );
    expect(runLine(buildTunnelCommand({ ...base, auth }))).toContain(
      `--auth credential --auth-allow 'O'"'"'Brien' --auth-allow 'O’Brien' --auth-allow '‘a‚ b‛'`
    );
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
    expect(authBlocksUDP({ ...none, method: "credential" })).toBe(true);
    expect(authBlocksUDP(none)).toBe(false);
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

  it("counts the 256-character subject limit in bytes, as the tunnel does", () => {
    const kind = (method: Parameters<typeof classifyAuthAllow>[0], entry: string) =>
      classifyAuthAllow(method, entry).ok;

    expect(kind("credential", "a".repeat(256))).toBe(true);
    expect(kind("credential", "a".repeat(257))).toBe(false);
    expect(kind("credential", "가".repeat(100))).toBe(false);
    expect(kind("credential", "가".repeat(85))).toBe(true);
    expect(kind("oidc", `${"a".repeat(250)}@example.com`)).toBe(false);
    expect(kind("oidc", `sub:${"a".repeat(256)}`)).toBe(true);
    expect(kind("oidc", `sub:${"a".repeat(257)}`)).toBe(false);
  });

  it("adds entries the way the tunnel reads them", () => {
    expect(addAuthAllow("oidc", [], "Alice@Example.com, alice@example.com,  @Example.COM")).toEqual([
      "alice@example.com",
      "@example.com",
    ]);
    expect(addAuthAllow("oidc", ["sub:AbC"], "SUB:AbC, SUB:abc")).toEqual([
      "sub:AbC",
      "sub:abc",
    ]);
    const wallet = "0xAbCdEf1234567890abcdef1234567890ABCDEF12";
    expect(addAuthAllow("siwe", [wallet], wallet.toLowerCase())).toEqual([wallet]);
    expect(addAuthAllow("credential", ["alice"], "Alice, alice, bob")).toEqual([
      "alice",
      "Alice",
      "bob",
    ]);
    expect(addAuthAllow("credential", [], "alice smith, bob")).toEqual([
      "alice smith",
      "bob",
    ]);
    expect(addAuthAllow("oidc", [], "sub:team lead 7, a@example.com")).toEqual([
      "sub:team lead 7",
      "a@example.com",
    ]);
    expect(classifyAuthAllow("oidc", "sub:team lead 7").ok).toBe(true);
    expect(addAuthAllow("siwe", [], `${wallet} ${wallet.slice(0, -1)}0`)).toEqual([
      wallet,
      `${wallet.slice(0, -1)}0`,
    ]);
    expect(addAuthAllow("credential", ["alice"], " , ")).toEqual(["alice"]);
  });

  it("does not let lowercasing turn a lookalike address into a valid one", () => {
    const typed = "\u212Aelvin@example.com";
    const [entry] = addAuthAllow("oidc", [], typed);

    expect(entry).toBe(typed);
    expect(classifyAuthAllow("oidc", entry ?? "").ok).toBe(false);
  });

  it("lists what keeps an OIDC command from running as shown", () => {
    const oidc: TunnelAuthOptions = { ...none, method: "oidc" };
    const ready: TunnelAuthOptions = {
      ...oidc,
      allow: ["alice@example.com"],
      oidcIssuer: "https://accounts.google.com",
      oidcClientId: "abc",
    };
    const blocking = (auth: TunnelAuthOptions) =>
      validateTunnelAuth(auth).map((issue) => issue.field);

    expect(blocking(oidc)).toEqual(["allow", "issuer", "clientId"]);
    expect(blocking(ready)).toEqual([]);
    expect(
      blocking({ ...ready, allow: ["alice"], oidcIssuer: "http://login.example.com" })
    ).toEqual(["issuer", "entries"]);
  });

  it("refuses the issuers the tunnel refuses", () => {
    const ready: TunnelAuthOptions = {
      ...none,
      method: "oidc",
      allow: ["alice@example.com"],
      oidcClientId: "abc",
    };
    const accepts = (issuer: string) =>
      validateTunnelAuth({ ...ready, oidcIssuer: issuer }).length === 0;

    expect(accepts("https://accounts.google.com")).toBe(true);
    expect(accepts("https://login.example.com/realms/team")).toBe(true);
    expect(accepts("https://accounts.google.com?x=1")).toBe(false);
    expect(accepts("https://accounts.google.com/#frag")).toBe(false);
    expect(accepts("https://user@accounts.google.com")).toBe(false);
    expect(accepts("https://user:pass@accounts.google.com")).toBe(false);
    expect(accepts("http://accounts.google.com")).toBe(false);
    expect(accepts("accounts.google.com")).toBe(false);
  });

  it("accepts open private-link and wallet lists but flags malformed entries", () => {
    expect(validateTunnelAuth({ ...none, method: "credential" })).toEqual([]);
    expect(validateTunnelAuth({ ...none, method: "siwe" })).toEqual([]);
    expect(
      validateTunnelAuth({ ...none, method: "siwe", allow: ["0x12"] }).map(
        (issue) => issue.field
      )
    ).toEqual(["entries"]);
    expect(validateTunnelAuth(none)).toEqual([]);
  });

  it("lets an invite through only for a listed name once names are listed", () => {
    expect(isListedSubject([], "anyone")).toBe(true);
    expect(isListedSubject(["alice", "bob"], " bob ")).toBe(true);
    expect(isListedSubject(["alice"], "Alice")).toBe(false);
    expect(isListedSubject(["alice"], "carol")).toBe(false);
  });
});

describe("rules shared with the Go gateway", () => {
  const methods = new Set(["credential", "siwe", "oidc", "saml", "email"]);

  it("reads every allowlist entry as the gateway does", () => {
    for (const row of ruleVectors.allow) {
      expect(methods.has(row.method)).toBe(true);
      const method = row.method as "credential" | "siwe" | "oidc" | "saml" | "email";
      const [entry] = addAuthAllow(method, [], row.typed);
      const valid = entry !== undefined && classifyAuthAllow(method, entry).ok;
      expect(valid, `${method} entry ${JSON.stringify(row.typed)}`).toBe(row.valid);
      if (row.valid && "canonical" in row) {
        expect(entry, `${method} entry ${JSON.stringify(row.typed)}`).toBe(row.canonical);
      }
    }
  });

  it("accepts the OIDC issuers the gateway accepts", () => {
    for (const row of ruleVectors.issuer) {
      const issues = validateTunnelAuth({
        ...DEFAULT_TUNNEL_AUTH,
        method: "oidc",
        allow: ["alice@example.com"],
        oidcIssuer: row.value,
        oidcClientId: "client",
      });
      expect(
        issues.some((issue) => issue.field === "issuer"),
        `issuer ${JSON.stringify(row.value)}`
      ).toBe(!row.valid);
    }
  });

  it("accepts the SAML metadata URLs the gateway accepts", () => {
    for (const row of ruleVectors.samlMetadata) {
      const issues = validateTunnelAuth({
        ...DEFAULT_TUNNEL_AUTH,
        method: "saml",
        allow: ["alice@example.com"],
        samlMetadataURL: row.value,
      });
      expect(
        issues.some((issue) => issue.field === "metadataURL"),
        `metadata ${JSON.stringify(row.value)}`
      ).toBe(!row.valid);
    }
  });

  it("accepts the SMTP server addresses the gateway accepts", () => {
    for (const row of ruleVectors.emailSMTPAddr) {
      const issues = validateTunnelAuth({
        ...DEFAULT_TUNNEL_AUTH,
        method: "email",
        allow: ["alice@example.com"],
        emailSMTPAddr: row.value,
        emailFrom: "login@example.com",
      });
      expect(
        issues.some((issue) => issue.field === "smtpAddr"),
        `smtp address ${JSON.stringify(row.value)}`
      ).toBe(!row.valid);
    }
  });

  it("accepts the email senders the gateway accepts", () => {
    for (const row of ruleVectors.emailFrom) {
      const issues = validateTunnelAuth({
        ...DEFAULT_TUNNEL_AUTH,
        method: "email",
        allow: ["alice@example.com"],
        emailSMTPAddr: "smtp.example.com:587",
        emailFrom: row.value,
      });
      expect(
        issues.some((issue) => issue.field === "from"),
        `sender ${JSON.stringify(row.value)}`
      ).toBe(!row.valid);
    }
  });
});
