import { describe, expect, it } from "vitest";
import type { Lease } from "@/types/api";
import { leaseToServer } from "./server";

const lease: Lease = {
  address: "0x0123456789012345678901234567890123456789",
  hostname: "demo.relay.example",
  canonical_hostname: "demo.0123456789012345678901234567890123456789.relay.example",
  expires_at: "",
  first_seen_at: "",
  last_seen_at: "",
  metadata: {},
  ready: 1,
};

describe("leaseToServer", () => {
  it("keys an app by its canonical hostname and links its public hostname", () => {
    const server = leaseToServer(lease);
    expect(server.id).toBe("demo.0123456789012345678901234567890123456789.relay.example");
    expect(server.dns).toBe("demo.relay.example");
    expect(server.link).toBe("https://demo.relay.example/");
  });

  it("gives a raw TCP or UDP app no web link", () => {
    expect(leaseToServer({ ...lease, tcp_addr: "relay.example:40001" }).link).toBe("");
    expect(leaseToServer({ ...lease, udp_addr: "relay.example:40002" }).link).toBe("");
  });

  it("does not link unavailable canonical origins without an alias", () => {
    const canonical = "default.0123456789012345678901234567890123456789.relay.example";
    const row: Lease = {
      ...lease,
      hostname: "",
      namespace: "local-tls-v1",
      canonical_hostname: canonical,
    };
    expect(leaseToServer(row).link).toBe("");
    expect(leaseToServer({ ...row, canonical_ready: true }).link).toBe(
      `https://${canonical}/`,
    );
    const unavailable = leaseToServer({
      ...row,
    });
    expect(unavailable.link).toBe("");
    expect(unavailable.online).toBe(false);
  });
});
