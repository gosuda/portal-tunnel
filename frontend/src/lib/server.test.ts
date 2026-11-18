import { describe, expect, it } from "vitest";
import type { DiscoveredService, Lease } from "@/types/api";
import { leaseToServer, mergeDiscoveredServices } from "./server";

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

describe("identity discovery cards", () => {
  it("keeps the local URL and one card per service without merging different owners", () => {
    const local = leaseToServer({ ...lease, name: "blog" });
    const location = { relay_url: "https://remote.example", url: "https://blog.remote.example/", current_relay: false, reported_ready: true, observed_at: "2026-11-16T00:00:00Z", expires_at: "2026-11-16T00:00:30Z", verification: "relay-reported" as const };
    const services: DiscoveredService[] = [
      { name: "blog", address: lease.address, metadata: {}, locations: [location] },
      { name: "api", address: lease.address, metadata: { description: "An API", tags: ["tools"] }, locations: [{ ...location, url: "https://api.remote.example/", reputation: { up: 7, down: 2 } }] },
      { name: "blog", address: "0x2222222222222222222222222222222222222222", metadata: {}, locations: [location] },
    ];
    const allCards = mergeDiscoveredServices([local], services);
    expect(allCards).toHaveLength(3);
    expect(allCards.filter((card) => card.serviceName === "blog")).toHaveLength(2);
    expect(allCards.find((card) => card.id === local.id)?.locations).toEqual([location]);

    const cards = mergeDiscoveredServices([local], services, lease.address);
    expect(cards).toHaveLength(2);
    expect(cards.find((card) => card.serviceName === "blog")?.link).toBe(local.link);
    const remote = cards.find((card) => card.serviceName === "api");
    expect(remote?.link).toBe("");
    expect(remote?.remoteOnly).toBe(true);
    expect(remote?.description).toBe("An API");
    expect(remote?.tags).toEqual(["tools"]);
    expect(remote?.observedReputation).toEqual({ up: 7, down: 2 });
    expect(remote?.reputation).toBeUndefined();
    const remoteBlogWithoutRep = allCards.find((card) => card.address === "0x2222222222222222222222222222222222222222");
    expect(remoteBlogWithoutRep?.observedReputation).toBeUndefined();
  });

  it("distinguishes an observed zero tally from unknown without local moderation authority", () => {
    const cards = mergeDiscoveredServices([], [{
      name: "zero", address: lease.address, metadata: {}, locations: [{
        relay_url: "https://remote.example", current_relay: false,
        reported_ready: true, observed_at: "", expires_at: "",
        verification: "relay-reported", reputation: { up: 0, down: 0 },
      }],
    }]);
    expect(cards[0].observedReputation).toEqual({ up: 0, down: 0 });
    expect(cards[0].reputation).toBeUndefined();
  });
});
