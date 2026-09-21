import { describe, expect, it } from "vitest";
import {
  mergeIncompatibleRelays,
  relayReleaseLabel,
} from "./ServerListView";

const CURRENT = "https://relay-current.example";

describe("mergeIncompatibleRelays", () => {
  it("appends incompatible relay URLs and preserves the observed protocol version", () => {
    const known = [{ relayURL: CURRENT, isCurrent: true }];
    expect(
      mergeIncompatibleRelays(
        known,
        [{ url: "https://relay-old.example", protocol_version: "8" }],
        CURRENT
      )
    ).toEqual([
      { relayURL: CURRENT, isCurrent: true },
      {
        relayURL: "https://relay-old.example",
        isCurrent: false,
        protocolVersion: "8",
      },
    ]);
  });

  it("skips entries already known and blank URLs", () => {
    const known = [{ relayURL: CURRENT, isCurrent: true }];
    expect(
      mergeIncompatibleRelays(
        known,
        [{ url: CURRENT }, { url: "   " }],
        CURRENT
      )
    ).toEqual(known);
  });
});

describe("relayReleaseLabel", () => {
  it("returns the observed release version as-is", () => {
    const relay = { relayURL: "https://relay-peer.example", isCurrent: false };
    expect(
      relayReleaseLabel({ "https://relay-peer.example": "v2.5.0" }, relay)
    ).toBe("v2.5.0");
  });

  it("falls back to the discovery release version for the current relay", () => {
    const relay = { relayURL: CURRENT, isCurrent: true };
    expect(
      relayReleaseLabel({}, relay, { release_version: " v2.6.1 " })
    ).toBe("v2.6.1");
  });

  it("falls back to the observed protocol version for incompatible relays", () => {
    const relay = {
      relayURL: "https://relay-old.example",
      isCurrent: false,
      protocolVersion: "8",
    };
    expect(relayReleaseLabel({}, relay)).toBe("discovery 8");
  });

  it("does not borrow the serving relay's protocol version for peers", () => {
    const relay = { relayURL: "https://relay-peer.example", isCurrent: false };
    expect(
      relayReleaseLabel({}, relay, { protocol_version: "9" })
    ).toBeNull();
  });

  it("returns null when nothing is known about the relay", () => {
    const relay = {
      relayURL: "https://relay-old.example",
      isCurrent: false,
    };
    expect(relayReleaseLabel({}, relay)).toBeNull();
  });

  it("treats an empty observed version as unknown", () => {
    const relay = { relayURL: CURRENT, isCurrent: false };
    expect(relayReleaseLabel({ [CURRENT]: "   " }, relay)).toBeNull();
  });
});
