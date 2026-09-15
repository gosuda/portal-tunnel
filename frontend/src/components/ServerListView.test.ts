import { describe, expect, it } from "vitest";
import {
  mergeIncompatibleRelays,
  buildKnownRelays,
} from "./ServerListView";

const CURRENT = "https://relay-current.example";

describe("mergeIncompatibleRelays", () => {
  it("returns the known list unchanged without incompatible entries", () => {
    const known = [{ relayURL: CURRENT, isCurrent: true, compatible: true }];
    expect(mergeIncompatibleRelays(known, undefined, CURRENT)).toBe(known);
  });

  it("appends incompatible relay URLs and preserves the observed protocol version", () => {
    const known = [{ relayURL: CURRENT, isCurrent: true, compatible: true }];
    expect(
      mergeIncompatibleRelays(
        known,
        [{ url: "https://relay-old.example", protocol_version: "8" }],
        CURRENT
      )
    ).toEqual([
      { relayURL: CURRENT, isCurrent: true, compatible: true },
      {
        relayURL: "https://relay-old.example",
        isCurrent: false,
        compatible: false,
        protocolVersion: "8",
      },
    ]);
  });

  it("skips entries already known and blank URLs", () => {
    const known = [{ relayURL: CURRENT, isCurrent: true, compatible: true }];
    expect(
      mergeIncompatibleRelays(
        known,
        [{ url: CURRENT }, { url: "   " }],
        CURRENT
      )
    ).toEqual(known);
  });
});

describe("buildKnownRelays", () => {
  it("marks compatible relays and carries version from discovery", () => {
    const discovery = {
      relays: [
        { api_https_addr: CURRENT, version: "9" },
        { api_https_addr: "https://relay-other.example", version: "9" },
      ],
    };
    const relays = buildKnownRelays(discovery, CURRENT);
    expect(relays).toEqual([
      {
        relayURL: CURRENT,
        isCurrent: true,
        compatible: true,
        protocolVersion: "9",
      },
      {
        relayURL: "https://relay-other.example",
        isCurrent: false,
        compatible: true,
        protocolVersion: "9",
      },
    ]);
  });

  it("keeps incompatible relays visible with their observed protocol version", () => {
    const discovery = {
      relays: [{ api_https_addr: CURRENT, version: "9" }],
      incompatible_relays: [
        { url: "https://relay-old.example", protocol_version: "8" },
      ],
    };
    const relays = buildKnownRelays(discovery, CURRENT);
    const incompatible = relays.find(
      (r) => r.relayURL === "https://relay-old.example"
    );
    expect(incompatible).toBeDefined();
    expect(incompatible?.compatible).toBe(false);
    expect(incompatible?.protocolVersion).toBe("8");
  });
});
