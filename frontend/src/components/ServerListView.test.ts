import { describe, expect, it } from "vitest";
import {
  mergeIncompatibleRelays,
  relayReleaseLabel,
} from "./ServerListView";

const CURRENT = "https://relay-current.example";

describe("mergeIncompatibleRelays", () => {
  it("returns the known list unchanged without incompatible entries", () => {
    const known = [{ relayURL: CURRENT, isCurrent: true }];
    expect(mergeIncompatibleRelays(known, undefined, CURRENT)).toBe(known);
  });

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
  const oldRelay = {
    relayURL: "https://relay-old.example",
    isCurrent: false,
    protocolVersion: "8",
  };

  it("shows loading while the release probe is pending", () => {
    expect(relayReleaseLabel({}, oldRelay)).toBe("loading...");
    expect(relayReleaseLabel({ [oldRelay.relayURL]: null }, oldRelay)).toBe(
      "loading..."
    );
  });

  it("falls back to the observed discovery protocol when the probe fails", () => {
    expect(
      relayReleaseLabel({ [oldRelay.relayURL]: "" }, oldRelay)
    ).toBe("discovery 8");
  });

  it("still reports offline without a protocol version", () => {
    expect(
      relayReleaseLabel({ [oldRelay.relayURL]: "" }, { ...oldRelay, protocolVersion: undefined })
    ).toBe("offline");
  });

  it("prefers the probed release version when available", () => {
    expect(
      relayReleaseLabel({ [oldRelay.relayURL]: "v2.3.8" }, oldRelay)
    ).toBe("v2.3.8");
  });
});
