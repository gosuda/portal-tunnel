import { describe, expect, it } from "vitest";
import { mergeIncompatibleRelays } from "./ServerListView";

const CURRENT = "https://relay-current.example";

describe("mergeIncompatibleRelays", () => {
  it("returns the known list unchanged without incompatible entries", () => {
    const known = [{ relayURL: CURRENT, isCurrent: true }];
    expect(mergeIncompatibleRelays(known, undefined, CURRENT)).toBe(known);
  });

  it("appends incompatible relay URLs not already known", () => {
    const known = [{ relayURL: CURRENT, isCurrent: true }];
    expect(
      mergeIncompatibleRelays(
        known,
        [{ url: "https://relay-old.example", protocol_version: "8" }],
        CURRENT
      )
    ).toEqual([
      { relayURL: CURRENT, isCurrent: true },
      { relayURL: "https://relay-old.example", isCurrent: false },
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
