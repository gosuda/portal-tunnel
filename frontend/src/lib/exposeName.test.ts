import { describe, expect, it } from "vitest";
import { buildDefaultExposeName, normalizeExposeName } from "@/lib/exposeName";

// Cross-language parity vectors -- keep in sync with utils/name_test.go
const exposeNameVectors = [
  { target: "3000", seed: "test_seed", expected: "bubble-cricket-beacon" },
  { target: "", seed: "portal", expected: "zesty-beacon-sketch" },
  { target: "http://localhost:8080", seed: "cli_abc", expected: "sprightly-rocket-zap" },
  { target: "192.168.1.1:8080", seed: "web_xyz", expected: "velvet-yeti-march" },
  { target: "localhost", seed: "cli_", expected: "misty-rocket-ripple" },
  // sprightly-thimble-boogie would exceed the lease name limit.
  { target: "3000", seed: "test_seed_24", expected: "sprightly-thimble" },
] as const;

describe("buildDefaultExposeName", () => {
  it.each(exposeNameVectors)(
    "generates $expected for target=$target seed=$seed",
    ({ target, seed, expected }) => {
      expect(buildDefaultExposeName(target, seed)).toBe(expected);
    },
  );

  it("always fits the lease name limit as a valid DNS label", () => {
    for (let i = 0; i < 2000; i += 1) {
      const name = buildDefaultExposeName("3000", `seed-${i}`);
      expect(name.length).toBeLessThanOrEqual(22);
      expect(name).toMatch(/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/);
    }
  });
});

describe("normalizeExposeName", () => {
  it("caps typed names at the lease name limit without a trailing hyphen", () => {
    expect(normalizeExposeName("staging-dashboard-api-v2-preview")).toBe(
      "staging-dashboard-api",
    );
  });

  it("drops internationalized names whose ASCII form exceeds the lease name limit", () => {
    expect(normalizeExposeName("한국어로된서비스이름")).toBe("");
  });
});
