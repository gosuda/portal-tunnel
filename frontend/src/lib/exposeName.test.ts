import { describe, expect, it } from "vitest";
import { normalizeExposeName } from "@/lib/exposeName";

describe("normalizeExposeName", () => {
  it("caps typed names at the lease name limit without a trailing hyphen", () => {
    expect(normalizeExposeName("staging-dashboard-api-v2-preview")).toBe(
      "staging-dashboard-api-v2-preview",
    );
    expect(
      normalizeExposeName(`${"a".repeat(62)}-tail-beyond-the-dns-label-limit`),
    ).toBe("a".repeat(62));
  });

  it("drops internationalized names whose ASCII form exceeds the lease name limit", () => {
    expect(normalizeExposeName("한국어로된서비스이름".repeat(3))).toBe("");
  });

  it("drops converted names that are not valid DNS labels", () => {
    expect(normalizeExposeName("a⑴b")).toBe("");
  });

  it("drops names shaped like a canonical label", () => {
    const address = "7a3b2c4d5e6f708192a3b4c5d6e7f8091a2b3c4d";
    expect(normalizeExposeName(address)).toBe("");
    expect(normalizeExposeName(`myapp-${address.toUpperCase()}`)).toBe("");
    expect(normalizeExposeName(`my-app-${address.slice(1)}`)).toBe(
      `my-app-${address.slice(1)}`,
    );
  });

  it("drops punycode names over the limit instead of cutting them", () => {
    expect(normalizeExposeName(`xn--${"a".repeat(60)}`)).toBe("");
  });
});
