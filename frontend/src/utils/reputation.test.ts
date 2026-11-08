import { describe, expect, it } from "vitest";
import { isHiddenByVotes, isReputationWarning } from "./reputation";

const summary = (up: number, down: number) => ({ hostname: "a", up, down, total: up + down });

describe("isHiddenByVotes", () => {
  it("hides at five down votes that outnumber the up votes", () => {
    expect(isHiddenByVotes(4, 5)).toBe(true);
    expect(isHiddenByVotes(5, 5)).toBe(false);
    expect(isHiddenByVotes(0, 4)).toBe(false);
  });
});

describe("isReputationWarning", () => {
  it("warns at five ratings with three or more down and 70% down", () => {
    expect(isReputationWarning(summary(1, 4))).toBe(true);
    expect(isReputationWarning(summary(2, 3))).toBe(false);
    expect(isReputationWarning(summary(0, 3))).toBe(false);
    expect(isReputationWarning(undefined)).toBe(false);
  });
});
