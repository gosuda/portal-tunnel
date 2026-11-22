import { describe, expect, it } from "vitest";

const DISALLOWED_PATTERNS = [
  /Opens available relay/i,
  /\d+\s+other relays checked/i,
  /unavailable or skipped/i,
  /Partial coverage/i,
  /Remote comments are read-only/i,
  /originating relays/i,
  /To post or manage a remote comment/i,
  /voters are not deduplicated/i,
  /View relay-reported comments/i,
  /View network comments/i,
  /No comments observed/i,
  /Choose a relay to open/i,
  /Candidates are relay-reported/i,
  /These are relay-reported counts/i,
];

describe("frontend slop and verbose disclaimer guard", () => {
  it("ensures no verbose disclaimers or slop phrases exist in frontend source code", () => {
    const modules = import.meta.glob("./**/*.{ts,tsx}", {
      query: "?raw",
      import: "default",
      eager: true,
    }) as Record<string, string>;

    const violations: { file: string; match: string }[] = [];

    for (const [filePath, content] of Object.entries(modules)) {
      if (filePath.includes(".test.")) continue;
      for (const pattern of DISALLOWED_PATTERNS) {
        const match = content.match(pattern);
        if (match) {
          violations.push({ file: filePath, match: match[0] });
        }
      }
    }

    expect(
      violations,
      `Found disallowed slop/disclaimer phrases in frontend source:\n${violations
        .map((v) => `  - ${v.file}: "${v.match}"`)
        .join("\n")}`
    ).toEqual([]);
  });
});
