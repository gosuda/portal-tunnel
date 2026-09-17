import { beforeEach, afterEach, describe, expect, it, vi } from "vitest";
import { openExternal } from "./navigate";
import { STORAGE_KEY_IS_PUSH } from "@/types/storage";

describe("openExternal", () => {
  beforeEach(() => {
    localStorage.clear();
    vi.stubGlobal("window", {
      location: { assign: vi.fn() },
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("sets the isPush flag before navigating", () => {
    const locationAssign = vi.mocked(window.location.assign);
    openExternal("https://example.com/page");
    expect(localStorage.getItem(STORAGE_KEY_IS_PUSH)).toBe("true");
    expect(locationAssign).toHaveBeenCalledWith("https://example.com/page");
  });

  it("sets the flag on every call so repeated calls are idempotent", () => {
    openExternal("https://a.example/");
    openExternal("https://b.example/");
    expect(localStorage.getItem(STORAGE_KEY_IS_PUSH)).toBe("true");
  });
});
