import { cleanup } from "@testing-library/react";
import { afterEach, beforeEach, vi } from "vitest";

const createMatchMedia = (matches = false) =>
  vi.fn().mockImplementation((query: string) => ({
    matches,
    media: query,
    onchange: null,
    addListener: vi.fn(),
    removeListener: vi.fn(),
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    dispatchEvent: vi.fn(),
  }));

if (typeof window !== "undefined" && !window.matchMedia) {
  Object.defineProperty(window, "matchMedia", {
    writable: true,
    configurable: true,
    value: createMatchMedia(false),
  });
}

function createMemoryStorage(): Storage {
  const items = new Map<string, string>();
  return {
    get length() {
      return items.size;
    },
    clear: () => items.clear(),
    getItem: (key) => items.get(key) ?? null,
    key: (index) => [...items.keys()][index] ?? null,
    removeItem: (key) => {
      items.delete(key);
    },
    setItem: (key, value) => {
      items.set(key, String(value));
    },
  };
}

for (const name of ["localStorage", "sessionStorage"] as const) {
  if (typeof globalThis[name]?.clear !== "function") {
    const storage = createMemoryStorage();
    Object.defineProperty(globalThis, name, { configurable: true, value: storage });
    if (typeof window !== "undefined" && window !== globalThis) {
      Object.defineProperty(window, name, { configurable: true, value: storage });
    }
  }
}

beforeEach(() => {
  if (typeof window !== "undefined" && !window.matchMedia) {
    Object.defineProperty(window, "matchMedia", {
      writable: true,
      configurable: true,
      value: createMatchMedia(false),
    });
  }
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});
