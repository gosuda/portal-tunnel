import { useSyncExternalStore } from "react";

function canMatchMedia(): boolean {
  return typeof window !== "undefined" && typeof window.matchMedia === "function";
}

/** Whether the media query matches now; false where matchMedia is missing. */
export function matchesMedia(query: string): boolean {
  return canMatchMedia() && window.matchMedia(query).matches;
}

/** Re-renders when the media query starts or stops matching. */
export function useMediaQuery(query: string): boolean {
  return useSyncExternalStore(
    (onChange) => {
      if (!canMatchMedia()) {
        return () => {};
      }
      const media = window.matchMedia(query);
      media.addEventListener("change", onChange);
      return () => media.removeEventListener("change", onChange);
    },
    () => matchesMedia(query),
    () => false
  );
}
