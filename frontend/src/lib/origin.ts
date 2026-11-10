const FALLBACK_ORIGIN = "https://localhost";

export function readCurrentOrigin(): string {
  return typeof window !== "undefined" ? window.location.origin : FALLBACK_ORIGIN;
}
