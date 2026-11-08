const FALLBACK_ORIGIN = "https://localhost";

/** The relay serving this page: the default relay and install host in commands. */
export function readCurrentOrigin(): string {
  return typeof window !== "undefined" ? window.location.origin : FALLBACK_ORIGIN;
}
