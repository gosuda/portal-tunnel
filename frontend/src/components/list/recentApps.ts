const STORAGE_KEY = "portal.recentApps";
const LIMIT = 20;

export function readRecentAppIds(): string[] {
  try {
    const parsed: unknown = JSON.parse(localStorage.getItem(STORAGE_KEY) ?? "[]");
    return Array.isArray(parsed) ? parsed.filter((id): id is string => typeof id === "string") : [];
  } catch {
    return [];
  }
}

export function recordAppOpened(id: string): void {
  try {
    const rest = readRecentAppIds().filter((recent) => recent !== id);
    localStorage.setItem(STORAGE_KEY, JSON.stringify([id, ...rest].slice(0, LIMIT)));
  } catch {}
}
