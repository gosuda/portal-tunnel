const ADMIN_AUTH_TOKEN_STORAGE_KEY = "portal:admin_access_token";

export function readAdminAuthToken(): string {
  try {
    return localStorage.getItem(ADMIN_AUTH_TOKEN_STORAGE_KEY)?.trim() || "";
  } catch {
    return "";
  }
}

export function writeAdminAuthToken(token: string): void {
  const value = token.trim();
  try {
    if (value) {
      localStorage.setItem(ADMIN_AUTH_TOKEN_STORAGE_KEY, value);
      return;
    }
    localStorage.removeItem(ADMIN_AUTH_TOKEN_STORAGE_KEY);
  } catch {
    // localStorage can be unavailable in restricted browser contexts.
  }
}
