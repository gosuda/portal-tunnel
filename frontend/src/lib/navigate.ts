// Single seam for leaving the SPA for a tenant service. isPush marks the open
// so bfcache restores of the detail page return to the directory instead.
import { STORAGE_KEY_IS_PUSH } from "@/types/storage";

export function openExternal(url: string) {
  localStorage.setItem(STORAGE_KEY_IS_PUSH, "true");
  window.location.assign(url);
}
