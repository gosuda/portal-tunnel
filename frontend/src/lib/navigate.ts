// Single seam for leaving the SPA for a tenant service. isPush marks the open
// so bfcache restores of the detail page return to the directory instead.
export function openExternal(url: string) {
  localStorage.setItem("isPush", "true");
  window.location.assign(url);
}
