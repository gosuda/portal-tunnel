// External navigation goes through this helper (instead of calling
// window.location inline) so directory-gate tests can mock the seam:
// jsdom's Location#assign is non-configurable and cannot be spied on.
export function openExternal(url: string): void {
  window.location.assign(url);
}
