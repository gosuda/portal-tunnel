export const API_PATHS = {
  admin: {
    prefix: "/admin",
    snapshot: "/admin/snapshot",
    login: "/admin/login",
    logout: "/admin/logout",
    authStatus: "/admin/auth/status",
    leases: "/admin/leases",

    approvalMode: "/admin/settings/approval-mode",
    landingPage: "/admin/settings/landing-page",
    udpSettings: "/admin/settings/udp",
    tcpPortSettings: "/admin/settings/tcp-port",
  },
  sdk: {
    prefix: "/sdk",
    register: "/sdk/register",
    unregister: "/sdk/unregister",
    renew: "/sdk/renew",
    domain: "/sdk/domain",
    connect: "/sdk/connect",
  },
  tunnel: {
    status: "/tunnel/status",
  },
  discovery: "/discovery",
  healthz: "/healthz",
  install: {
    shell: "/install.sh",
    powershell: "/install.ps1",
  },
  appPrefix: "/app/",
} as const;

export const ROUTE_PATHS = {
  home: "/",
  serverDetail: "/server/:id",
  admin: "/admin",
  adminLogin: "/admin/login",
} as const;

export function encodePathPart(value: string): string {
  return btoa(value).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function adminLeasePath(
  name: string,
  address: string,
  action: "ban" | "bps" | "approve" | "deny"
): string {
  const encodedName = encodePathPart(name);
  const encodedAddress = encodePathPart(address);
  return `${API_PATHS.admin.leases}/${encodeURIComponent(encodedName)}/${encodeURIComponent(encodedAddress)}/${action}`;
}

export function adminIPBanPath(ip: string): string {
  return `${API_PATHS.admin.prefix}/ips/${encodeURIComponent(ip.trim())}/ban`;
}
