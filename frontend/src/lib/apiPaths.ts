export const RELAY_API_PATHS = {
  public: {
    state: "/api/state",
  },
  admin: {
    root: "/api/admin",
    authLogin: "/api/admin/auth/login",
    logout: "/api/admin/auth/logout",
    authStatus: "/api/admin/auth/status",
  },
  policy: {
    root: "/api/policy",
    state: "/api/policy/state",
    leases: "/api/policy/leases",
    ips: "/api/policy/ips",
  },
  x402: {
    root: "/api/x402",
    supported: "/api/x402/supported",
    verify: "/api/x402/verify",
    settle: "/api/x402/settle",
  },
  sdk: {
    domain: "/sdk/domain",
  },
  discovery: "/discovery",
  install: {
    shell: "/api/install.sh",
    powershell: "/api/install.ps1",
  },
} as const;

export const BROWSER_API_PATHS = RELAY_API_PATHS;

export const ROUTE_PATHS = {
  home: "/",
  serverDetail: "/server/:id",
  admin: "/admin",
} as const;
