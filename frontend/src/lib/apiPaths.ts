export const RELAY_API_PATHS = {
  public: {
    state: "/api/state",
  },
  admin: {
    root: "/api/admin",
    authChallenge: "/api/admin/auth/challenge",
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
  sdk: {
    domain: "/sdk/domain",
  },
  discovery: "/discovery",
  install: {
    shell: "/api/install.sh",
    powershell: "/api/install.ps1",
  },
} as const;

export const PRESENTATION_API_PATHS = {
  public: {
    state: "/ui/state",
  },
  policy: {
    root: "/ui/policy",
    state: "/ui/policy/state",
    leases: "/ui/policy/leases",
    ips: "/ui/policy/ips",
  },
  service: {
    status: "/ui/service/status",
  },
  thumbnail: {
    prefix: "/ui/thumbnail/",
  },
} as const;

export const BROWSER_API_PATHS = {
  ...RELAY_API_PATHS,
  public: PRESENTATION_API_PATHS.public,
  policy: PRESENTATION_API_PATHS.policy,
  service: PRESENTATION_API_PATHS.service,
  thumbnail: PRESENTATION_API_PATHS.thumbnail,
} as const;

export const ROUTE_PATHS = {
  home: "/",
  serverDetail: "/server/:id",
  admin: "/admin",
} as const;
