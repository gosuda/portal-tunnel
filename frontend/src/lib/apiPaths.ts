// Application callback paths mirror types/paths.go's PathApplicationAuth* constants.
export const AUTH_CALLBACK_PATH = "/_portal/auth/callback";
export const AUTH_SAML_ACS_PATH = "/_portal/auth/saml/acs";
export const AUTH_SAML_METADATA_PATH = "/_portal/auth/saml/metadata";

export const RELAY_API_PATHS = {
  public: {
    state: "/api/state",
    comments: "/api/comments",
    commentsVote: "/api/comments/vote",
    commentsDelete: "/api/comments/delete",
    reputationVote: "/api/reputation/vote",
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
  },
  x402: {
    root: "/api/x402",
    supported: "/api/x402/supported",
    verify: "/api/x402/verify",
    settle: "/api/x402/settle",
  },
  sdk: {
    domain: "/sdk/domain",
    certificateChain: "/sdk/certificate-chain",
  },
  discovery: "/discovery",
  install: {
    shell: "/api/install.sh",
    powershell: "/api/install.ps1",
  },
} as const;

export const ROUTE_PATHS = {
  home: "/",
  serverDetail: "/server/:id",
  admin: "/admin",
} as const;
