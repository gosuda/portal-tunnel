package types

const (
	PathRoot      = "/"
	PathAPIPrefix = "/api"
	PathHealthz   = PathAPIPrefix + "/healthz"
	PathState     = PathAPIPrefix + "/state"

	PathAdmin           = PathAPIPrefix + "/admin"
	PathAdminPrefix     = PathAdmin + "/"
	PathAdminAuthLogin  = PathAdmin + "/auth/login"
	PathAdminLogout     = PathAdmin + "/auth/logout"
	PathAdminAuthStatus = PathAdmin + "/auth/status"

	PathPolicy       = PathAPIPrefix + "/policy"
	PathPolicyPrefix = PathPolicy + "/"
	PathPolicyState  = PathPolicy + "/state"
	PathPolicyLeases = PathPolicy + "/leases"
	PathPolicyIPs    = PathPolicy + "/ips"

	PathInstallShell      = PathAPIPrefix + "/install.sh"
	PathInstallPowerShell = PathAPIPrefix + "/install.ps1"
	PathInstallBinPrefix  = PathAPIPrefix + "/install/bin/"

	PathX402Facilitator = PathAPIPrefix + "/x402"
	X402SupportedPath   = PathX402Facilitator + "/supported"
	X402VerifyPath      = PathX402Facilitator + "/verify"
	X402SettlePath      = PathX402Facilitator + "/settle"

	PathV1Prefix = "/v1"
	PathV1Sign   = PathV1Prefix + "/sign"

	PathSDKPrefix            = "/sdk"
	PathSDKDomain            = PathSDKPrefix + "/domain"
	PathSDKRegisterChallenge = PathSDKPrefix + "/register/challenge"
	PathSDKRegister          = PathSDKPrefix + "/register"
	PathSDKRenew             = PathSDKPrefix + "/renew"
	PathSDKUnregister        = PathSDKPrefix + "/unregister"
	PathSDKHop               = PathSDKPrefix + "/hop"
	PathSDKConnect           = PathSDKPrefix + "/connect"

	PathDiscovery         = "/discovery"
	PathDiscoveryAnnounce = PathDiscovery + "/announce"
)

// ReservedRootPrefixes are relay-owned root-host path trees that must never
// be served by the SPA frontend fallback.
var ReservedRootPrefixes = []string{PathAPIPrefix, PathSDKPrefix, PathDiscovery, PathV1Prefix}

const (
	X402PreparePath = "/x402/prepare"
	X402ClientPath  = "/x402/client.js"

	PathAgentPrefix        = "/agent"
	PathAgentStatus        = PathAgentPrefix + "/status"
	PathAgentShutdown      = PathAgentPrefix + "/shutdown"
	PathAgentTunnels       = PathAgentPrefix + "/tunnels"
	PathAgentTunnelsPrefix = PathAgentPrefix + "/tunnels/"
	PathAgentAuthChallenge = PathAgentPrefix + "/auth/challenge"
	PathAgentAuthLogin     = PathAgentPrefix + "/auth/login"
	PathAgentAuthLogout    = PathAgentPrefix + "/auth/logout"
	PathAgentAuthStatus    = PathAgentPrefix + "/auth/status"
)
