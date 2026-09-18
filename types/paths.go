package types

const (
	PathRoot      = "/"
	PathLLMs      = "/llms.txt"
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

	PathInstallShell      = PathAPIPrefix + "/install.sh"
	PathInstallPowerShell = PathAPIPrefix + "/install.ps1"
	PathInstallBinPrefix  = PathAPIPrefix + "/install/bin/"

	PathV1Prefix = "/v1"
	PathV1Sign   = PathV1Prefix + "/sign"

	PathSDKPrefix            = "/sdk"
	PathSDKDomain            = PathSDKPrefix + "/domain"
	PathSDKRegisterChallenge = PathSDKPrefix + "/register/challenge"
	PathSDKRegister          = PathSDKPrefix + "/register"
	PathSDKRenew             = PathSDKPrefix + "/renew"
	PathSDKReverse           = PathSDKPrefix + "/reverse"
	PathSDKUnregister        = PathSDKPrefix + "/unregister"
	PathSDKConnect           = PathSDKPrefix + "/connect"
	PathSDKCache             = PathSDKPrefix + "/cache"

	PathDiscovery         = "/discovery"
	PathDiscoveryAnnounce = PathDiscovery + "/announce"
)

// ReservedRootPrefixes are relay-owned root-host path trees never served by the SPA fallback.
var ReservedRootPrefixes = []string{PathAPIPrefix, PathSDKPrefix, PathDiscovery, PathV1Prefix}

const (
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
