package types

const (
	ReleaseVersion              = "v2.1.4"
	ProtocolVersion             = "5"
	PortalRelayRegistryURL      = "https://raw.githubusercontent.com/gosuda/portal-tunnel/feature/tor-vpn-relay/registry.json"
	MinDiscoveryRoutingAttempts = 1
	MaxDiscoveryRoutingAttempts = 32

	HeaderAccessToken = "X-Portal-Access-Token"
	MarkerKeepalive   = byte(0x00)
	MarkerRawStart    = byte(0x01)
	MarkerTLSStart    = byte(0x02)
)
