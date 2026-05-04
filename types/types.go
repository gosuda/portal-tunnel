package types

const (
	ReleaseVersion         = "v2.1.9"
	SDKVersion             = "6"
	DiscoveryVersion       = "7"
	OfficialReleaseBaseURL = "https://github.com/gosuda/portal-tunnel/releases"

	HeaderAccessToken = "X-Portal-Access-Token"
	MarkerKeepalive   = byte(0x00)
	MarkerRawStart    = byte(0x01)
	MarkerTLSStart    = byte(0x02)
)

func PortalRelayRegistryURLs() []string {
	return []string{
		"https://raw.githubusercontent.com/gosuda/portal-tunnel/main/registry.json",
		"https://object.rly.best/portal-tunnel/registry.json",
	}
}
