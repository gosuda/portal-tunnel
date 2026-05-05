package types

const (
	ReleaseVersion         = "v2.1.10"
	SDKVersion             = "6"
	DiscoveryVersion       = "7"
	OfficialReleaseBaseURL = "https://github.com/gosuda/portal-tunnel/releases"

	HeaderAccessToken = "X-Portal-Access-Token"
	MarkerKeepalive   = byte(0x00)
	MarkerRawStart    = byte(0x01)
	MarkerTLSStart    = byte(0x02)
)
