package types

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/pelletier/go-toml/v2"

	portaltunnel "github.com/gosuda/portal-tunnel/v2"
)

const (
	HeaderAccessToken       = "X-Portal-Access-Token"
	HeaderProtocolVersion   = "X-Portal-Protocol-Version"
	HeaderReverseCapability = "X-Portal-Reverse-Capability"
)

const (
	DefaultHTTPRedirectAddr = ":80"
	HTTPRedirectFeatureName = "http-redirect"
	HTTPRedirectEnabledEnv  = "HTTP_REDIRECT_ENABLED"
)

// HTTPRedirectConfig controls the optional canonical-portal HTTP listener.
// The zero value disables redirects and HSTS; an empty Addr defaults to :80.
type HTTPRedirectConfig struct {
	Enabled bool
	Addr    string
	HSTS    bool
}

var (
	ReleaseVersion         string
	SDKVersion             string
	SDKVersionMin          string
	DiscoveryVersion       string
	DiscoveryVersionMin    string
	OfficialReleaseBaseURL string
	BootstrapRelays        []string
)

func init() {
	var m struct {
		Release struct {
			Version string `toml:"version"`
			BaseURL string `toml:"base_url"`
		} `toml:"release"`
		Protocol struct {
			Tunnel       string `toml:"tunnel"`
			Discovery    string `toml:"discovery"`
			TunnelMin    string `toml:"min_tunnel"`
			DiscoveryMin string `toml:"min_discovery"`
		} `toml:"protocol"`
	}
	if err := toml.Unmarshal(portaltunnel.ConfigTOML, &m); err != nil {
		panic(fmt.Errorf("unmarshal config TOML: %w", err))
	}
	var registry struct {
		Relays []string `json:"relays"`
	}
	if err := json.Unmarshal(portaltunnel.RegistryJSON, &registry); err != nil {
		panic(fmt.Errorf("unmarshal registry JSON: %w", err))
	}
	ReleaseVersion = m.Release.Version
	OfficialReleaseBaseURL = m.Release.BaseURL
	SDKVersion = m.Protocol.Tunnel
	SDKVersionMin = m.Protocol.TunnelMin
	DiscoveryVersion = m.Protocol.Discovery
	DiscoveryVersionMin = m.Protocol.DiscoveryMin
	if SDKVersionMin == "" {
		SDKVersionMin = SDKVersion
	}
	if DiscoveryVersionMin == "" {
		DiscoveryVersionMin = DiscoveryVersion
	}
	BootstrapRelays = registry.Relays
}

func ProtocolVersionNum(version string) int {
	n, err := strconv.Atoi(strings.TrimSpace(version))
	if err != nil {
		return 0
	}
	return n
}

func CanServeProtocolVersion(requested, current, minimum string) bool {
	return requested == "" || NegotiatedProtocolVersion(requested, current, minimum) == requested
}

func NegotiatedProtocolVersion(requested, current, minimum string) string {
	requestedNum := ProtocolVersionNum(requested)
	if requestedNum == 0 {
		return minimum
	}
	if requestedNum < ProtocolVersionNum(minimum) || requestedNum > ProtocolVersionNum(current) {
		return current
	}
	return requested
}
