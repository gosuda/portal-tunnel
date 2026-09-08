package types

import (
	"encoding/json"
	"fmt"

	"github.com/pelletier/go-toml/v2"

	portaltunnel "github.com/gosuda/portal-tunnel/v2"
)

const (
	HeaderAccessToken      = "X-Portal-Access-Token"
	HeaderXPayment         = "X-PAYMENT"
	HeaderPaymentSignature = "PAYMENT-SIGNATURE"
	HeaderPaymentRequired  = "PAYMENT-REQUIRED"
	HeaderXPaymentRequired = "X-PAYMENT-REQUIRED"
	HeaderPaymentResponse  = "PAYMENT-RESPONSE"
	HeaderXPaymentResponse = "X-PAYMENT-RESPONSE"
	MarkerKeepalive        = byte(0x00)
	MarkerRawStart         = byte(0x01)
	MarkerTLSStart         = byte(0x02)
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
	DiscoveryVersion       string
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
			Tunnel    string `toml:"tunnel"`
			Discovery string `toml:"discovery"`
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
	DiscoveryVersion = m.Protocol.Discovery
	BootstrapRelays = registry.Relays
}
