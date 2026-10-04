// Package manifest owns the repository build manifest and bootstrap registry
// embedded into the binaries. It is the single authority for the release
// version, the official release base URL, the wire protocol versions, and the
// bootstrap relay set; everything else derives from these values.
package manifest

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/pelletier/go-toml/v2"
)

//go:embed manifest.toml
var manifestTOML []byte

//go:embed registry.json
var registryJSON []byte

//go:embed llms.txt
var llmsText string

var (
	releaseVersion           string
	releaseBaseURL           string
	tunnelProtocolVersion    string
	discoveryProtocolVersion string
	bootstrapRelays          []string
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
	if err := toml.Unmarshal(manifestTOML, &m); err != nil {
		panic(fmt.Errorf("unmarshal manifest toml: %w", err))
	}
	var registry struct {
		Relays []string `json:"relays"`
	}
	if err := json.Unmarshal(registryJSON, &registry); err != nil {
		panic(fmt.Errorf("unmarshal registry json: %w", err))
	}
	releaseVersion = m.Release.Version
	releaseBaseURL = m.Release.BaseURL
	tunnelProtocolVersion = m.Protocol.Tunnel
	discoveryProtocolVersion = m.Protocol.Discovery
	bootstrapRelays = registry.Relays
}

// ReleaseVersion is the release version of these binaries.
func ReleaseVersion() string { return releaseVersion }

// ReleaseBaseURL is the official release download base URL.
func ReleaseBaseURL() string { return releaseBaseURL }

// TunnelProtocolVersion is the tunnel wire protocol version (manifest
// protocol.tunnel).
func TunnelProtocolVersion() string { return tunnelProtocolVersion }

// DiscoveryProtocolVersion is the discovery wire protocol version (manifest
// protocol.discovery).
func DiscoveryProtocolVersion() string { return discoveryProtocolVersion }

// BootstrapRelays returns a copy of the built-in bootstrap relay set.
func BootstrapRelays() []string { return slices.Clone(bootstrapRelays) }

// LLMsText is the relay-served llms.txt guide; its %s placeholders are filled
// in with the serving relay's URL.
func LLMsText() string { return llmsText }
