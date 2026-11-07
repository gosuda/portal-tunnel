package tunnel

import (
	"cmp"
	"os"
	"slices"
	"strings"

	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/gateway"
	"github.com/gosuda/portal-tunnel/v2/portal/discovery"
	"github.com/gosuda/portal-tunnel/v2/sdk/appauth"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

// Config is one tunnel as its user describes it. The flags of portal expose, a
// [[tunnels]] entry of the agent config and an Agent API request all become a
// Config, and Spec is the one way from a Config to the runtime. A Config holds
// what was set and nothing else: a nil or zero value stands for the default,
// which Spec fills in, so an agent config written from it repeats no default.
// The TOML keys are those of the agent config. The metadata, auth and payment
// components bring their own keys, so a setting added to a component needs no
// change here.
type Config struct {
	// Identity.
	Name         string `toml:"name,omitempty"`
	IdentityPath string `toml:"identity_path,omitempty"`
	IdentityJSON string `toml:"identity_json,omitempty"`

	// Transport: what the tunnel exposes.
	TargetAddr          string      `toml:"target,omitempty"`
	Serve               string      `toml:"serve,omitempty"`
	HTTPRoutes          []HTTPRoute `toml:"http_routes,omitempty"`
	StripRequestHeaders []string    `toml:"strip_request_headers,omitempty"`
	UDPEnabled          bool        `toml:"udp,omitempty"`
	UDPAddr             string      `toml:"udp_addr,omitempty"`
	TCPEnabled          bool        `toml:"tcp,omitempty"`
	// Cache comes from portal expose --cache; the agent config has no key for it.
	Cache *CacheConfig `toml:"-"`

	// Relays. A nil Discovery means on, a nil BanMITM means off, and a zero
	// MaxActiveRelays means discovery.DefaultMaxActiveRelays.
	RelayURLs       []string `toml:"relays,omitempty"`
	Discovery       *bool    `toml:"discovery,omitempty"`
	MaxActiveRelays int      `toml:"max_active_relays,omitempty"`
	Overlay         bool     `toml:"overlay,omitempty"`
	BanMITM         *bool    `toml:"ban_mitm,omitempty"`

	types.LeaseMetadata
	appauth.ApplicationAuthConfig
	gateway.X402Config
}

// Normalize puts c in the form a config stores: values without surrounding
// spaces, relay URLs in their canonical form, the methods of an HTTP route in
// upper case and once each, and each component as its owner normalizes it. Paths
// stay as they are; a frontend resolves a relative one against its own base.
func (c *Config) Normalize() error {
	c.Name = strings.TrimSpace(c.Name)
	c.TargetAddr = strings.TrimSpace(c.TargetAddr)
	c.Serve = strings.TrimSpace(c.Serve)
	c.UDPAddr = strings.TrimSpace(c.UDPAddr)
	if c.HTTPRoutes != nil {
		routes := make([]HTTPRoute, 0, len(c.HTTPRoutes))
		for _, route := range c.HTTPRoutes {
			routes = append(routes, HTTPRoute{
				Prefix:   strings.TrimSpace(route.Prefix),
				Upstream: strings.TrimSpace(route.Upstream),
				Methods:  normalizeHTTPMethods(route.Methods),
				Amount:   strings.TrimSpace(route.Amount),
			})
		}
		c.HTTPRoutes = routes
	}
	c.StripRequestHeaders = slices.Clone(c.StripRequestHeaders)
	relays, err := utils.NormalizeRelayURLs(c.RelayURLs...)
	if err != nil {
		return err
	}
	c.RelayURLs = relays
	c.Description = strings.TrimSpace(c.Description)
	c.Owner = strings.TrimSpace(c.Owner)
	c.Thumbnail = strings.TrimSpace(c.Thumbnail)
	c.Tags = utils.CompactStrings(c.Tags)
	if c.ApplicationAuthConfig, err = c.ApplicationAuthConfig.Normalize(); err != nil {
		return err
	}
	c.X402Config = c.X402Config.Normalize()
	return nil
}

func normalizeHTTPMethods(methods []string) []string {
	var out []string
	for _, method := range methods {
		method = strings.ToUpper(strings.TrimSpace(method))
		if method != "" && !slices.Contains(out, method) {
			out = append(out, method)
		}
	}
	return out
}

// Spec resolves c into the runtime description of the tunnel: it normalizes c,
// fills in the defaults and validates the result. Any auth setting, a static
// site, HTTP routes, the relay cache or a header to strip makes the tunnel an
// HTTP tunnel. The spec comes back as resolved even when it is not valid; only
// a value that cannot be normalized leaves it empty.
func (c Config) Spec() (Spec, error) {
	if err := c.Normalize(); err != nil {
		return Spec{}, err
	}
	spec := Spec{
		Identity: IdentitySpec{Name: c.Name, Path: c.IdentityPath, JSON: c.IdentityJSON},
		Relays: RelaySpec{
			URLs:      c.RelayURLs,
			Discovery: c.Discovery == nil || *c.Discovery,
			MaxActive: cmp.Or(c.MaxActiveRelays, discovery.DefaultMaxActiveRelays),
			Overlay:   c.Overlay,
			BanMITM:   c.BanMITM != nil && *c.BanMITM,
		},
		Metadata:  c.LeaseMetadata,
		Transport: TransportSpec{Target: c.TargetAddr, TCP: c.TCPEnabled},
	}
	if c.UDPEnabled {
		spec.Transport.UDP = &UDPConfig{Target: c.UDPAddr}
	}
	auth := c.ApplicationAuthConfig
	if c.Serve != "" || len(c.HTTPRoutes) > 0 || !auth.IsZero() || c.Cache != nil || len(c.StripRequestHeaders) > 0 {
		payment := gateway.X402Payment{X402Config: c.X402Config}
		payment.FacilitatorToken = cmp.Or(payment.FacilitatorToken, strings.TrimSpace(os.Getenv("CSPR_CLOUD_API_KEY")))
		spec.HTTP = &HTTPConfig{
			Serve:               c.Serve,
			Routes:              c.HTTPRoutes,
			StripRequestHeaders: c.StripRequestHeaders,
			Payment:             payment,
			Cache:               c.Cache,
		}
		if !auth.IsZero() {
			spec.HTTP.Auth = &auth
		}
	}
	return spec, spec.Validate()
}
