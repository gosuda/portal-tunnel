package tunnel

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/gateway"
	"github.com/gosuda/portal-tunnel/v2/portal/discovery"
	"github.com/gosuda/portal-tunnel/v2/sdk/appauth"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

// Config is one tunnel as its user describes it: the flags of portal expose,
// a [[tunnels]] entry of the agent config, or an Agent API request. A Config
// holds what was set and nothing else; nil and zero values stand for defaults
// that Spec fills in. The TOML keys are those of the agent config.
type Config struct {
	TLSCert      string `toml:"tls_cert,omitempty"`
	TLSKey       string `toml:"tls_key,omitempty"`
	Name         string `toml:"name,omitempty"`
	IdentityPath string `toml:"identity_path,omitempty"`
	IdentityJSON string `toml:"identity_json,omitempty"`

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
	AuthConfig
	gateway.X402Config
}

// AuthConfig is the application auth component of a tunnel.
type AuthConfig = appauth.Config

// ParseHTTPRoute parses one PATH=UPSTREAM [METHOD[,METHOD...]:AMOUNT] entry.
// An amount without methods applies payment to every method.
func ParseHTTPRoute(value string) (HTTPRoute, error) {
	prefix, rest, ok := strings.Cut(value, "=")
	if !ok {
		return HTTPRoute{}, fmt.Errorf("expected PATH=UPSTREAM [METHOD[,METHOD...]:AMOUNT]")
	}
	prefix = strings.TrimSpace(prefix)
	if !strings.HasPrefix(prefix, "/") {
		return HTTPRoute{}, fmt.Errorf("route path %q must start with /", prefix)
	}
	fields := strings.Fields(rest)
	if len(fields) == 0 || len(fields) > 2 {
		return HTTPRoute{}, fmt.Errorf("expected an upstream and optional payment amount")
	}
	route := HTTPRoute{Prefix: utils.NormalizeURLPath(prefix), Upstream: fields[0]}
	if len(fields) == 2 {
		methods, amount, hasMethods := strings.Cut(fields[1], ":")
		if !hasMethods {
			amount = fields[1]
		}
		if amount == "" {
			return HTTPRoute{}, fmt.Errorf("payment amount is required")
		}
		route.Amount = amount
		if hasMethods {
			var err error
			route.Methods, err = gateway.NormalizePaymentMethods(strings.Split(methods, ","))
			if err != nil {
				return HTTPRoute{}, err
			}
		}
	}
	return route, nil
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
			methods, err := gateway.NormalizePaymentMethods(route.Methods)
			if err != nil {
				return fmt.Errorf("HTTP route %q: %w", route.Prefix, err)
			}
			routes = append(routes, HTTPRoute{
				Prefix:   strings.TrimSpace(route.Prefix),
				Upstream: strings.TrimSpace(route.Upstream),
				Methods:  methods,
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
	if c.AuthConfig, err = c.AuthConfig.Normalize(); err != nil {
		return err
	}
	c.X402Config = c.X402Config.Normalize()
	return nil
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
		TLSCert:  c.TLSCert,
		TLSKey:   c.TLSKey,
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
	auth := c.AuthConfig
	if c.Serve != "" || len(c.HTTPRoutes) > 0 || !auth.IsZero() || c.Cache != nil || len(c.StripRequestHeaders) > 0 {
		spec.HTTP = &HTTPConfig{
			Serve:               c.Serve,
			Routes:              c.HTTPRoutes,
			StripRequestHeaders: c.StripRequestHeaders,
			Payment:             c.X402Config,
			Cache:               c.Cache,
		}
		if !auth.IsZero() {
			spec.HTTP.Auth = &auth
		}
	}
	return spec, spec.Validate()
}
