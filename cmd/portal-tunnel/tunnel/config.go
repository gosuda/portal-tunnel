package tunnel

import (
	"cmp"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	nanoscheme "github.com/gosuda/x402-facilitator/scheme/nano"

	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/gateway"
	"github.com/gosuda/portal-tunnel/v2/portal/certmonitor"
	"github.com/gosuda/portal-tunnel/v2/portal/discovery"
	"github.com/gosuda/portal-tunnel/v2/portal/namespace"
	"github.com/gosuda/portal-tunnel/v2/sdk/appauth"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

// Config is one tunnel as its user describes it: the flags of portal expose,
// a [[tunnels]] entry of the agent config, or an Agent API request. A Config
// holds what was set and nothing else; nil and zero values stand for defaults
// that Resolve fills in on an execution copy. The TOML keys are those of the agent config.
type Config struct {
	TLSMonitorStateDir    string `toml:"tls_monitor_state_dir,omitempty"`
	TLSMonitorBaseline    string `toml:"tls_monitor_baseline,omitempty"`
	TLSMonitorDNSResolver string `toml:"tls_monitor_dns_resolver,omitempty"`
	TLSAuto               bool   `toml:"tls_auto,omitempty"`
	TLSStateDir           string `toml:"tls_state_dir,omitempty"`
	TLSRequireLocal       bool   `toml:"tls_require_local,omitempty"`
	TLSCert               string `toml:"tls_cert,omitempty"`
	TLSKey                string `toml:"tls_key,omitempty"`
	Name                  string `toml:"name,omitempty"`
	IdentityPath          string `toml:"identity_path,omitempty"`
	IdentityJSON          string `toml:"identity_json,omitempty"`

	TargetAddr          string      `toml:"target,omitempty"`
	Serve               string      `toml:"serve,omitempty"`
	HTTPRoutes          []HTTPRoute `toml:"http_routes,omitempty"`
	StripRequestHeaders []string    `toml:"strip_request_headers,omitempty"`
	UDPEnabled          bool        `toml:"udp,omitempty"`
	UDPAddr             string      `toml:"udp_addr,omitempty"`
	TCPEnabled          bool        `toml:"tcp,omitempty"`
	Replica             bool        `toml:"replica,omitempty"`
	Inspect             bool        `toml:"inspect,omitempty"`
	InspectBodies       bool        `toml:"inspect_bodies,omitempty"`
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
	c.HTTPRoutes = slices.Clone(c.HTTPRoutes)
	for i := range c.HTTPRoutes {
		route := &c.HTTPRoutes[i]
		methods, err := gateway.NormalizePaymentMethods(route.Methods)
		if err != nil {
			return fmt.Errorf("HTTP route %q: %w", route.Prefix, err)
		}
		route.Prefix, route.Upstream, route.Amount = strings.TrimSpace(route.Prefix), strings.TrimSpace(route.Upstream), strings.TrimSpace(route.Amount)
		route.Methods = methods
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

// Resolve returns an execution copy without changing the stored settings.
func (c Config) Resolve() (Config, error) {
	if err := c.Normalize(); err != nil {
		return Config{}, err
	}
	c.Discovery = new(c.DiscoveryEnabled())
	c.BanMITM = new(c.BanMITM != nil && *c.BanMITM)
	c.MaxActiveRelays = c.RelayLimit()
	if c.TLSAuto && c.TLSStateDir == "" && c.IdentityJSON == "" && c.IdentityPath != "" {
		c.TLSStateDir = c.IdentityPath + ".tls"
	}
	return c, c.validate()
}

func (c Config) usesHTTP() bool {
	return c.Inspect || c.TLSAuto || c.TLSCert != "" || c.Replica || c.Serve != "" || len(c.HTTPRoutes) > 0 ||
		!c.IsZero() || c.Cache != nil || len(c.StripRequestHeaders) > 0
}

func (c Config) certificateMonitor() *certmonitor.MonitorConfig {
	if c.TLSMonitorStateDir == "" && c.TLSMonitorBaseline == "" && c.TLSMonitorDNSResolver == "" {
		return nil
	}
	return &certmonitor.MonitorConfig{StateDir: c.TLSMonitorStateDir, BaselineFile: c.TLSMonitorBaseline, DNSResolver: c.TLSMonitorDNSResolver}
}

type HTTPRoute struct {
	Prefix   string   `json:"prefix" toml:"prefix,omitempty"`
	Upstream string   `json:"upstream" toml:"upstream,omitempty"`
	Methods  []string `json:"methods,omitempty" toml:"methods,omitempty"`
	Amount   string   `json:"amount,omitempty" toml:"amount,omitempty"`
}

type CacheConfig struct{ TTL time.Duration }

var (
	errReplicaRequiresHTTP    = errors.New("replicas require HTTP without dedicated TCP/UDP ports, relay cache, or overlay")
	errReplicaApplicationAuth = errors.New("replicas cannot use email or SAML authentication: one-time login consumption is local to each gateway")
	errReplicaNanoPayments    = errors.New("replicas cannot use Nano payments: payment proof consumption is local to each gateway")
)

func (c Config) validate() error {
	if c.Name != "" {
		if _, err := namespace.NormalizeServiceName(c.Name); err != nil {
			return fmt.Errorf("tunnel name: %w", err)
		}
	}
	if c.InspectBodies && !c.Inspect {
		return fmt.Errorf("inspect_bodies requires inspect")
	}
	if c.Inspect && c.Cache != nil {
		return fmt.Errorf("HTTP inspection cannot be combined with relay cache")
	}
	if c.Replica {
		if c.Cache != nil || c.Overlay || c.TCPEnabled || c.UDPEnabled {
			return errReplicaRequiresHTTP
		}
		if nanoscheme.IsNanoNetwork(c.Network) {
			for _, route := range c.HTTPRoutes {
				if route.Amount != "" {
					return errReplicaNanoPayments
				}
			}
		}
		if c.Provider == appauth.ProviderEmail || c.Provider == appauth.ProviderSAML {
			return errReplicaApplicationAuth
		}
	}
	if monitor := c.certificateMonitor(); monitor != nil {
		if c.TCPEnabled || c.Cache != nil {
			return fmt.Errorf("TLS certificate monitoring cannot be combined with relay cache or raw TCP")
		}
		if err := monitor.Validate(); err != nil {
			return err
		}
	}
	if (c.TLSCert == "") != (c.TLSKey == "") {
		return fmt.Errorf("tls_cert and tls_key must be configured together")
	}
	if c.TLSAuto {
		if c.TLSCert != "" {
			return fmt.Errorf("tls_auto cannot be combined with tls_cert or tls_key")
		}
		if c.TLSStateDir == "" {
			return fmt.Errorf("tls_auto requires tls_state_dir when no file-backed identity is configured")
		}
	} else if c.TLSStateDir != "" {
		return fmt.Errorf("tls_state_dir requires tls_auto")
	}
	if c.TLSRequireLocal && !c.TLSAuto && c.TLSCert == "" {
		return fmt.Errorf("tls_require_local requires tls_auto or local certificate files")
	}
	if (c.TLSCert != "" || c.TLSAuto) && c.TCPEnabled {
		return fmt.Errorf("local TLS certificates cannot be combined with raw TCP")
	}
	if !c.usesHTTP() {
		if c.TargetAddr == "" {
			return fmt.Errorf("tunnel target is required")
		}
		if _, err := utils.NormalizeLoopbackTarget(c.TargetAddr); err != nil {
			return fmt.Errorf("target: %w", err)
		}
		if _, err := utils.NormalizeLoopbackTarget(c.UDPAddr); err != nil {
			return fmt.Errorf("udp_addr: %w", err)
		}
		return nil
	}
	if c.TCPEnabled || c.UDPEnabled {
		return fmt.Errorf("HTTP tunnel cannot be combined with TCP or UDP")
	}
	if c.Serve != "" {
		if c.TargetAddr != "" || len(c.HTTPRoutes) > 0 {
			return fmt.Errorf("static serving cannot be combined with a target or HTTP routes")
		}
	} else if c.TargetAddr == "" && len(c.HTTPRoutes) == 0 {
		return fmt.Errorf("HTTP tunnel requires a target, route, or static site")
	}
	if c.TargetAddr != "" && len(c.HTTPRoutes) > 0 {
		return fmt.Errorf("HTTP tunnel cannot combine a target and routes")
	}
	if c.TargetAddr != "" {
		if _, err := utils.NormalizeHTTPUpstream(c.TargetAddr); err != nil {
			return fmt.Errorf("target: %w", err)
		}
	}
	if c.Cache != nil {
		if c.Serve == "" {
			return fmt.Errorf("relay cache requires a static site")
		}
		if c.BanMITM != nil && *c.BanMITM {
			return fmt.Errorf("relay cache permits TLS termination and cannot be combined with MITM protection")
		}
		if !c.IsZero() {
			return fmt.Errorf("application auth cannot be combined with relay cache")
		}
	}
	for _, route := range c.HTTPRoutes {
		if route.Prefix == "" || route.Upstream == "" {
			return fmt.Errorf("HTTP routes require a prefix and upstream")
		}
		if !strings.HasPrefix(route.Prefix, "/") {
			return fmt.Errorf("HTTP route %q prefix must start with /", route.Prefix)
		}
		if route.Amount != "" && c.PayTo == "" {
			return fmt.Errorf("HTTP route %q payment amount requires a payment recipient", route.Prefix)
		}
		if route.Amount == "" && len(route.Methods) > 0 {
			return fmt.Errorf("HTTP route %q methods require a payment amount", route.Prefix)
		}
	}
	if len(c.StripRequestHeaders) > 0 {
		if c.Serve != "" {
			return fmt.Errorf("strip request headers cannot be combined with static serving (--serve); static sites do not proxy request headers")
		}
		for _, header := range c.StripRequestHeaders {
			switch strings.ToLower(strings.TrimSpace(header)) {
			case "host":
				return fmt.Errorf(`strip request header "Host" is not supported: Go stores it in Request.Host, not Header`)
			case "x-forwarded-proto":
				return fmt.Errorf(`strip request header "X-Forwarded-Proto" is not supported: RunHTTP always overwrites it with the trusted https value`)
			}
		}
	}
	if !c.IsZero() {
		return appauth.Validate(c.AuthConfig)
	}
	return nil
}

// DiscoveryEnabled and RelayLimit apply defaults without changing stored intent.
func (c Config) DiscoveryEnabled() bool { return c.Discovery == nil || *c.Discovery }
func (c Config) RelayLimit() int        { return cmp.Or(c.MaxActiveRelays, discovery.DefaultMaxActiveRelays) }
