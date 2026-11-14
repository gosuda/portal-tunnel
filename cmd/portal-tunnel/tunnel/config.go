package tunnel

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/gateway"
	"github.com/gosuda/portal-tunnel/v2/portal/certmonitor"
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
	TLSMonitorStateDir    string `toml:"tls_monitor_state_dir,omitempty"`
	TLSMonitorBaseline    string `toml:"tls_monitor_baseline,omitempty"`
	TLSMonitorDNSResolver string `toml:"tls_monitor_dns_resolver,omitempty"`
	TLSAuto               bool   `toml:"tls_auto,omitempty"`
	TLSStateDir           string `toml:"tls_state_dir,omitempty"`
	TLSRequireLocal       bool   `toml:"tls_require_local,omitempty"`
	TLSCert               string `toml:"tls_cert,omitempty"`
	TLSKey                string `toml:"tls_key,omitempty"`

	PGNSZone             string   `toml:"pgns_zone,omitempty"`
	PGNSAlias            string   `toml:"pgns_alias,omitempty"`
	PGNSSiteLabel        string   `toml:"pgns_site_label,omitempty"`
	PGNSSequencers       []string `toml:"pgns_sequencers,omitempty"`
	PGNSWitnesses        []string `toml:"pgns_witnesses,omitempty"`
	PGNSWitnessThreshold int      `toml:"pgns_witness_threshold,omitempty"`
	PGNSStateDir         string   `toml:"pgns_state_dir,omitempty"`
	PGNSRecoveryPubKey   string   `toml:"pgns_recovery_pubkey,omitempty"`
	PGNSACMEDirectory    string   `toml:"pgns_acme_directory,omitempty"`
	PGNSACMEEmail        string   `toml:"pgns_acme_email,omitempty"`
	PGNSACMECAIssuer     string   `toml:"pgns_acme_caa_issuer,omitempty"`
	PGNSACMEEABKID       string   `toml:"pgns_acme_eab_kid,omitempty"`
	PGNSACMEEABHMAC      string   `toml:"pgns_acme_eab_hmac,omitempty"`
	PGNSPersist01        bool     `toml:"pgns_persist01,omitempty"`
	PGNSRelayEndpoints   []string `toml:"pgns_endpoints,omitempty"`

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
	Replica             bool        `toml:"replica,omitempty"`
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
		var err error
		route, err = parseConfigRoutePayment(route, fields[1])
		if err != nil {
			return HTTPRoute{}, err
		}
	}
	return route, nil
}

func parseConfigRoutePayment(route HTTPRoute, field string) (HTTPRoute, error) {
	methods, amount, hasMethods := strings.Cut(field, ":")
	if !hasMethods {
		amount = field
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
		routes, err := normalizeConfigHTTPRoutes(c.HTTPRoutes)
		if err != nil {
			return err
		}
		c.HTTPRoutes = routes
	}
	c.StripRequestHeaders = slices.Clone(c.StripRequestHeaders)
	c.normalizePGNS()
	relays, err := types.NormalizeRelayURLs(c.RelayURLs...)
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

func (c *Config) normalizePGNS() {
	c.PGNSZone = strings.TrimSpace(c.PGNSZone)
	c.PGNSAlias = strings.TrimSpace(c.PGNSAlias)
	c.PGNSSiteLabel = strings.TrimSpace(c.PGNSSiteLabel)
	c.PGNSStateDir = strings.TrimSpace(c.PGNSStateDir)
	c.PGNSRecoveryPubKey = strings.TrimSpace(c.PGNSRecoveryPubKey)
	c.PGNSACMEDirectory = strings.TrimSpace(c.PGNSACMEDirectory)
	c.PGNSACMEEmail = strings.TrimSpace(c.PGNSACMEEmail)
	c.PGNSACMECAIssuer = strings.TrimSpace(c.PGNSACMECAIssuer)
	c.PGNSACMEEABKID = strings.TrimSpace(c.PGNSACMEEABKID)
	c.PGNSACMEEABHMAC = strings.TrimSpace(c.PGNSACMEEABHMAC)
	c.PGNSSequencers = utils.CompactStrings(c.PGNSSequencers)
	c.PGNSWitnesses = utils.CompactStrings(c.PGNSWitnesses)
	c.PGNSRelayEndpoints = utils.CompactStrings(c.PGNSRelayEndpoints)
}

func normalizeConfigHTTPRoutes(routes []HTTPRoute) ([]HTTPRoute, error) {
	normalized := make([]HTTPRoute, 0, len(routes))
	for _, route := range routes {
		methods, err := gateway.NormalizePaymentMethods(route.Methods)
		if err != nil {
			return nil, fmt.Errorf("HTTP route %q: %w", route.Prefix, err)
		}
		normalized = append(normalized, HTTPRoute{
			Prefix:   strings.TrimSpace(route.Prefix),
			Upstream: strings.TrimSpace(route.Upstream),
			Methods:  methods,
			Amount:   strings.TrimSpace(route.Amount),
		})
	}
	return normalized, nil
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
		TLSCert:         c.TLSCert,
		TLSAuto:         c.TLSAuto,
		TLSStateDir:     c.TLSStateDir,
		TLSRequireLocal: c.TLSRequireLocal,
		TLSKey:          c.TLSKey,
		PGNS:            buildConfigSpecPGNS(c),
		Identity:        IdentitySpec{Name: c.Name, Path: c.IdentityPath, JSON: c.IdentityJSON},
		Relays: RelaySpec{
			URLs:      c.RelayURLs,
			Discovery: c.Discovery == nil || *c.Discovery,
			MaxActive: cmp.Or(c.MaxActiveRelays, discovery.DefaultMaxActiveRelays),
			Overlay:   c.Overlay,
			BanMITM:   c.BanMITM != nil && *c.BanMITM,
		},
		Metadata:  c.LeaseMetadata,
		Transport: TransportSpec{Target: c.TargetAddr, TCP: c.TCPEnabled, Replica: c.Replica},
	}
	if c.UDPEnabled {
		spec.Transport.UDP = &UDPConfig{Target: c.UDPAddr}
	}
	if c.TLSMonitorStateDir != "" || c.TLSMonitorBaseline != "" || c.TLSMonitorDNSResolver != "" {
		spec.CertificateMonitor = &certmonitor.MonitorConfig{
			StateDir:     c.TLSMonitorStateDir,
			BaselineFile: c.TLSMonitorBaseline,
			DNSResolver:  c.TLSMonitorDNSResolver,
		}
	}
	spec.HTTP = buildConfigSpecHTTP(c)
	if spec.TLSAuto && spec.TLSStateDir == "" {
		if spec.Identity.JSON == "" && spec.Identity.Path != "" {
			spec.TLSStateDir = spec.Identity.Path + ".tls"
		}
	}
	if spec.PGNS != nil && spec.PGNS.Zone != "" && spec.PGNS.StateDir == "" {
		if spec.Identity.JSON == "" && spec.Identity.Path != "" {
			spec.PGNS.StateDir = spec.Identity.Path + ".pgns"
		}
	}
	return spec, spec.Validate()
}

func buildConfigSpecPGNS(c Config) *PGNSConfig {
	configured := c.PGNSZone != "" ||
		c.PGNSAlias != "" ||
		c.PGNSSiteLabel != "" ||
		len(c.PGNSSequencers) > 0 ||
		len(c.PGNSWitnesses) > 0 ||
		c.PGNSWitnessThreshold != 0 ||
		c.PGNSStateDir != "" ||
		c.PGNSRecoveryPubKey != "" ||
		c.PGNSACMEDirectory != "" ||
		c.PGNSACMEEmail != "" ||
		c.PGNSACMECAIssuer != "" ||
		c.PGNSACMEEABKID != "" ||
		c.PGNSACMEEABHMAC != "" ||
		c.PGNSPersist01 ||
		len(c.PGNSRelayEndpoints) > 0
	if !configured {
		return nil
	}
	return &PGNSConfig{
		Zone:             c.PGNSZone,
		Alias:            c.PGNSAlias,
		SiteLabel:        c.PGNSSiteLabel,
		Sequencers:       c.PGNSSequencers,
		Witnesses:        c.PGNSWitnesses,
		WitnessThreshold: c.PGNSWitnessThreshold,
		StateDir:         c.PGNSStateDir,
		RecoveryPubKey:   c.PGNSRecoveryPubKey,
		ACMEDirectory:    c.PGNSACMEDirectory,
		ACMEEmail:        c.PGNSACMEEmail,
		ACMECAIssuer:     c.PGNSACMECAIssuer,
		ACMEEABKID:       c.PGNSACMEEABKID,
		ACMEEABHMAC:      c.PGNSACMEEABHMAC,
		Persist01:        c.PGNSPersist01,
		RelayEndpoints:   c.PGNSRelayEndpoints,
	}
}

func buildConfigSpecHTTP(c Config) *HTTPConfig {
	auth := c.AuthConfig
	localTLS := c.TLSAuto || c.TLSCert != "" || c.PGNSZone != ""
	httpRouting := c.Replica || c.Serve != "" || len(c.HTTPRoutes) != 0
	httpPolicy := !auth.IsZero() || c.Cache != nil || len(c.StripRequestHeaders) != 0
	if !localTLS && !httpRouting && !httpPolicy {
		return nil
	}
	httpConfig := &HTTPConfig{
		Serve:               c.Serve,
		Routes:              c.HTTPRoutes,
		StripRequestHeaders: c.StripRequestHeaders,
		Payment:             c.X402Config,
		Cache:               c.Cache,
	}
	if !auth.IsZero() {
		httpConfig.Auth = &auth
	}
	return httpConfig
}
