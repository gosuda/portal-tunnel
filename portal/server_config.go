package portal

import (
	"cmp"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/gosuda/portal-tunnel/v2/portal/acme"
	"github.com/gosuda/portal-tunnel/v2/portal/cache"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

const DefaultHTTPRedirectAddr = ":80"

// HTTPRedirectConfig controls the optional canonical-portal HTTP listener.
// The zero value disables redirects and HSTS; an empty Addr defaults to :80.
type HTTPRedirectConfig struct {
	Enabled bool
	Addr    string
	HSTS    bool
}

type ServerConfig struct {
	Cache            cache.Config
	IVNPConfigPath   string
	PortalURL        string
	StateDir         string
	Bootstraps       []string
	DiscoveryEnabled bool
	SNIPort          int
	HTTPRedirect     HTTPRedirectConfig
	SNIListenAddr    string
	MinPort          int
	MaxPort          int
	ACME             acme.Config
	// UnapprovedLeasesPerSource bounds the leases one source can hold without
	// being routable. Zero disables the bound.
	UnapprovedLeasesPerSource int
	// DefaultIdentityBPS is the stream budget in bytes/second for identities
	// without an operator override. Zero permits unlimited traffic.
	DefaultIdentityBPS int

	// ApplicationOwnsDomainReport delegates types.PathSDKDomain to the
	// application handler, which can compose Server.DomainReport() itself.
	ApplicationOwnsDomainReport bool
}

// NormalizeHTTPRedirectConfig validates redirect settings without resolving names
// or binding sockets. Listener availability is checked only when the server starts.
func parsePortInRange(portStr string, min, max int, outErr error) (int, error) {
	n, err := strconv.Atoi(portStr)
	if err != nil {
		return 0, fmt.Errorf("%w: %w", outErr, err)
	}
	if n < min || n > max {
		return 0, outErr
	}
	return n, nil
}

func parseRedirectTarget(portalURL string) (*url.URL, error) {
	target, err := url.Parse(strings.TrimSpace(portalURL))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errHTTPRedirectRequiresPortalURLAbsolute, err)
	}
	hasHTTPSOrigin := target.Scheme == "https" && utils.NormalizeHostname(target.Hostname()) != "" && target.Opaque == ""
	if !hasHTTPSOrigin || target.User != nil || strings.HasSuffix(target.Host, ":") {
		return nil, errHTTPRedirectRequiresPortalURLAbsolute
	}
	if port := target.Port(); port != "" {
		if _, err := parsePortInRange(port, 1, 65535, errHTTPRedirectPortalURLPortMust); err != nil {
			return nil, err
		}
	}
	return target, nil
}

func normalizeRedirectAddr(cfg HTTPRedirectConfig) (HTTPRedirectConfig, error) {
	cfg.Addr = cmp.Or(strings.TrimSpace(cfg.Addr), DefaultHTTPRedirectAddr)
	host, port, err := net.SplitHostPort(cfg.Addr)
	if err != nil {
		return HTTPRedirectConfig{}, fmt.Errorf("http redirect HTTP_REDIRECT_ADDR must be a host:port address: %w", err)
	}
	if strings.ContainsAny(host, " \t\r\n/#?@\\") {
		return HTTPRedirectConfig{}, errHTTPRedirectHTTPRedirectAddrHas
	}
	if strings.Contains(host, ":") {
		if _, err := netip.ParseAddr(host); err != nil {
			return HTTPRedirectConfig{}, fmt.Errorf("http redirect HTTP_REDIRECT_ADDR has an invalid IP address: %w", err)
		}
	}
	if _, err := parsePortInRange(port, 0, 65535, errHTTPRedirectHTTPRedirectAddrPort); err != nil {
		return HTTPRedirectConfig{}, err
	}
	return cfg, nil
}

func NormalizeHTTPRedirectConfig(cfg HTTPRedirectConfig, portalURL string) (HTTPRedirectConfig, error) {
	if !cfg.Enabled {
		return cfg, nil
	}
	if _, err := parseRedirectTarget(portalURL); err != nil {
		return HTTPRedirectConfig{}, err
	}
	return normalizeRedirectAddr(cfg)
}

// ValidateServerConfig normalizes server configuration and checks the
// side-effect-free invariants required before runtime resources are created.
func applyValidateServerConfigACME(cfg ServerConfig) (ServerConfig, error) {
	caDirURL, err := acme.NormalizeCADirURL(cfg.ACME.CADirURL)
	if err != nil {
		return ServerConfig{}, err
	}
	cfg.ACME.CADirURL = caDirURL
	if err := cfg.Cache.Validate(); err != nil {
		return ServerConfig{}, err
	}
	return cfg, nil
}

func applyValidateServerConfigRelayURLs(cfg ServerConfig) (ServerConfig, error) {
	selfRelayURL, err := utils.NormalizeRelayURL(cfg.PortalURL)
	if err != nil {
		return ServerConfig{}, fmt.Errorf("normalize portal url: %w", err)
	}
	if utils.PortalRootHost(selfRelayURL) == "" {
		return ServerConfig{}, errRootHostIsRequired
	}
	bootstraps, err := utils.NormalizeRelayURLs(cfg.Bootstraps...)
	if err != nil {
		return ServerConfig{}, fmt.Errorf("normalize bootstraps: %w", err)
	}
	cfg.PortalURL = selfRelayURL
	cfg.Bootstraps = bootstraps
	cfg.Bootstraps = removeRelayURL(cfg.Bootstraps, selfRelayURL)
	return cfg, nil
}

func finishValidateServerConfigPorts(cfg ServerConfig) ServerConfig {
	if cfg.SNIPort == 0 {
		cfg.SNIPort = DefaultSNIPort(cfg.PortalURL)
	}
	cfg.SNIPort = utils.IntOrDefault(cfg.SNIPort, 443)
	cfg.SNIListenAddr = cmp.Or(cfg.SNIListenAddr, fmt.Sprintf(":%d", cfg.SNIPort))
	return cfg
}

func ValidateServerConfig(cfg ServerConfig) (ServerConfig, error) {
	if cfg.DefaultIdentityBPS < 0 {
		return ServerConfig{}, errDefaultIdentityBPSMustNonNegative
	}
	if cfg.UnapprovedLeasesPerSource < 0 {
		return ServerConfig{}, errUnapprovedLeaseLimitNegative
	}
	cfg.IVNPConfigPath = strings.TrimSpace(cfg.IVNPConfigPath)
	if cfg.IVNPConfigPath != "" && !cfg.DiscoveryEnabled {
		return ServerConfig{}, errRelayOverlayRequiresDiscovery
	}
	cfg.PortalURL = strings.TrimSuffix(strings.TrimSpace(cfg.PortalURL), "/")
	cfg.StateDir = strings.TrimSpace(cfg.StateDir)
	if cfg.StateDir == "" {
		return ServerConfig{}, errStateDirectoryIsRequired
	}
	if strings.TrimSpace(cfg.ACME.KeyDir) == "" {
		cfg.ACME.KeyDir = cfg.StateDir
	}
	next, err := applyValidateServerConfigACME(cfg)
	if err != nil {
		return ServerConfig{}, err
	}
	cfg = next
	if cfg.HTTPRedirect, err = NormalizeHTTPRedirectConfig(cfg.HTTPRedirect, cfg.PortalURL); err != nil {
		return ServerConfig{}, err
	}
	next, err = applyValidateServerConfigRelayURLs(cfg)
	if err != nil {
		return ServerConfig{}, err
	}
	cfg = next
	return finishValidateServerConfigPorts(cfg), nil
}

// DefaultSNIPort returns the local SNI listener port for a deployment that
// leaves SNI_PORT unset: the explicit PORTAL_URL port when the canonical
// origin names one, otherwise 443.
func DefaultSNIPort(portalURL string) int {
	normalized, err := utils.NormalizeRelayURL(portalURL)
	if err != nil {
		return 443
	}
	parsed, err := url.Parse(normalized)
	if err != nil || parsed.Port() == "" {
		return 443
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil || port < 1 || port > 65535 {
		return 443
	}
	return port
}

func (cfg ServerConfig) snapshot() ServerConfig {
	cfg.Bootstraps = slices.Clone(cfg.Bootstraps)
	return cfg
}

// ValidateTransportPolicy checks policy limits and the configured lease port range.
// Runtime availability is checked by Server.ValidateTransportPolicy.
func (cfg ServerConfig) ValidateTransportPolicy(udpEnabled bool, udpMaxLeases int, tcpEnabled bool, tcpMaxLeases int) error {
	if udpMaxLeases < 0 || tcpMaxLeases < 0 {
		return errTransportMaxLeasesMustNonNegative
	}
	if udpEnabled || tcpEnabled {
		minInRange := cfg.MinPort > 0 && cfg.MinPort <= 65535
		maxInRange := cfg.MaxPort > 0 && cfg.MaxPort <= 65535
		if !minInRange || !maxInRange || cfg.MinPort > cfg.MaxPort {
			return errTransportEnablementRequiresLeasePortRange
		}
	}
	return nil
}
