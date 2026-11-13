package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/gateway"
	"github.com/gosuda/portal-tunnel/v2/portal/certmonitor"
	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/sdk"
	"github.com/gosuda/portal-tunnel/v2/sdk/appauth"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

var (
	errTLSAutomaticWithFiles                   = errors.New("tls_auto cannot be combined with tls_cert or tls_key")
	errTLSAutomaticStateRequired               = errors.New("tls_auto requires tls_state_dir when no file-backed identity is configured")
	errTLSStateWithoutAutomatic                = errors.New("tls_state_dir requires tls_auto")
	errTLSRequireLocalWithoutMode              = errors.New("tls_require_local requires tls_auto or local certificate files")
	errTLSCertificatePairRequired              = errors.New("tls_cert and tls_key must be configured together")
	errLocalTLSWithRawTCP                      = errors.New("local TLS certificates cannot be combined with raw TCP")
	errLocalTLSWithRelayCache                  = errors.New("local TLS certificates cannot be combined with relay cache")
	errCertificateMonitorModeUnsupported       = errors.New("TLS certificate monitoring cannot be combined with relay cache or raw TCP")
	errTunnelTargetIsRequired                  = errors.New("tunnel target is required")
	errHTTPTunnelCannotCombinedTCPOr           = errors.New("HTTP tunnel cannot be combined with TCP or UDP")
	errStaticServingCannotCombinedTargetOr     = errors.New("static serving cannot be combined with a target or HTTP routes")
	errHTTPTunnelRequiresTargetRouteOr         = errors.New("HTTP tunnel requires a target, route, or static site")
	errHTTPTunnelCannotCombineTargetAnd        = errors.New("HTTP tunnel cannot combine a target and routes")
	errRelayCacheRequiresStaticSite            = errors.New("relay cache requires a static site")
	errRelayCachePermitsTLSTerminationAnd      = errors.New("relay cache permits TLS termination and cannot be combined with MITM protection")
	errApplicationAuthCannotCombinedRelayCache = errors.New("application auth cannot be combined with relay cache")
	errHTTPRoutesRequirePrefixAndUpstream      = errors.New("HTTP routes require a prefix and upstream")
	errStripRequestHeadersCannotCombinedStatic = errors.New("strip request headers cannot be combined with static serving (--serve); static sites do not proxy request headers")
	errStripRequestHeadersRequireHTTPUpstream  = errors.New("strip request headers require an HTTP upstream route or target")
	errStripRequestHeaderHostNotSupported      = errors.New(`strip request header "Host" is not supported: Go stores it in Request.Host, not Header`)
	errStripRequestHeaderXForwardedProto       = errors.New(`strip request header "X-Forwarded-Proto" is not supported: RunHTTP always overwrites it with the trusted https value`)
	errCasperPaymentsRequireAnAsset            = errors.New("casper payments require an asset")
)

// Spec is the resolved description of one tunnel that the runtime is built from.
type Spec struct {
	CertificateMonitor *certmonitor.MonitorConfig
	TLSAuto            bool
	TLSStateDir        string
	TLSRequireLocal    bool
	TLSCert            string
	TLSKey             string
	Identity           IdentitySpec
	Relays             RelaySpec
	Metadata           types.LeaseMetadata
	Transport          TransportSpec
	HTTP               *HTTPConfig
}

type IdentitySpec struct {
	Name string
	Path string
	JSON string
}

type RelaySpec struct {
	URLs      []string
	Discovery bool
	MaxActive int
	Overlay   bool
	BanMITM   bool
}

type TransportSpec struct {
	Target string
	TCP    bool
	UDP    *UDPConfig
}

type UDPConfig struct {
	Target string
}

type HTTPConfig struct {
	Routes  []HTTPRoute
	Serve   string
	Auth    *appauth.Config
	Payment gateway.X402Config
	Cache   *CacheConfig
	// StripRequestHeaders lists client request headers removed before
	// forwarding to every routed HTTP upstream.
	StripRequestHeaders []string
}

type HTTPRoute struct {
	Prefix   string   `json:"prefix" toml:"prefix,omitempty"`
	Upstream string   `json:"upstream" toml:"upstream,omitempty"`
	Methods  []string `json:"methods,omitempty" toml:"methods,omitempty"`
	Amount   string   `json:"amount,omitempty" toml:"amount,omitempty"`
}

type CacheConfig struct {
	TTL time.Duration
}

func validateHTTPCoupling(spec Spec) error {
	target := strings.TrimSpace(spec.Transport.Target)
	httpConfig := spec.HTTP
	if spec.Transport.TCP || spec.Transport.UDP != nil {
		return errHTTPTunnelCannotCombinedTCPOr
	}
	if strings.TrimSpace(httpConfig.Serve) != "" {
		if target != "" || len(httpConfig.Routes) > 0 {
			return errStaticServingCannotCombinedTargetOr
		}
	} else if target == "" && len(httpConfig.Routes) == 0 {
		return errHTTPTunnelRequiresTargetRouteOr
	}
	if target != "" && len(httpConfig.Routes) > 0 {
		return errHTTPTunnelCannotCombineTargetAnd
	}
	return nil
}

func validateHTTPCache(spec Spec) error {
	httpConfig := spec.HTTP
	if httpConfig.Cache == nil {
		return nil
	}
	if strings.TrimSpace(httpConfig.Serve) == "" {
		return errRelayCacheRequiresStaticSite
	}
	if spec.Relays.BanMITM {
		return errRelayCachePermitsTLSTerminationAnd
	}
	if httpConfig.Auth != nil {
		return errApplicationAuthCannotCombinedRelayCache
	}
	return nil
}

func validateHTTPRoutes(config *HTTPConfig) error {
	for _, route := range config.Routes {
		prefix := strings.TrimSpace(route.Prefix)
		if prefix == "" || strings.TrimSpace(route.Upstream) == "" {
			return errHTTPRoutesRequirePrefixAndUpstream
		}
		if !strings.HasPrefix(prefix, "/") {
			return fmt.Errorf("HTTP route %q prefix must start with /", prefix)
		}
		if strings.TrimSpace(route.Amount) != "" && strings.TrimSpace(config.Payment.PayTo) == "" {
			return fmt.Errorf("HTTP route %q payment amount requires a payment recipient", prefix)
		}
		if strings.TrimSpace(route.Amount) == "" && len(route.Methods) > 0 {
			return fmt.Errorf("HTTP route %q methods require a payment amount", prefix)
		}
	}
	return nil
}

func validateStripRequestHeaders(spec Spec) error {
	httpConfig := spec.HTTP
	if len(httpConfig.StripRequestHeaders) == 0 {
		return nil
	}
	if strings.TrimSpace(httpConfig.Serve) != "" {
		return errStripRequestHeadersCannotCombinedStatic
	}
	target := strings.TrimSpace(spec.Transport.Target)
	hasHTTPUpstream := len(httpConfig.Routes) > 0 || strings.TrimSpace(target) != "" || httpConfig.Auth != nil
	if !hasHTTPUpstream {
		return errStripRequestHeadersRequireHTTPUpstream
	}
	for _, h := range httpConfig.StripRequestHeaders {
		if strings.EqualFold(strings.TrimSpace(h), "Host") {
			return errStripRequestHeaderHostNotSupported
		}
		if strings.EqualFold(strings.TrimSpace(h), "X-Forwarded-Proto") {
			return errStripRequestHeaderXForwardedProto
		}
	}
	return nil
}

func (spec Spec) Validate() error {
	if spec.CertificateMonitor != nil {
		if spec.Transport.TCP || (spec.HTTP != nil && spec.HTTP.Cache != nil) {
			return errCertificateMonitorModeUnsupported
		}
		if err := spec.CertificateMonitor.Validate(); err != nil {
			return err
		}
	}
	if (spec.TLSCert == "") != (spec.TLSKey == "") {
		return errTLSCertificatePairRequired
	}
	if spec.TLSAuto {
		if spec.TLSCert != "" {
			return errTLSAutomaticWithFiles
		}
		if spec.TLSStateDir == "" {
			return errTLSAutomaticStateRequired
		}
	} else if spec.TLSStateDir != "" {
		return errTLSStateWithoutAutomatic
	}
	if spec.TLSRequireLocal && !spec.TLSAuto && spec.TLSCert == "" {
		return errTLSRequireLocalWithoutMode
	}
	if spec.TLSCert != "" || spec.TLSAuto {
		if spec.Transport.TCP {
			return errLocalTLSWithRawTCP
		}
		if spec.HTTP != nil && spec.HTTP.Cache != nil {
			return errLocalTLSWithRelayCache
		}
	}
	target := strings.TrimSpace(spec.Transport.Target)
	if spec.HTTP == nil {
		if target == "" {
			return errTunnelTargetIsRequired
		}
		return nil
	}
	if err := validateHTTPCoupling(spec); err != nil {
		return err
	}
	if err := validateHTTPCache(spec); err != nil {
		return err
	}
	if err := validateHTTPRoutes(spec.HTTP); err != nil {
		return err
	}
	if err := validateStripRequestHeaders(spec); err != nil {
		return err
	}
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(spec.HTTP.Payment.Network)), "casper:") && strings.TrimSpace(spec.HTTP.Payment.Asset) == "" {
		return errCasperPaymentsRequireAnAsset
	}
	if auth := spec.HTTP.Auth; auth != nil {
		if err := appauth.Validate(*auth); err != nil {
			return err
		}
	}
	return nil
}

// Runtime owns the assembled Portal tunnel and its low-level exposure.
type Runtime struct {
	Identity     types.Identity
	Exposure     *sdk.Exposure
	handler      http.Handler
	target       string
	udpTarget    string
	authProvider atomic.Pointer[authProviderCheck]
}

type authProviderCheck struct{ err error }

func buildExposedRoutes(spec Spec) ([]gateway.ExposedHTTPRoute, error) {
	routes := make([]gateway.ExposedHTTPRoute, 0)
	if spec.HTTP == nil {
		return routes, nil
	}
	if serve := strings.TrimSpace(spec.HTTP.Serve); serve != "" {
		root, index, err := utils.ResolveStaticSite(serve)
		if err != nil {
			return nil, fmt.Errorf("resolve static site %q: %w", serve, err)
		}
		routes = append(routes, gateway.ExposedHTTPRoute{Prefix: "/", StaticRoot: root, StaticIndex: index})
	}
	for _, route := range spec.HTTP.Routes {
		routes = append(routes, gateway.ExposedHTTPRoute{
			Prefix: route.Prefix, Upstream: route.Upstream,
			Methods: append([]string(nil), route.Methods...), Amount: route.Amount,
		})
	}
	if len(routes) == 0 {
		routes = append(routes, gateway.ExposedHTTPRoute{Prefix: "/", Upstream: spec.Transport.Target})
	}
	return routes, nil
}

func buildExposureOptions(spec Spec) []sdk.Option {
	opts := []sdk.Option{
		sdk.WithMITMProtection(spec.Relays.BanMITM),
		sdk.WithTLSCertificate(spec.TLSCert, spec.TLSKey),
		sdk.WithMetadata(spec.Metadata),
	}
	if spec.TLSAuto {
		opts = append(opts, sdk.WithAutomaticTLS(spec.TLSStateDir, spec.TLSRequireLocal))
	}
	if monitor := spec.CertificateMonitor; monitor != nil {
		opts = append(opts, sdk.WithCertificateMonitoring(monitor.StateDir, monitor.BaselineFile, monitor.DNSResolver))
	}
	if spec.Transport.UDP != nil {
		opts = append(opts, sdk.WithUDP())
	}
	if spec.Transport.TCP {
		opts = append(opts, sdk.WithTCP())
	}
	if spec.Relays.Overlay {
		opts = append(opts, sdk.WithOverlay())
	}
	if spec.Relays.Discovery {
		opts = append(opts, sdk.WithDiscovery(spec.Relays.MaxActive))
	}
	if spec.HTTP != nil && spec.HTTP.Cache != nil {
		opts = append(opts, sdk.WithStaticRelayCache(spec.HTTP.Serve, spec.HTTP.Cache.TTL))
	}
	return opts
}

func composeTunnelHandler(spec Spec, runtime *Runtime, listenerIdentity types.Identity, routes []gateway.ExposedHTTPRoute) (http.Handler, error) {
	handler, err := gateway.ComposeHTTPRoutes(routes, spec.HTTP.Payment)
	if err == nil && spec.HTTP.Auth != nil {
		auth := *spec.HTTP.Auth
		auth.PublicHosts = runtime.publicHosts
		handler, err = appauth.New(handler, listenerIdentity, auth)
	}
	if err == nil && len(spec.HTTP.StripRequestHeaders) > 0 {
		handler, err = gateway.NewStripRequestHeaders(handler, spec.HTTP.StripRequestHeaders)
	}
	if err != nil {
		_ = runtime.Exposure.Close()
		return nil, err
	}
	return handler, nil
}

func resolveStartRuntimeIdentityRelays(spec Spec) (types.Identity, []string, error) {
	listenerIdentity, err := identity.LoadOrCreate(spec.Identity.Name, spec.Identity.Path, spec.Identity.JSON)
	if err != nil {
		return types.Identity{}, nil, fmt.Errorf("resolve identity: %w", err)
	}
	explicitRelayURLs, err := utils.NormalizeRelayURLs(spec.Relays.URLs...)
	if err != nil {
		return types.Identity{}, nil, err
	}
	return listenerIdentity, explicitRelayURLs, nil
}

func establishStartRuntime(ctx context.Context, spec Spec) (*Runtime, types.Identity, []gateway.ExposedHTTPRoute, error) {
	if err := spec.Validate(); err != nil {
		return nil, types.Identity{}, nil, err
	}
	routes, err := buildExposedRoutes(spec)
	if err != nil {
		return nil, types.Identity{}, nil, err
	}
	listenerIdentity, explicitRelayURLs, err := resolveStartRuntimeIdentityRelays(spec)
	if err != nil {
		return nil, types.Identity{}, nil, err
	}
	runtime, err := exposeTunnelRuntime(ctx, spec, listenerIdentity, explicitRelayURLs)
	if err != nil {
		return nil, types.Identity{}, nil, err
	}
	return runtime, listenerIdentity, routes, nil
}

func monitorStartRuntimeAuth(ctx context.Context, spec Spec, runtime *Runtime) {
	if spec.HTTP.Auth == nil {
		return
	}
	go func() {
		err := appauth.Check(ctx, *spec.HTTP.Auth)
		if ctx.Err() != nil {
			return
		}
		runtime.authProvider.Store(&authProviderCheck{err: err})
		if err != nil {
			log.Warn().Err(err).Str("address", runtime.Identity.Address).Msg("application auth provider is not usable; visitors cannot sign in until it is")
		}
	}()
}

func Start(ctx context.Context, spec Spec) (*Runtime, error) {
	runtime, listenerIdentity, routes, err := establishStartRuntime(ctx, spec)
	if err != nil {
		return nil, err
	}
	if spec.HTTP == nil {
		return runtime, nil
	}
	if runtime.handler, err = composeTunnelHandler(spec, runtime, listenerIdentity, routes); err != nil {
		return nil, err
	}
	monitorStartRuntimeAuth(ctx, spec, runtime)
	return runtime, nil
}

func (runtime *Runtime) publicHosts() []appauth.PublicHost {
	var hosts []appauth.PublicHost
	for _, relay := range runtime.Exposure.Relays() {
		hosts = append(hosts, appauth.PublicHost{URL: relay.PublicURL}, appauth.PublicHost{URL: relay.LegacyURL}, appauth.PublicHost{URL: relay.AliasURL, Since: relay.AliasSince})
	}
	return hosts
}

// AuthProviderCheck reports whether the startup check of the application auth
// provider has finished and, if it failed, why the provider is not usable.
func (runtime *Runtime) AuthProviderCheck() (checked bool, err error) {
	if check := runtime.authProvider.Load(); check != nil {
		return true, check.err
	}
	return false, nil
}

func (runtime *Runtime) Run(ctx context.Context) error {
	if runtime.handler != nil {
		return sdk.RunHTTP(ctx, runtime.Exposure, runtime.handler, "")
	}
	return sdk.ProxyWithConfig(ctx, runtime.Exposure, sdk.ProxyConfig{
		TCPTarget: runtime.target,
		UDPTarget: runtime.udpTarget,
	})
}

func (runtime *Runtime) Close() error {
	return runtime.Exposure.Close()
}
