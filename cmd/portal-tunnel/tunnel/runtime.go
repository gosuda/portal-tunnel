package tunnel

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/gateway"
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
	TLSAuto         bool
	TLSStateDir     string
	TLSRequireLocal bool
	TLSCert         string
	TLSKey          string
	Identity        IdentitySpec
	Relays          RelaySpec
	Metadata        types.LeaseMetadata
	Transport       TransportSpec
	HTTP            *HTTPConfig
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

func (spec Spec) Validate() error {
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
	if httpConfig.Cache != nil {
		if strings.TrimSpace(httpConfig.Serve) == "" {
			return errRelayCacheRequiresStaticSite
		}
		if spec.Relays.BanMITM {
			return errRelayCachePermitsTLSTerminationAnd
		}
		if httpConfig.Auth != nil {
			return errApplicationAuthCannotCombinedRelayCache
		}
	}
	for _, route := range httpConfig.Routes {
		prefix := strings.TrimSpace(route.Prefix)
		if prefix == "" || strings.TrimSpace(route.Upstream) == "" {
			return errHTTPRoutesRequirePrefixAndUpstream
		}
		if !strings.HasPrefix(prefix, "/") {
			return fmt.Errorf("HTTP route %q prefix must start with /", prefix)
		}
		if strings.TrimSpace(route.Amount) != "" && strings.TrimSpace(httpConfig.Payment.PayTo) == "" {
			return fmt.Errorf("HTTP route %q payment amount requires a payment recipient", prefix)
		}
		if strings.TrimSpace(route.Amount) == "" && len(route.Methods) > 0 {
			return fmt.Errorf("HTTP route %q methods require a payment amount", prefix)
		}
	}
	if len(httpConfig.StripRequestHeaders) > 0 {
		if strings.TrimSpace(httpConfig.Serve) != "" {
			return errStripRequestHeadersCannotCombinedStatic
		}
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
	}
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(httpConfig.Payment.Network)), "casper:") && strings.TrimSpace(httpConfig.Payment.Asset) == "" {
		return errCasperPaymentsRequireAnAsset
	}
	if auth := httpConfig.Auth; auth != nil {
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

func Start(ctx context.Context, spec Spec) (*Runtime, error) {
	if err := spec.Validate(); err != nil {
		return nil, err
	}

	routes := make([]gateway.ExposedHTTPRoute, 0)
	if spec.HTTP != nil {
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
	}

	listenerIdentity, err := identity.LoadOrCreate(spec.Identity.Name, spec.Identity.Path, spec.Identity.JSON)
	if err != nil {
		return nil, fmt.Errorf("resolve identity: %w", err)
	}
	explicitRelayURLs, err := utils.NormalizeRelayURLs(spec.Relays.URLs...)
	if err != nil {
		return nil, err
	}
	opts := []sdk.Option{
		sdk.WithMITMProtection(spec.Relays.BanMITM),
		sdk.WithTLSCertificate(spec.TLSCert, spec.TLSKey),
		sdk.WithMetadata(spec.Metadata),
	}
	if spec.TLSAuto {
		opts = append(opts, sdk.WithAutomaticTLS(spec.TLSStateDir, spec.TLSRequireLocal))
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

	exposure, err := sdk.Expose(ctx, listenerIdentity, explicitRelayURLs, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to start relays: %w", err)
	}
	runtime := &Runtime{Identity: listenerIdentity, Exposure: exposure, target: spec.Transport.Target}
	if spec.Transport.UDP != nil {
		runtime.udpTarget = cmp.Or(spec.Transport.UDP.Target, spec.Transport.Target)
	}
	if spec.HTTP == nil {
		return runtime, nil
	}

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
		_ = exposure.Close()
		return nil, err
	}
	runtime.handler = handler
	if spec.HTTP.Auth != nil {
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
	return runtime, nil
}

func (runtime *Runtime) publicHosts() []appauth.PublicHost {
	var hosts []appauth.PublicHost
	for _, relay := range runtime.Exposure.Relays() {
		hosts = append(hosts, appauth.PublicHost{URL: relay.PublicURL}, appauth.PublicHost{URL: relay.AliasURL, Since: relay.AliasSince})
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
