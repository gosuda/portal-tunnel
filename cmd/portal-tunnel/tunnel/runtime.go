package tunnel

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"

	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/gateway"
	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/sdk"
	"github.com/gosuda/portal-tunnel/v2/sdk/appauth"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

// Runtime owns the assembled Portal tunnel and its low-level exposure.
type Runtime struct {
	Identity     types.Identity
	Exposure     *sdk.Exposure
	InspectorURL string
	gateway      *gateway.HTTPGateway
	handler      http.Handler
	target       string
	udpTarget    string
	authProvider atomic.Pointer[authProviderCheck]
}

type authProviderCheck struct{ err error }

func buildExposedRoutes(resolved Config) ([]gateway.ExposedHTTPRoute, error) {
	routes := make([]gateway.ExposedHTTPRoute, 0)
	if !resolved.usesHTTP() {
		return routes, nil
	}
	if serve := strings.TrimSpace(resolved.Serve); serve != "" {
		root, index, err := utils.ResolveStaticSite(serve)
		if err != nil {
			return nil, fmt.Errorf("resolve static site %q: %w", serve, err)
		}
		routes = append(routes, gateway.ExposedHTTPRoute{Prefix: "/", StaticRoot: root, StaticIndex: index})
	}
	for _, route := range resolved.HTTPRoutes {
		routes = append(routes, gateway.ExposedHTTPRoute{
			Prefix: route.Prefix, Upstream: route.Upstream,
			Methods: append([]string(nil), route.Methods...), Amount: route.Amount,
		})
	}
	if len(routes) == 0 {
		routes = append(routes, gateway.ExposedHTTPRoute{Prefix: "/", Upstream: resolved.TargetAddr})
	}
	return routes, nil
}

func buildExposureOptions(resolved Config) []sdk.Option {
	opts := []sdk.Option{
		sdk.WithMITMProtection(resolved.BanMITM != nil && *resolved.BanMITM),
		sdk.WithTLSCertificate(resolved.TLSCert, resolved.TLSKey),
		sdk.WithMetadata(resolved.LeaseMetadata),
	}
	if resolved.Replica {
		opts = append(opts, sdk.WithReplicas())
	}
	if resolved.TLSAuto {
		opts = append(opts, sdk.WithAutomaticTLS(resolved.TLSStateDir, resolved.TLSRequireLocal))
	}
	if monitor := resolved.certificateMonitor(); monitor != nil {
		opts = append(opts, sdk.WithCertificateMonitoring(monitor.StateDir, monitor.BaselineFile, monitor.DNSResolver))
	}
	if resolved.UDPEnabled {
		opts = append(opts, sdk.WithUDP())
	}
	if resolved.TCPEnabled {
		opts = append(opts, sdk.WithTCP())
	}
	if resolved.Overlay {
		opts = append(opts, sdk.WithOverlay())
	}
	if resolved.DiscoveryEnabled() {
		opts = append(opts, sdk.WithDiscovery(resolved.RelayLimit()))
	}
	if resolved.Cache != nil {
		opts = append(opts, sdk.WithStaticRelayCache(resolved.Serve, resolved.Cache.TTL))
	}
	return opts
}

func composeTunnelHandler(resolved Config, runtime *Runtime, listenerIdentity types.Identity, routes []gateway.ExposedHTTPRoute) (http.Handler, error) {
	var handler http.Handler
	var err error
	if runtime.gateway, err = gateway.ComposeHTTPRoutes(routes, resolved.X402Config); err == nil {
		handler = runtime.gateway
	}
	if err == nil && resolved.Inspect {
		runtime.InspectorURL, err = runtime.gateway.StartInspector(resolved.InspectBodies)
		if err == nil {
			log.Info().Str("inspector_url", runtime.InspectorURL).Bool("capture_bodies", resolved.InspectBodies).
				Msg("local HTTP inspector listening; captures are in memory; bodies may contain secrets when enabled")
		}
	}
	if err == nil && !resolved.IsZero() {
		auth := resolved.AuthConfig
		auth.PublicHosts = runtime.publicHosts
		handler, err = appauth.New(handler, listenerIdentity, auth)
	}
	if err == nil && len(resolved.StripRequestHeaders) > 0 {
		handler, err = gateway.NewStripRequestHeaders(handler, resolved.StripRequestHeaders)
	}
	if err != nil {
		_ = runtime.Close()
		return nil, err
	}
	return handler, nil
}

// Start resolves an execution copy and owns its exposure and HTTP gateway.
func Start(ctx context.Context, config Config) (*Runtime, error) {
	config, err := config.Resolve()
	if err != nil {
		return nil, err
	}
	routes, err := buildExposedRoutes(config)
	if err != nil {
		return nil, err
	}
	listenerIdentity, err := identity.LoadOrCreate(config.Name, config.IdentityPath, config.IdentityJSON)
	if err != nil {
		return nil, fmt.Errorf("resolve identity: %w", err)
	}
	exposure, err := sdk.Expose(ctx, listenerIdentity, config.RelayURLs, buildExposureOptions(config)...)
	if err != nil {
		return nil, fmt.Errorf("failed to start relays: %w", err)
	}
	runtime := &Runtime{Identity: listenerIdentity, Exposure: exposure, target: config.TargetAddr}
	if config.UDPEnabled {
		runtime.udpTarget = cmp.Or(config.UDPAddr, config.TargetAddr)
	}
	if !config.usesHTTP() {
		return runtime, nil
	}
	if runtime.handler, err = composeTunnelHandler(config, runtime, listenerIdentity, routes); err != nil {
		return nil, err
	}
	if !config.IsZero() {
		go func() {
			err := appauth.Check(ctx, config.AuthConfig)
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
		if relay.PublicURL != relay.AliasURL {
			hosts = append(hosts, appauth.PublicHost{URL: relay.PublicURL})
		}
		hosts = append(hosts, appauth.PublicHost{URL: relay.AliasURL, Epoch: relay.AliasEpoch, Since: relay.AliasSince})
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

// Close stops the exposure and releases the gateway's payment runtime, such
// as RPC connections and claim logs.
func (runtime *Runtime) Close() error {
	return errors.Join(runtime.Exposure.Close(), runtime.gateway.Close())
}
