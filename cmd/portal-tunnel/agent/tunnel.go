package agent

import (
	"cmp"
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/gateway"
	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/sdk"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

// TunnelRuntime owns an exposure and its local HTTP or stream/datagram handler.
type TunnelRuntime struct {
	*sdk.Exposure
	Identity types.Identity
	handler  http.Handler
	proxy    sdk.ProxyConfig
}

// StartTunnel assembles the same tunnel for foreground and managed callers.
// The caller owns Run and Close, including cancellation and retry policy.
func StartTunnel(ctx context.Context, cfg TunnelConfig) (*TunnelRuntime, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	routes := make([]gateway.ExposedHTTPRoute, 0, len(cfg.HTTPRoutes)+1)
	if serve := strings.TrimSpace(cfg.Serve); serve != "" {
		root, index, err := utils.ResolveStaticSite(serve)
		if err != nil {
			return nil, fmt.Errorf("serve %q: %w", serve, err)
		}
		routes = append(routes, gateway.ExposedHTTPRoute{Prefix: "/", StaticRoot: root, StaticIndex: index})
	}
	for _, route := range cfg.HTTPRoutes {
		routes = append(routes, gateway.ExposedHTTPRoute{
			Prefix: route.Prefix, Upstream: route.Upstream, Methods: route.Methods, Amount: route.Amount,
		})
	}
	auth := strings.TrimSpace(cfg.Auth)
	if auth != "" && len(routes) == 0 {
		routes = append(routes, gateway.ExposedHTTPRoute{Prefix: "/", Upstream: cfg.TargetAddr})
	}
	listenerIdentity, err := identity.LoadOrCreate(
		cfg.Name,
		cfg.TargetAddr,
		cfg.IdentityPath,
		cfg.IdentityJSON,
	)
	if err != nil {
		return nil, fmt.Errorf("resolve identity: %w", err)
	}
	relays, err := utils.NormalizeRelayURLs(cfg.RelayURLs...)
	if err != nil {
		return nil, err
	}
	opts := []sdk.Option{
		sdk.WithMITMProtection(cfg.BanMITM != nil && *cfg.BanMITM),
		sdk.WithMetadata(cfg.metadata()),
	}
	if cfg.UDPEnabled {
		opts = append(opts, sdk.WithUDP())
	}
	if cfg.TCPEnabled {
		opts = append(opts, sdk.WithTCP())
	}
	if cfg.Overlay {
		opts = append(opts, sdk.WithOverlay())
	}
	if cfg.Discovery == nil || *cfg.Discovery {
		opts = append(opts, sdk.WithDiscovery(cfg.MaxActiveRelays))
	}
	if cfg.Cache {
		opts = append(opts, sdk.WithStaticRelayCache(cfg.Serve, cfg.CacheTTL))
	}
	exposure, err := sdk.Expose(ctx, listenerIdentity, relays, opts...)
	if err != nil {
		return nil, err
	}
	runtime := &TunnelRuntime{
		Exposure: exposure,
		Identity: listenerIdentity,
		proxy:    sdk.ProxyConfig{TCPTarget: cfg.TargetAddr},
	}
	if cfg.UDPEnabled {
		runtime.proxy.UDPTarget = utils.StringOrDefault(cfg.UDPAddr, cfg.TargetAddr)
	}
	if len(routes) > 0 {
		runtime.handler, err = gateway.ComposeHTTPRoutes(routes, gateway.X402Payment{
			Testnet: cfg.X402Testnet, Network: cfg.X402Network, Asset: cfg.X402Asset,
			PayTo: cfg.X402PayTo, Endpoints: cfg.X402Endpoints,
			FacilitatorToken: cmp.Or(
				strings.TrimSpace(cfg.X402FacilitatorToken),
				strings.TrimSpace(os.Getenv("CSPR_CLOUD_API_KEY")),
			),
		})
		if err == nil && auth != "" {
			runtime.handler, err = gateway.NewApplicationAuth(runtime.handler, listenerIdentity, gateway.ApplicationAuthConfig{
				Provider: auth, AllowedWallets: cfg.AuthAllowedWallets, IdentityHeaders: cfg.AuthIdentityHeaders,
			})
		}
		if err != nil {
			_ = exposure.Close()
			return nil, err
		}
	}
	return runtime, nil
}

// Run serves the configured application until cancellation or a terminal error.
func (runtime *TunnelRuntime) Run(ctx context.Context) error {
	if runtime.handler != nil {
		return sdk.RunHTTP(ctx, runtime.Exposure, runtime.handler, "")
	}
	return sdk.ProxyWithConfig(ctx, runtime.Exposure, runtime.proxy)
}
