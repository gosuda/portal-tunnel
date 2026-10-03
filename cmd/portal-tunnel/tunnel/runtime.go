package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/gateway"
	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/sdk"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

// Spec is Portal's canonical description of one tunnel. Frontends own parsing
// and serialization; runtime assembly starts at this boundary.
type Spec struct {
	Identity  IdentitySpec
	Relays    RelaySpec
	Metadata  types.LeaseMetadata
	Transport TransportSpec
	HTTP      *HTTPConfig
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
	Routes              []HTTPRoute                    `koanf:"routes"`
	Serve               string                         `koanf:"serve"`
	Auth                *gateway.ApplicationAuthConfig `koanf:"auth"`
	Payment             gateway.X402Payment            `koanf:"payment"`
	Cache               *CacheConfig                   `koanf:"cache"`
	StripRequestHeaders []string                       `koanf:"strip_request_headers"`
}

type HTTPRoute struct {
	Prefix   string   `json:"prefix" koanf:"prefix"`
	Upstream string   `json:"upstream" koanf:"upstream"`
	Methods  []string `json:"methods,omitempty" koanf:"methods"`
	Amount   string   `json:"amount,omitempty" koanf:"amount"`
}

type CacheConfig struct {
	TTL time.Duration
}

func (spec Spec) Validate() error {
	target := strings.TrimSpace(spec.Transport.Target)
	if spec.HTTP == nil {
		if target == "" {
			return errors.New("tunnel target is required")
		}
		return nil
	}

	httpConfig := spec.HTTP
	if spec.Transport.TCP || spec.Transport.UDP != nil {
		return errors.New("HTTP tunnel cannot be combined with TCP or UDP")
	}
	if strings.TrimSpace(httpConfig.Serve) != "" {
		if target != "" || len(httpConfig.Routes) > 0 {
			return errors.New("static serving cannot be combined with a target or HTTP routes")
		}
	} else if target == "" && len(httpConfig.Routes) == 0 {
		return errors.New("HTTP tunnel requires a target, route, or static site")
	}
	if target != "" && len(httpConfig.Routes) > 0 {
		return errors.New("HTTP tunnel cannot combine a target and routes")
	}
	if httpConfig.Cache != nil {
		if strings.TrimSpace(httpConfig.Serve) == "" {
			return errors.New("relay cache requires a static site")
		}
		if spec.Relays.BanMITM {
			return errors.New("relay cache permits TLS termination and cannot be combined with MITM protection")
		}
		if httpConfig.Auth != nil {
			return errors.New("application auth cannot be combined with relay cache")
		}
	}
	for _, route := range httpConfig.Routes {
		prefix := strings.TrimSpace(route.Prefix)
		if prefix == "" || strings.TrimSpace(route.Upstream) == "" {
			return errors.New("HTTP routes require a prefix and upstream")
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
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(httpConfig.Payment.Network)), "casper:") && strings.TrimSpace(httpConfig.Payment.Asset) == "" {
		return errors.New("casper payments require an asset")
	}
	if auth := httpConfig.Auth; auth != nil {
		provider, err := gateway.NormalizeApplicationAuthProvider(auth.Provider)
		if err != nil {
			return err
		}
		if provider == gateway.ApplicationAuthProviderCredential && len(auth.AllowedWallets) > 0 {
			return errors.New("application auth wallet allowlist requires the siwe provider")
		}
	}
	return nil
}

// Runtime owns the assembled Portal tunnel and its low-level exposure.
type Runtime struct {
	Identity  types.Identity
	Exposure  *sdk.Exposure
	handler   http.Handler
	target    string
	udpTarget string
}

func Start(ctx context.Context, spec Spec) (*Runtime, error) {
	if err := spec.Validate(); err != nil {
		return nil, err
	}

	routes := make([]gateway.ExposedHTTPRoute, 0)
	if spec.HTTP != nil {
		stripHeaders := append([]string(nil), spec.HTTP.StripRequestHeaders...)
		if serve := strings.TrimSpace(spec.HTTP.Serve); serve != "" {
			root, index, err := utils.ResolveStaticSite(serve)
			if err != nil {
				return nil, fmt.Errorf("resolve static site %q: %w", serve, err)
			}
			routes = append(routes, gateway.ExposedHTTPRoute{Prefix: "/", StaticRoot: root, StaticIndex: index, StripRequestHeaders: stripHeaders})
		}
		for _, route := range spec.HTTP.Routes {
			routes = append(routes, gateway.ExposedHTTPRoute{
				Prefix: route.Prefix, Upstream: route.Upstream,
				Methods: append([]string(nil), route.Methods...), Amount: route.Amount,
				StripRequestHeaders: append([]string(nil), stripHeaders...),
			})
		}
		if len(routes) == 0 {
			routes = append(routes, gateway.ExposedHTTPRoute{Prefix: "/", Upstream: spec.Transport.Target, StripRequestHeaders: stripHeaders})
		}
	}

	listenerIdentity, err := identity.LoadOrCreate(spec.Identity.Name, spec.Transport.Target, spec.Identity.Path, spec.Identity.JSON)
	if err != nil {
		return nil, fmt.Errorf("resolve identity: %w", err)
	}
	explicitRelayURLs, err := utils.NormalizeRelayURLs(spec.Relays.URLs...)
	if err != nil {
		return nil, err
	}
	opts := []sdk.Option{
		sdk.WithMITMProtection(spec.Relays.BanMITM),
		sdk.WithMetadata(spec.Metadata),
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
		runtime.udpTarget = utils.StringOrDefault(spec.Transport.UDP.Target, spec.Transport.Target)
	}
	if spec.HTTP == nil {
		return runtime, nil
	}

	handler, err := gateway.ComposeHTTPRoutes(routes, spec.HTTP.Payment)
	if err == nil && spec.HTTP.Auth != nil {
		handler, err = gateway.NewApplicationAuth(handler, listenerIdentity, *spec.HTTP.Auth)
	}
	if err != nil {
		_ = exposure.Close()
		return nil, err
	}
	runtime.handler = handler
	return runtime, nil
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
