package tunnel

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

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
	// Output selects the lifecycle output format: "" or "text" keeps the
	// human-readable log path; "jsonl" emits machine-readable relay
	// lifecycle records. Frontends own parsing; runtime assembly starts
	// at this boundary.
	Output string
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
	Auth    *gateway.ApplicationAuthConfig
	Payment gateway.X402Payment
	Cache   *CacheConfig
	// StripRequestHeaders lists client request headers removed before
	// forwarding to every routed HTTP upstream. It requires at least one
	// upstream route: static-only exposures forward nothing.
	StripRequestHeaders []string
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
	switch spec.Output {
	case "", "text", "jsonl":
	default:
		return fmt.Errorf("output %q: supported values are text and jsonl", spec.Output)
	}
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
	if len(httpConfig.StripRequestHeaders) > 0 {
		if strings.TrimSpace(httpConfig.Serve) != "" {
			return errors.New("strip request headers cannot be combined with static serving (--serve); static sites do not proxy request headers")
		}
		hasHTTPUpstream := len(httpConfig.Routes) > 0 || strings.TrimSpace(target) != "" || httpConfig.Auth != nil
		if !hasHTTPUpstream {
			return errors.New("strip request headers require an HTTP upstream route or target")
		}
		for _, h := range httpConfig.StripRequestHeaders {
			if strings.EqualFold(strings.TrimSpace(h), "Host") {
				return errors.New(`strip request header "Host" is not supported: Go stores it in Request.Host, not Header`)
			}
			if strings.EqualFold(strings.TrimSpace(h), "X-Forwarded-Proto") {
				return errors.New(`strip request header "X-Forwarded-Proto" is not supported: RunHTTP always overwrites it with the trusted https value`)
			}
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
	output    string
}

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
	runtime := &Runtime{Identity: listenerIdentity, Exposure: exposure, target: spec.Transport.Target, output: spec.Output}
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
	if err == nil && len(spec.HTTP.StripRequestHeaders) > 0 {
		handler, err = gateway.NewStripRequestHeaders(handler, spec.HTTP.StripRequestHeaders)
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

// relayLifecycleRecord is one machine-readable relay lifecycle record
// emitted in --output jsonl mode. It projects the SDK RelayStatus snapshot
// as-is; the SDK Exposure remains the only owner of relay state.
type relayLifecycleRecord struct {
	Event      string `json:"event"`
	RelayURL   string `json:"relay_url"`
	State      string `json:"state"`
	Failure    string `json:"failure,omitempty"`
	PublicURL  string `json:"public_url,omitempty"`
	AliasURL   string `json:"alias_url,omitempty"`
	UDPAddr    string `json:"udp_addr,omitempty"`
	TCPAddr    string `json:"tcp_addr,omitempty"`
	Version    string `json:"version,omitempty"`
	Deselected bool   `json:"deselected"`
	Error      string `json:"error,omitempty"`
}

// relayLifecycleRecordFrom projects one SDK RelayStatus snapshot onto the
// machine-readable record. AliasURL is emitted only while the relay is
// ready, and Error is bounded to one line so records stay parseable; no
// secrets are part of RelayStatus.
func relayLifecycleRecordFrom(status sdk.RelayStatus) relayLifecycleRecord {
	record := relayLifecycleRecord{
		Event:      "relay_status",
		RelayURL:   status.RelayURL,
		State:      string(cmp.Or(status.State, sdk.RelayConnecting)),
		Failure:    string(status.Failure),
		PublicURL:  status.PublicURL,
		UDPAddr:    status.UDPAddr,
		TCPAddr:    status.TCPAddr,
		Version:    status.Version,
		Deselected: status.Deselected,
	}
	if status.State == sdk.RelayReady && !status.Deselected {
		record.AliasURL = status.AliasURL
	}
	if status.Err != nil {
		record.Error = strings.ReplaceAll(status.Err.Error(), "\n", " ")
	}
	return record
}

// StartRelayLifecycleWriter projects relay lifecycle changes onto w as
// JSONL when spec.Output is jsonl: one relay_status record per update,
// sourced from the SDK's authoritative Updates channel with a Relays()
// snapshot for already-known state at start. The channel is a bounded,
// coalescing notification, not a lossless event log; consumers reconcile
// against the snapshot by re-deriving it on restart. Text mode (default)
// starts nothing.
func (runtime *Runtime) StartRelayLifecycleWriter(ctx context.Context, w io.Writer) {
	if runtime == nil || runtime.Exposure == nil || runtime.output != "jsonl" || w == nil {
		return
	}
	go func() {
		encoder := json.NewEncoder(w)
		writeStatus := func(status sdk.RelayStatus) {
			if err := encoder.Encode(relayLifecycleRecordFrom(status)); err != nil {
				log.Error().Err(err).Msg("relay lifecycle record write failed")
			}
		}
		for _, status := range runtime.Exposure.Relays() {
			writeStatus(status)
		}
		updates := runtime.Exposure.Updates()
		for {
			select {
			case <-ctx.Done():
				return
			case status, ok := <-updates:
				if !ok {
					return
				}
				writeStatus(status)
			}
		}
	}()
}
