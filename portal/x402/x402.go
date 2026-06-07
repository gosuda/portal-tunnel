package x402

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	facilitatorapi "github.com/gosuda/x402-facilitator/api"
	facilitatorcore "github.com/gosuda/x402-facilitator/facilitator"
	suischeme "github.com/gosuda/x402-facilitator/scheme/sui"
	facilitatortypes "github.com/gosuda/x402-facilitator/types"
	foundationx402 "github.com/x402-foundation/x402/go"
	x402http "github.com/x402-foundation/x402/go/http"
	x402nethttp "github.com/x402-foundation/x402/go/http/nethttp"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/types"
)

const (
	defaultPaymentTimeout   = 30 * time.Second
	defaultRouteDescription = "Portal protected route"
)

func NetworkDisplayName(network string) string {
	return suischeme.GetNetworkName(strings.TrimSpace(strings.ToLower(network)))
}

func PublicNodeRPCURL(network string) string {
	urls := suischeme.GetDefaultURLs(strings.TrimSpace(strings.ToLower(network)))
	if len(urls) == 0 {
		return ""
	}
	return urls[0]
}

func networkNamespace(network string) string {
	network = strings.TrimSpace(strings.ToLower(network))
	namespace, _, ok := strings.Cut(network, ":")
	if !ok {
		return ""
	}
	return namespace
}

func isTestnetNetwork(network string) bool {
	networkID := suischeme.GetNetworkID(strings.TrimSpace(strings.ToLower(network)))
	return networkID != "" && networkID != "mainnet"
}

type FacilitatorConfig struct {
	Network  string
	RPCURL   string
	Identity types.Identity
}

func MountFacilitator(mux *http.ServeMux, cfg FacilitatorConfig) error {
	if mux == nil {
		return errors.New("payment facilitator requires an api mux")
	}
	network := strings.TrimSpace(strings.ToLower(cfg.Network))
	if network == "" {
		network = types.X402DefaultNetwork
	}
	rpcURL := strings.TrimSpace(cfg.RPCURL)
	if rpcURL == "" {
		rpcURL = PublicNodeRPCURL(network)
	}
	if networkNamespace(network) != "sui" {
		return fmt.Errorf("unsupported payment rail %q", network)
	}
	facilitator, err := facilitatorcore.NewFacilitator(facilitatortypes.Exact, network, rpcURL, "")
	if err != nil {
		return fmt.Errorf("create payment facilitator: %w", err)
	}
	mux.Handle(types.PathX402Facilitator+"/", http.StripPrefix(types.PathX402Facilitator, facilitatorapi.NewServer(facilitator)))
	return nil
}

type HTTPRequestContext = x402http.HTTPRequestContext

type PriceResolver func(context.Context, HTTPRequestContext) (string, error)

type HTTPRouteHandlerConfig struct {
	Prefix         string
	Next           http.Handler
	X402           types.X402Config
	TunnelIdentity types.Identity
	Metadata       types.LeaseMetadata
	PriceResolver  PriceResolver
}

func NewHTTPRouteHandler(cfg HTTPRouteHandlerConfig) (http.Handler, error) {
	next := cfg.Next
	if next == nil {
		next = http.NotFoundHandler()
	}
	prefix := strings.TrimSpace(cfg.Prefix)
	if prefix == "" {
		prefix = "/"
	}
	network := strings.TrimSpace(strings.ToLower(cfg.X402.Network))
	if network == "" {
		network = types.X402DefaultNetwork
	}
	facilitatorURL := strings.TrimSpace(cfg.X402.FacilitatorURL)
	if facilitatorURL == "" {
		return nil, fmt.Errorf("http route %q payment facilitator_url is required", prefix)
	}
	priceValue := strings.TrimSpace(cfg.X402.Price)
	if priceValue == "" && cfg.PriceResolver == nil {
		return nil, fmt.Errorf("http route %q payment price is required", prefix)
	}
	var price any = foundationx402.Price(priceValue)
	if cfg.PriceResolver != nil {
		price = x402http.DynamicPriceFunc(func(ctx context.Context, req x402http.HTTPRequestContext) (foundationx402.Price, error) {
			resolvedPrice, err := cfg.PriceResolver(ctx, req)
			if err != nil {
				return "", err
			}
			resolvedPrice = strings.TrimSpace(resolvedPrice)
			if resolvedPrice == "" {
				return "", fmt.Errorf("http route %q payment dynamic price is empty", prefix)
			}
			return foundationx402.Price(resolvedPrice), nil
		})
	}
	payTo := strings.TrimSpace(cfg.X402.PayTo)
	if payTo == "" || strings.EqualFold(payTo, types.X402PayToIdentity) {
		payTo = strings.TrimSpace(cfg.TunnelIdentity.SuiAddress)
		if payTo == "" {
			payTo = strings.TrimSpace(cfg.TunnelIdentity.Address)
		}
		if payTo == "" {
			return nil, fmt.Errorf("http route %q payment identity requires a Sui Ed25519 receive address or an explicit Sui receive address", prefix)
		}
	}
	if payTo == "" {
		return nil, fmt.Errorf("http route %q payment receive address is required", prefix)
	}
	var schemeServer foundationx402.SchemeNetworkServer
	var err error
	switch networkNamespace(network) {
	case "sui":
		payTo, err = identity.NormalizeSuiAddress(payTo)
		if err != nil {
			return nil, fmt.Errorf("http route %q Sui receive address: %w", prefix, err)
		}
		schemeServer, err = newSuiExactServer(network)
		if err != nil {
			return nil, fmt.Errorf("http route %q Sui payment rail: %w", prefix, err)
		}
	default:
		return nil, fmt.Errorf("http route %q unsupported payment rail %q", prefix, network)
	}
	if cfg.X402.PaymentTimeoutSecs < 0 {
		return nil, errors.New("payment_timeout_seconds cannot be negative")
	}
	if cfg.X402.MaxTimeoutSeconds < 0 {
		return nil, errors.New("max_timeout_seconds cannot be negative")
	}

	timeout := defaultPaymentTimeout
	if cfg.X402.PaymentTimeoutSecs > 0 {
		timeout = time.Duration(cfg.X402.PaymentTimeoutSecs) * time.Second
	}
	resource := strings.TrimSpace(cfg.X402.Resource)
	description := strings.TrimSpace(cfg.Metadata.Description)
	if description == "" {
		description = defaultRouteDescription
	}
	middleware := x402nethttp.X402Payment(x402nethttp.Config{
		Routes: x402http.RoutesConfig{
			"*": x402http.RouteConfig{
				Accepts: []x402http.PaymentOption{
					{
						Scheme:            types.X402SchemeExact,
						PayTo:             payTo,
						Price:             price,
						Network:           foundationx402.Network(network),
						MaxTimeoutSeconds: cfg.X402.MaxTimeoutSeconds,
					},
				},
				Resource:    resource,
				Description: description,
				MimeType:    strings.TrimSpace(cfg.X402.MimeType),
			},
		},
		Facilitator: x402http.NewHTTPFacilitatorClient(&x402http.FacilitatorConfig{
			URL: facilitatorURL,
		}),
		Schemes: []x402nethttp.SchemeConfig{
			{
				Network: foundationx402.Network(network),
				Server:  schemeServer,
			},
		},
		PaywallConfig: &x402http.PaywallConfig{
			AppName: strings.TrimSpace(cfg.TunnelIdentity.Name),
			AppLogo: strings.TrimSpace(cfg.Metadata.Thumbnail),
			Testnet: isTestnetNetwork(network),
		},
		SyncFacilitatorOnStart: true,
		Timeout:                timeout,
	})
	return middleware(next), nil
}
