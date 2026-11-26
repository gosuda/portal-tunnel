package gateway

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/gosuda/x402-facilitator/resource/paywall"

	"github.com/gosuda/portal-tunnel/v2/sdk"
	"github.com/gosuda/portal-tunnel/v2/sdk/appauth"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

var (
	errStripRequestHeaderNameRequired       = errors.New("strip request header name is required")
	errHostCannotStrippedGoStoresIt         = errors.New(`"Host" cannot be stripped: Go stores it in Request.Host, not Header`)
	errXForwardedProtoCannotStrippedRunhttp = errors.New(`"X-Forwarded-Proto" cannot be stripped: RunHTTP always overwrites it with the trusted https value before this middleware runs`)
	errLeastOneHTTPRouteRequired            = errors.New("at least one http route is required")
	errX402PaymentMethodIsRequired          = errors.New("x402 payment method is required")
)

// X402Config is the payment component of a tunnel config, carried under its
// x402_* keys. The facilitator token is a secret: never returned by any API.
type X402Config struct {
	Testnet          bool     `json:"x402_testnet,omitempty" toml:"x402_testnet,omitempty"`
	Network          string   `json:"x402_network,omitempty" toml:"x402_network,omitempty"`
	Asset            string   `json:"x402_asset,omitempty" toml:"x402_asset,omitempty"`
	PayTo            string   `json:"x402_pay_to,omitempty" toml:"x402_pay_to,omitempty"`
	Endpoints        []string `json:"x402_endpoints,omitempty" toml:"x402_endpoints,omitempty"`
	FacilitatorToken string   `json:"-" toml:"x402_facilitator_token,omitempty"`
	// Options are network-specific settings passed through to the
	// facilitator's paywall unchanged, such as nano_claims_file. The
	// paywall rejects a key the selected network does not understand.
	Options map[string]string `json:"x402_options,omitempty" toml:"x402_options,omitempty"`
}

// Normalize returns c in the form a config stores: values without surrounding
// spaces, the network in lower case, and no empty endpoint.
func (c X402Config) Normalize() X402Config {
	c.Network = strings.ToLower(strings.TrimSpace(c.Network))
	c.Asset = strings.TrimSpace(c.Asset)
	c.PayTo = strings.TrimSpace(c.PayTo)
	c.Endpoints = utils.CompactStrings(c.Endpoints)
	c.FacilitatorToken = strings.TrimSpace(c.FacilitatorToken)
	var options map[string]string
	for key, value := range c.Options {
		if key = strings.TrimSpace(key); key != "" {
			if options == nil {
				options = make(map[string]string, len(c.Options))
			}
			options[key] = strings.TrimSpace(value)
		}
	}
	c.Options = options
	return c
}

// ParseX402Option parses one KEY=VALUE x402 option.
func ParseX402Option(raw string) (string, string, error) {
	key, value, ok := strings.Cut(raw, "=")
	if key = strings.TrimSpace(key); !ok || key == "" {
		return "", "", fmt.Errorf("x402 option %q must be KEY=VALUE", raw)
	}
	return key, strings.TrimSpace(value), nil
}

// X402PreparePath and X402ClientPath are the payment helper endpoints the
// gateway serves when at least one route is paid.
const (
	X402PreparePath = paywall.PreparePath
	X402ClientPath  = paywall.ClientPath
)

// ExposedHTTPRoute is one route exposed through the tunnel HTTP gateway,
// carrying the optional x402 payment metadata that gates it.
type ExposedHTTPRoute struct {
	// Prefix is the public request path prefix, such as "/api" or "/".
	Prefix string
	// Upstream is the target HTTP URL, or a loopback host:port shorthand.
	// Leave empty when StaticRoot is set.
	Upstream string
	// StaticRoot serves a local directory as a static SPA when set.
	StaticRoot string
	// StaticIndex is the SPA entry file for the static route.
	StaticIndex string
	// Methods limits payment enforcement to these HTTP methods.
	// Empty means every method is paid.
	Methods []string
	// Amount enables x402 payment for this route. It is a human amount in
	// the network's settlement asset, such as "0.01"; empty means the
	// route is unpaid.
	Amount string
}

func normalizeComposeHTTPRoutesPrefix(raw string) string {
	prefix := strings.TrimSpace(raw)
	if prefix != "" && strings.HasPrefix(prefix, "/") {
		prefix = utils.NormalizeURLPath(prefix)
	}
	return prefix
}

// ComposeHTTPRoutes builds the payment-agnostic sdk router and wraps it with
// the facilitator's chain-agnostic paywall, which charges only the routes
// carrying an x402 amount. The caller owns the returned gateway and must
// Close it to release the payment runtime.
func ComposeHTTPRoutes(routes []ExposedHTTPRoute, contract X402Config) (*HTTPGateway, error) {
	if len(routes) == 0 {
		return nil, errLeastOneHTTPRouteRequired
	}
	sdkConfigs := make([]sdk.HTTPRouteConfig, 0, len(routes))
	paid := make([]paywall.Route, 0, len(routes))
	for _, route := range routes {
		prefix := normalizeComposeHTTPRoutesPrefix(route.Prefix)
		sdkConfigs = append(sdkConfigs, sdk.HTTPRouteConfig{
			Prefix:      prefix,
			Upstream:    route.Upstream,
			StaticRoot:  route.StaticRoot,
			StaticIndex: route.StaticIndex,
		})
		paid = append(paid, paywall.Route{Prefix: prefix, Amount: route.Amount, Methods: route.Methods})
	}
	routed, err := sdk.NewHTTPRoutes(sdkConfigs)
	if err != nil {
		return nil, err
	}
	pw, err := paywall.New(contract.paywallConfig(), paid)
	if err != nil {
		return nil, fmt.Errorf("x402 payment: %w", err)
	}
	return &HTTPGateway{payment: pw, routed: routed, handler: pw.Wrap(routed)}, nil
}

// HTTPGateway is the routed tunnel handler with its payment runtime.
type HTTPGateway struct {
	payment   *paywall.Paywall
	routed    *sdk.HTTPRoutes
	inspector *httpInspector
	handler   http.Handler
}

func (g *HTTPGateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	utils.DelHeaderSpellings(r.Header, types.HeaderAccessCredential)
	if _, ok := appauth.PrincipalFromContext(r.Context()); !ok {
		utils.DelHeaderSpellings(r.Header, types.PortalIdentityHeaders...)
	}
	g.handler.ServeHTTP(w, r)
}

// Close releases the payment runtime. It is safe on a nil gateway.
func (g *HTTPGateway) Close() error {
	if g == nil {
		return nil
	}
	return errors.Join(g.inspector.Close(), g.payment.Close())
}
