package gateway

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	x402http "github.com/gosuda/x402-facilitator/resource/http"
	nanofacilitator "github.com/gosuda/x402-facilitator/scheme/nano/facilitator"
	suihttp "github.com/gosuda/x402-facilitator/scheme/sui/http"
	facilitatortypes "github.com/gosuda/x402-facilitator/types"

	"github.com/gosuda/portal-tunnel/v2/sdk"
	"github.com/gosuda/portal-tunnel/v2/sdk/appauth"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

var (
	errStripRequestHeaderNameRequired                = errors.New("strip request header name is required")
	errHostCannotStrippedGoStoresIt                  = errors.New(`"Host" cannot be stripped: Go stores it in Request.Host, not Header`)
	errXForwardedProtoCannotStrippedRunhttp          = errors.New(`"X-Forwarded-Proto" cannot be stripped: RunHTTP always overwrites it with the trusted https value before this middleware runs`)
	errLeastOneHTTPRouteRequired                     = errors.New("at least one http route is required")
	errX402UsdcPaymentRequiresSuiPay                 = errors.New("x402 USDC payment requires a Sui pay-to address")
	errX402WcsprPaymentRequiresWcsprCep              = errors.New("x402 wCSPR payment requires the wCSPR CEP-18 contract hash")
	errX402WcsprPaymentRequiresCasperPay             = errors.New("x402 wCSPR payment requires a Casper pay-to address")
	errX402XnoPaymentRequiresChecksummedNano         = errors.New("x402 XNO payment requires a checksummed Nano pay-to address")
	errCsprCloudX402FacilitatorRequiresAuthorization = errors.New("CSPR.cloud x402 facilitator requires an authorization token")
	errX402PaymentMethodIsRequired                   = errors.New("x402 payment method is required")
)

const (
	suiMainnetNetwork = "sui:mainnet"
	suiTestnetNetwork = "sui:testnet"

	defaultMaxTimeoutSeconds = 60
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
	// NanoClaimsFile keeps spent Nano payment blocks spent across restarts:
	// each settled block hash is appended and fsynced before the request is
	// served. Empty keeps the in-memory claim set, which forgets on restart.
	NanoClaimsFile string `json:"x402_nano_claims_file,omitempty" toml:"x402_nano_claims_file,omitempty"`
	// NanoRequireBinding accepts a Nano payment only with a nano-block-sig/1
	// binding signed by the paying account for this route.
	NanoRequireBinding bool `json:"x402_nano_require_binding,omitempty" toml:"x402_nano_require_binding,omitempty"`
}

// Normalize returns c in the form a config stores: values without surrounding
// spaces, the network in lower case, and no empty endpoint.
func (c X402Config) Normalize() X402Config {
	c.Network = strings.ToLower(strings.TrimSpace(c.Network))
	c.Asset = strings.TrimSpace(c.Asset)
	c.PayTo = strings.TrimSpace(c.PayTo)
	c.Endpoints = utils.CompactStrings(c.Endpoints)
	c.FacilitatorToken = strings.TrimSpace(c.FacilitatorToken)
	c.NanoClaimsFile = strings.TrimSpace(c.NanoClaimsFile)
	return c
}

// X402PreparePath is the gateway-owned path for the /x402/prepare endpoint.
const X402PreparePath = "/x402/prepare"

// X402ClientPath is the gateway-owned path for the /x402/client.js endpoint.
const X402ClientPath = "/x402/client.js"

const x402RequestBodyLimit int64 = 64 << 10

type x402PreparePaymentRequest struct {
	Sender string `json:"sender"`
	Method string `json:"method,omitempty"`
	Path   string `json:"path,omitempty"`
}

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
	// the contract's settlement asset (USDC on Sui, wCSPR on Casper, XNO
	// on Nano), such as "0.01"; empty means the route is unpaid.
	Amount string
}

func normalizeComposeHTTPRoutesPrefix(raw string) string {
	prefix := strings.TrimSpace(raw)
	if prefix != "" && strings.HasPrefix(prefix, "/") {
		prefix = utils.NormalizeURLPath(prefix)
	}
	return prefix
}

func collectComposeHTTPRoutesSDKConfigs(routes []ExposedHTTPRoute) []sdk.HTTPRouteConfig {
	sdkConfigs := make([]sdk.HTTPRouteConfig, 0, len(routes))
	for _, route := range routes {
		sdkConfigs = append(sdkConfigs, sdk.HTTPRouteConfig{
			Prefix:      normalizeComposeHTTPRoutesPrefix(route.Prefix),
			Upstream:    route.Upstream,
			StaticRoot:  route.StaticRoot,
			StaticIndex: route.StaticIndex,
		})
	}
	return sdkConfigs
}

func buildComposeHTTPRoutesPaidEntry(route ExposedHTTPRoute, contract X402Config, g *HTTPGateway) (string, *routePolicy, error) {
	prefix := normalizeComposeHTTPRoutesPrefix(route.Prefix)
	amount := strings.TrimSpace(route.Amount)
	if amount == "" {
		if len(route.Methods) > 0 {
			return "", nil, fmt.Errorf("http route %q payment methods require amount", prefix)
		}
		return prefix, nil, nil
	}
	if contract.PayTo == "" {
		return "", nil, fmt.Errorf("http route %q amount requires x402 pay-to", prefix)
	}
	methods, err := NormalizePaymentMethods(route.Methods)
	if err != nil {
		return "", nil, fmt.Errorf("http route %q x402 payment: %w", prefix, err)
	}
	paid, err := composePaidRoute(prefix, amount, contract, g)
	if err != nil {
		return "", nil, fmt.Errorf("http route %q x402 payment: %w", prefix, err)
	}
	paid.prefix = prefix
	paid.methods = paymentMethodSet(methods)
	return prefix, paid, nil
}

func assembleComposeHTTPRoutesPolicies(routes []ExposedHTTPRoute, contract X402Config, g *HTTPGateway) error {
	g.policies = make(map[string]*routePolicy, len(routes))
	for _, route := range routes {
		prefix, paid, err := buildComposeHTTPRoutesPaidEntry(route, contract, g)
		if err != nil {
			return err
		}
		if paid == nil {
			continue
		}
		g.servesX402 = true
		g.policies[prefix] = paid
	}
	return nil
}

// ComposeHTTPRoutes builds the payment-agnostic sdk router and explicitly
// wraps only the routes carrying an x402 amount with payment gates. The
// returned handler also serves the shared x402 client and prepare endpoints
// when at least one route is paid; a fully unpaid gateway passes those paths
// through to the routes like any other path. The caller owns the returned
// gateway and closes it when the tunnel stops; a failed composition has
// already released what it opened.
func ComposeHTTPRoutes(routes []ExposedHTTPRoute, contract X402Config) (*HTTPGateway, error) {
	if len(routes) == 0 {
		return nil, errLeastOneHTTPRouteRequired
	}
	contract.PayTo = strings.TrimSpace(contract.PayTo)
	g := &HTTPGateway{clientJS: suihttp.ClientHandler()}
	err := assembleComposeHTTPRoutesPolicies(routes, contract, g)
	if err == nil {
		g.routes, err = sdk.NewHTTPRoutes(collectComposeHTTPRoutesSDKConfigs(routes))
	}
	if err != nil {
		_ = g.Close()
		return nil, err
	}
	return g, nil
}

type routePolicy struct {
	prefix       string
	requirements facilitatortypes.PaymentRequirements
	gate         *x402http.Gate
	preparer     *suihttp.Preparer
	methods      map[string]struct{}
}

func (p *routePolicy) paidMethod(method string) bool {
	if p == nil || p.gate == nil {
		return false
	}
	if len(p.methods) == 0 {
		return true
	}
	_, ok := p.methods[strings.ToUpper(strings.TrimSpace(method))]
	return ok
}

// HTTPGateway serves the composed routes and their x402 gates. It owns the
// Nano claim log when x402_nano_claims_file is set.
type HTTPGateway struct {
	routes     *sdk.HTTPRoutes
	policies   map[string]*routePolicy
	servesX402 bool
	clientJS   http.Handler
	nano       *nanofacilitator.NanoFacilitator
	nanoClaims *nanofacilitator.FileClaimStore
}

// Close releases the Nano claim log, if one is open. Payments that reach the
// gateway after Close are refused, never accepted unrecorded.
func (g *HTTPGateway) Close() error {
	if g == nil || g.nanoClaims == nil {
		return nil
	}
	return g.nanoClaims.Close()
}

func (g *HTTPGateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	utils.DelHeaderSpellings(r.Header, types.HeaderAccessCredential)
	if _, ok := appauth.PrincipalFromContext(r.Context()); !ok {
		utils.DelHeaderSpellings(r.Header, types.PortalIdentityHeaders...)
	}

	path := "/"
	if r.URL != nil {
		path = r.URL.Path
	}
	path = utils.NormalizeURLPath(path)

	if g.servesX402 {
		if path == X402ClientPath {
			g.clientJS.ServeHTTP(w, r)
			return
		}
		if path == X402PreparePath {
			g.servePrepare(w, r)
			return
		}
	}

	prefix, handler := g.routes.Match(path)
	if handler == nil {
		http.NotFound(w, r)
		return
	}
	if policy := g.policies[prefix]; policy.paidMethod(r.Method) {
		handler = policy.gate.Wrap(handler)
	}
	handler.ServeHTTP(w, r)
}

func (g *HTTPGateway) servePrepare(w http.ResponseWriter, r *http.Request) {
	if !utils.RequireMethod(w, r, http.MethodPost) {
		return
	}
	req, ok := utils.DecodeJSONRequestAs[x402PreparePaymentRequest](w, r, x402RequestBodyLimit, utils.APIErrorResponse{
		Status:  http.StatusBadRequest,
		Code:    types.APIErrorCodeInvalidJSON,
		Message: "invalid payment prepare request",
	})
	if !ok {
		return
	}
	if strings.TrimSpace(req.Path) == "" {
		http.Error(w, "path is required", http.StatusBadRequest)
		return
	}
	path := utils.NormalizeURLPath(req.Path)
	method := http.MethodGet
	if raw := strings.ToUpper(strings.TrimSpace(req.Method)); raw != "" {
		method = raw
	}

	prefix, _ := g.routes.Match(path)
	policy := g.policies[prefix]
	if policy == nil {
		http.NotFound(w, r)
		return
	}
	if !policy.paidMethod(method) {
		http.Error(w, "x402 payment is not enabled for path", http.StatusNotFound)
		return
	}
	if policy.preparer != nil {
		policy.preparer.WritePrepare(w, r, req.Sender)
		return
	}
	g.writeRouteChallenge(w, r, policy)
}

func (g *HTTPGateway) writeRouteChallenge(w http.ResponseWriter, r *http.Request, policy *routePolicy) {
	body := struct {
		X402Version int                                    `json:"x402Version"`
		Error       string                                 `json:"error,omitempty"`
		Resource    *facilitatortypes.ResourceInfo         `json:"resource,omitempty"`
		Accepts     []facilitatortypes.PaymentRequirements `json:"accepts"`
	}{
		X402Version: int(facilitatortypes.X402VersionV2),
		Error:       "payment required",
		Resource:    &facilitatortypes.ResourceInfo{URL: utils.PublicURLForPath(r, policy.prefix)},
		Accepts:     []facilitatortypes.PaymentRequirements{policy.requirements},
	}
	raw, err := json.Marshal(body)
	if err != nil {
		http.Error(w, "encode x402 payment requirements", http.StatusInternalServerError)
		return
	}
	encoded := base64.StdEncoding.EncodeToString(raw)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set(x402http.HeaderPaymentRequired, encoded)
	w.Header().Set(x402http.HeaderXPaymentRequired, encoded)
	w.WriteHeader(http.StatusPaymentRequired)
	_, _ = w.Write(raw)
}
