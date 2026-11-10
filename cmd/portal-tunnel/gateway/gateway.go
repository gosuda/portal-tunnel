package gateway

import (
	"cmp"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"

	facilitatorclient "github.com/gosuda/x402-facilitator/api/client"
	x402http "github.com/gosuda/x402-facilitator/resource/http"
	casperscheme "github.com/gosuda/x402-facilitator/scheme/casper"
	nanoscheme "github.com/gosuda/x402-facilitator/scheme/nano"
	nanofacilitator "github.com/gosuda/x402-facilitator/scheme/nano/facilitator"
	suischeme "github.com/gosuda/x402-facilitator/scheme/sui"
	suifacilitator "github.com/gosuda/x402-facilitator/scheme/sui/facilitator"
	suihttp "github.com/gosuda/x402-facilitator/scheme/sui/http"
	facilitatortypes "github.com/gosuda/x402-facilitator/types"
	"golang.org/x/crypto/blake2b"

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
}

// Normalize returns c in the form a config stores: values without surrounding
// spaces, the network in lower case, and no empty endpoint.
func (c X402Config) Normalize() X402Config {
	c.Network = strings.ToLower(strings.TrimSpace(c.Network))
	c.Asset = strings.TrimSpace(c.Asset)
	c.PayTo = strings.TrimSpace(c.PayTo)
	c.Endpoints = utils.CompactStrings(c.Endpoints)
	c.FacilitatorToken = strings.TrimSpace(c.FacilitatorToken)
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

// NewStripRequestHeaders removes the listed client request headers, in any
// case or underscore spelling, before Portal processing. Host and other
// invalid names are rejected.
func NewStripRequestHeaders(next http.Handler, names []string) (http.Handler, error) {
	headers := make([]string, 0, len(names))
	seen := make(map[string]struct{}, len(names))
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			return nil, errStripRequestHeaderNameRequired
		}
		if !isValidHeaderName(name) {
			return nil, fmt.Errorf("invalid strip request header name %q", name)
		}
		canonical := http.CanonicalHeaderKey(name)
		switch canonical {
		case "Host":
			return nil, errHostCannotStrippedGoStoresIt
		case "X-Forwarded-Proto":
			return nil, errXForwardedProtoCannotStrippedRunhttp
		}
		if _, ok := seen[canonical]; ok {
			continue
		}
		seen[canonical] = struct{}{}
		headers = append(headers, canonical)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		utils.DelHeaderSpellings(r.Header, headers...)
		next.ServeHTTP(w, r)
	}), nil
}

func isValidHeaderName(name string) bool {
	for i := range len(name) {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		default:
			switch c {
			case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
			default:
				return false
			}
		}
	}
	return true
}

// ComposeHTTPRoutes builds the payment-agnostic sdk router and explicitly
// wraps only the routes carrying an x402 amount with payment gates. The
// returned handler also serves the shared x402 client and prepare endpoints
// when at least one route is paid; a fully unpaid gateway passes those paths
// through to the routes like any other path.
func ComposeHTTPRoutes(routes []ExposedHTTPRoute, contract X402Config) (http.Handler, error) {
	if len(routes) == 0 {
		return nil, errLeastOneHTTPRouteRequired
	}
	contract.PayTo = strings.TrimSpace(contract.PayTo)

	sdkConfigs := make([]sdk.HTTPRouteConfig, 0, len(routes))
	policies := make(map[string]*routePolicy, len(routes))
	servesX402 := false
	var nano *nanofacilitator.NanoFacilitator
	for _, route := range routes {
		prefix := strings.TrimSpace(route.Prefix)
		if prefix != "" && strings.HasPrefix(prefix, "/") {
			prefix = utils.NormalizeURLPath(prefix)
		}
		sdkConfigs = append(sdkConfigs, sdk.HTTPRouteConfig{
			Prefix:      prefix,
			Upstream:    route.Upstream,
			StaticRoot:  route.StaticRoot,
			StaticIndex: route.StaticIndex,
		})

		amount := strings.TrimSpace(route.Amount)
		if amount == "" && len(route.Methods) > 0 {
			return nil, fmt.Errorf("http route %q payment methods require amount", prefix)
		}
		if amount == "" {
			continue
		}
		if contract.PayTo == "" {
			return nil, fmt.Errorf("http route %q amount requires x402 pay-to", prefix)
		}
		methods, err := NormalizePaymentMethods(route.Methods)
		if err != nil {
			return nil, fmt.Errorf("http route %q x402 payment: %w", prefix, err)
		}
		paid, err := composePaidRoute(prefix, amount, contract, &nano)
		if err != nil {
			return nil, fmt.Errorf("http route %q x402 payment: %w", prefix, err)
		}
		paid.prefix = prefix
		paid.methods = paymentMethodSet(methods)
		servesX402 = true
		policies[prefix] = paid
	}

	routed, err := sdk.NewHTTPRoutes(sdkConfigs)
	if err != nil {
		return nil, err
	}

	return &httpGateway{
		routes:     routed,
		policies:   policies,
		servesX402: servesX402,
		clientJS:   suihttp.ClientHandler(),
	}, nil
}

func composePaidRoute(prefix, amount string, contract X402Config, nano **nanofacilitator.NanoFacilitator) (*routePolicy, error) {
	network := strings.ToLower(strings.TrimSpace(contract.Network))
	switch {
	case network == "" || network == suiMainnetNetwork || network == suiTestnetNetwork:
		return composeSuiRoute(prefix, amount, contract)
	case casperscheme.IsCasperNetwork(network):
		return composeCasperRoute(prefix, amount, contract)
	case nanoscheme.IsNanoNetwork(network):
		return composeNanoRoute(prefix, amount, network, contract, nano)
	default:
		return nil, fmt.Errorf("unsupported x402 network %q", network)
	}
}

func composeSuiRoute(prefix, amount string, contract X402Config) (*routePolicy, error) {
	network := strings.ToLower(strings.TrimSpace(contract.Network))
	if network == "" {
		if contract.Testnet {
			network = suiTestnetNetwork
		} else {
			network = suiMainnetNetwork
		}
	}
	asset, ok := suischeme.GetGaslessStablecoinType(network, "USDC")
	if !ok {
		return nil, fmt.Errorf("USDC is not gasless stablecoin allowlisted on %s", network)
	}
	payTo := suischeme.NormalizeAddress(contract.PayTo)
	if payTo == "" {
		return nil, errX402UsdcPaymentRequiresSuiPay
	}
	atomic, err := suischeme.StablecoinAmountToAtomic(network, "USDC", amount)
	if err != nil {
		return nil, err
	}
	requirements := facilitatortypes.PaymentRequirements{
		Scheme:            string(facilitatortypes.Exact),
		Network:           network,
		Asset:             asset,
		Amount:            atomic,
		PayTo:             payTo,
		MaxTimeoutSeconds: defaultMaxTimeoutSeconds,
		Extra: map[string]any{
			"asset":               "USDC",
			"assetTransferMethod": "sui-gasless-stablecoin-address-balance",
		},
	}
	facilitator, err := suifacilitator.NewSuiFacilitatorWithOptions(network, firstEndpoint(contract.Endpoints), "", suifacilitator.SuiFacilitatorOptions{
		GaslessStablecoinTypes: []string{asset},
	})
	if err != nil {
		return nil, err
	}
	gate, err := x402http.New(x402http.Config{
		Requirements: requirements,
		Facilitator:  facilitator,
		Resource: &facilitatortypes.ResourceInfo{
			URL:      prefix,
			MimeType: "text/html",
		},
	})
	if err != nil {
		return nil, err
	}
	preparer, err := suihttp.NewPreparer(suihttp.Config{
		Requirements:     requirements,
		ResourcePath:     prefix,
		ResourceMimeType: "text/html",
		Endpoints:        contract.Endpoints,
	})
	if err != nil {
		return nil, err
	}
	return &routePolicy{requirements: canonicalRequirements(requirements), gate: gate, preparer: preparer}, nil
}

func composeCasperRoute(prefix, amount string, contract X402Config) (*routePolicy, error) {
	network := strings.ToLower(strings.TrimSpace(contract.Network))
	if network == "" {
		if contract.Testnet {
			network = casperscheme.NetworkTestnet
		} else {
			network = casperscheme.NetworkMainnet
		}
	}
	if casperscheme.GetNetworkInfo(network) == nil {
		return nil, fmt.Errorf("unsupported Casper network %q", network)
	}
	asset := strings.ToLower(strings.TrimSpace(contract.Asset))
	if asset == "" {
		return nil, errX402WcsprPaymentRequiresWcsprCep
	}
	payTo := casperscheme.NormalizeAddress(contract.PayTo)
	if payTo == "" {
		return nil, errX402WcsprPaymentRequiresCasperPay
	}
	motes, err := casperscheme.CSPRToMotes(amount)
	if err != nil {
		return nil, err
	}
	requirements := facilitatortypes.PaymentRequirements{
		Scheme:            string(facilitatortypes.Exact),
		Network:           network,
		Asset:             asset,
		Amount:            motes.String(),
		PayTo:             payTo,
		MaxTimeoutSeconds: defaultMaxTimeoutSeconds,
		Extra: map[string]any{
			"asset":               casperscheme.WCSPRSymbol,
			"assetTransferMethod": "casper-cep18-transfer",
			"decimals":            casperscheme.MoteDecimals,
		},
	}
	facilitator, err := newCasperFacilitatorClient(contract)
	if err != nil {
		return nil, err
	}
	gate, err := x402http.New(x402http.Config{
		Requirements: requirements,
		Facilitator:  facilitator,
		Resource:     &facilitatortypes.ResourceInfo{URL: prefix, MimeType: "text/html"},
	})
	if err != nil {
		return nil, err
	}
	return &routePolicy{requirements: canonicalRequirements(requirements), gate: gate}, nil
}

func composeNanoRoute(prefix, amount, network string, contract X402Config, nano **nanofacilitator.NanoFacilitator) (*routePolicy, error) {
	payTo := normalizeNanoAddress(contract.PayTo)
	if payTo == "" {
		return nil, errX402XnoPaymentRequiresChecksummedNano
	}
	raw, err := xnoToRaw(amount)
	if err != nil {
		return nil, err
	}
	if *nano == nil {
		endpoints := make([]string, 0, len(contract.Endpoints))
		for _, endpoint := range contract.Endpoints {
			if endpoint = strings.TrimSpace(endpoint); endpoint != "" && !slices.Contains(endpoints, endpoint) {
				endpoints = append(endpoints, endpoint)
			}
		}
		if len(endpoints) > 0 && len(endpoints) < nanoscheme.MinIndependentEndpoints {
			return nil, fmt.Errorf("x402 XNO payment requires at least %d independent Nano RPC endpoints", nanoscheme.MinIndependentEndpoints)
		}
		facilitator, err := nanofacilitator.NewNanoFacilitatorWithOptions(network, "", "", nanofacilitator.NanoFacilitatorOptions{
			Endpoints: endpoints,
		})
		if err != nil {
			return nil, err
		}
		*nano = facilitator
	}
	requirements := facilitatortypes.PaymentRequirements{
		Scheme:            string(facilitatortypes.Exact),
		Network:           network,
		Asset:             nanoscheme.AssetXNO,
		Amount:            raw,
		PayTo:             payTo,
		MaxTimeoutSeconds: defaultMaxTimeoutSeconds,
		Extra: map[string]any{
			"asset":               nanoscheme.AssetXNO,
			"assetTransferMethod": "nano-native-send",
			"decimals":            nanoscheme.XNORawDecimals,
		},
	}
	gate, err := x402http.New(x402http.Config{
		Requirements: requirements,
		Facilitator:  *nano,
		Resource:     &facilitatortypes.ResourceInfo{URL: prefix, MimeType: "text/html"},
	})
	if err != nil {
		return nil, err
	}
	return &routePolicy{requirements: canonicalRequirements(requirements), gate: gate}, nil
}

const nanoAddressAlphabet = "13456789abcdefghijkmnopqrstuwxyz"

func normalizeNanoAddress(address string) string {
	address = strings.ToLower(strings.TrimSpace(address))
	encoded, ok := strings.CutPrefix(address, "nano_")
	if !ok {
		encoded, ok = strings.CutPrefix(address, "xrb_")
	}
	if !ok {
		return ""
	}
	if len(encoded) != 60 {
		return ""
	}
	bits := new(big.Int)
	for i := range len(encoded) {
		value := strings.IndexByte(nanoAddressAlphabet, encoded[i])
		if value < 0 {
			return ""
		}
		bits.Lsh(bits, 5).Or(bits, big.NewInt(int64(value)))
	}
	decoded := bits.FillBytes(make([]byte, 38))
	if decoded[0] != 0 {
		return ""
	}
	hash, err := blake2b.New(5, nil)
	if err != nil {
		return ""
	}
	_, _ = hash.Write(decoded[1:33])
	checksum := hash.Sum(nil)
	slices.Reverse(checksum)
	if string(checksum) != string(decoded[33:]) {
		return ""
	}
	return "nano_" + encoded
}

func xnoToRaw(amount string) (string, error) {
	amount = strings.TrimSpace(amount)
	whole, frac, _ := strings.Cut(amount, ".")
	whole = cmp.Or(whole, "0")
	fracValid := frac == "" || isDecimalDigits(frac)
	if !isDecimalDigits(whole) || !fracValid || strings.HasSuffix(amount, ".") {
		return "", fmt.Errorf("invalid XNO amount %q", amount)
	}
	if len(frac) > nanoscheme.XNORawDecimals {
		return "", fmt.Errorf("XNO amount %q has more than %d decimals", amount, nanoscheme.XNORawDecimals)
	}
	raw, ok := new(big.Int).SetString(whole+frac+strings.Repeat("0", nanoscheme.XNORawDecimals-len(frac)), 10)
	if !ok || raw.Sign() <= 0 {
		return "", fmt.Errorf("invalid XNO amount %q", amount)
	}
	return raw.String(), nil
}

func isDecimalDigits(value string) bool {
	if value == "" {
		return false
	}
	for i := range len(value) {
		if value[i] < '0' || value[i] > '9' {
			return false
		}
	}
	return true
}

func newCasperFacilitatorClient(contract X402Config) (*facilitatorclient.Client, error) {
	endpoint := cmp.Or(firstEndpoint(contract.Endpoints), casperscheme.DefaultFacilitatorURL)
	token := strings.TrimSpace(contract.FacilitatorToken)
	if token == "" && strings.EqualFold(strings.TrimRight(endpoint, "/"), casperscheme.DefaultFacilitatorURL) {
		return nil, errCsprCloudX402FacilitatorRequiresAuthorization
	}
	if token != "" {
		u, err := url.Parse(endpoint)
		if err != nil {
			return nil, fmt.Errorf("parse x402 facilitator endpoint %q: %w", endpoint, err)
		}
		if u.Scheme == "http" && !utils.IsLoopbackHost(u.Hostname()) {
			return nil, fmt.Errorf("x402 facilitator endpoint %q sends the authorization token over plaintext http; use https or a loopback endpoint", endpoint)
		}
	}
	client, err := facilitatorclient.NewClient(endpoint)
	if err != nil {
		return nil, fmt.Errorf("create casper x402 facilitator: %w", err)
	}
	if token != "" {
		client.CreateAuthHeader = func() (map[string]map[string]string, error) {
			return map[string]map[string]string{
				"verify": {"Authorization": token},
				"settle": {"Authorization": token},
			}, nil
		}
	}
	return client, nil
}

func firstEndpoint(endpoints []string) string {
	for _, endpoint := range endpoints {
		if endpoint = strings.TrimSpace(endpoint); endpoint != "" {
			return endpoint
		}
	}
	return ""
}

func canonicalRequirements(requirements facilitatortypes.PaymentRequirements) facilitatortypes.PaymentRequirements {
	extra := make(map[string]any, len(requirements.Extra)+1)
	for key, value := range requirements.Extra {
		extra[key] = value
	}
	extra["paymentFlow"] = x402http.PaymentFlowUpfront
	requirements.Extra = extra
	return requirements
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

type httpGateway struct {
	routes     *sdk.HTTPRoutes
	policies   map[string]*routePolicy
	servesX402 bool
	clientJS   http.Handler
}

func (g *httpGateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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

func (g *httpGateway) servePrepare(w http.ResponseWriter, r *http.Request) {
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

func (g *httpGateway) writeRouteChallenge(w http.ResponseWriter, r *http.Request, policy *routePolicy) {
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

// NormalizePaymentMethods trims, uppercases, de-duplicates, and orders payment
// methods. Blank entries are rejected: an empty list pays every method.
func NormalizePaymentMethods(methods []string) ([]string, error) {
	set := make(map[string]struct{}, len(methods))
	for _, raw := range methods {
		method := strings.ToUpper(strings.TrimSpace(raw))
		if method == "" {
			return nil, errX402PaymentMethodIsRequired
		}
		set[method] = struct{}{}
	}
	if len(set) == 0 {
		return nil, nil
	}
	out := make([]string, 0, len(set))
	for method := range set {
		out = append(out, method)
	}
	sort.Strings(out)
	return out, nil
}

func paymentMethodSet(methods []string) map[string]struct{} {
	set := make(map[string]struct{}, len(methods))
	for _, method := range methods {
		set[method] = struct{}{}
	}
	return set
}
