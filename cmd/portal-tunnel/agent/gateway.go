package agent

import (
	"cmp"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	facilitatorclient "github.com/gosuda/x402-facilitator/api/client"
	x402http "github.com/gosuda/x402-facilitator/resource/http"
	casperscheme "github.com/gosuda/x402-facilitator/scheme/casper"
	suischeme "github.com/gosuda/x402-facilitator/scheme/sui"
	suifacilitator "github.com/gosuda/x402-facilitator/scheme/sui/facilitator"
	suihttp "github.com/gosuda/x402-facilitator/scheme/sui/http"
	facilitatortypes "github.com/gosuda/x402-facilitator/types"

	"github.com/gosuda/portal-tunnel/v2/sdk"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

const (
	suiMainnetNetwork = "sui:mainnet"
	suiTestnetNetwork = "sui:testnet"

	// defaultMaxTimeoutSeconds is published when a paid route leaves the
	// contract timeout unset; the upstream x402 gates default to the same.
	defaultMaxTimeoutSeconds = 60
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
	// the contract's settlement asset (USDC on Sui, wCSPR on Casper), such
	// as "0.01"; empty means the route is unpaid.
	Amount string
}

// ComposeHTTPRoutes builds the payment-agnostic sdk router and explicitly
// wraps only the routes carrying an x402 amount with payment gates. The
// returned handler also serves the shared x402 client and prepare endpoints
// when at least one route is paid; a fully unpaid gateway passes those paths
// through to the routes like any other path.
func ComposeHTTPRoutes(routes []ExposedHTTPRoute, contract types.X402Payment) (http.Handler, error) {
	if len(routes) == 0 {
		return nil, errors.New("at least one http route is required")
	}
	contract.PayTo = strings.TrimSpace(contract.PayTo)

	sdkConfigs := make([]sdk.HTTPRouteConfig, 0, len(routes))
	policies := make([]routePolicy, 0, len(routes))
	servesX402 := false
	for _, route := range routes {
		prefix := strings.TrimSpace(route.Prefix)
		if prefix != "" && strings.HasPrefix(prefix, "/") {
			prefix = utils.NormalizeURLPath(prefix)
		}
		policy := routePolicy{prefix: prefix}
		sdkConfigs = append(sdkConfigs, sdk.HTTPRouteConfig{
			Prefix:      prefix,
			Upstream:    route.Upstream,
			StaticRoot:  route.StaticRoot,
			StaticIndex: route.StaticIndex,
		})

		amount := strings.TrimSpace(route.Amount)
		if amount == "" {
			if len(route.Methods) > 0 {
				return nil, fmt.Errorf("http route %q payment methods require amount", prefix)
			}
			policies = append(policies, policy)
			continue
		}
		if contract.PayTo == "" {
			return nil, fmt.Errorf("http route %q amount requires x402 pay-to", prefix)
		}
		methods, err := normalizedPaymentMethods(route.Methods)
		if err != nil {
			return nil, fmt.Errorf("http route %q x402 payment: %w", prefix, err)
		}
		paid, err := composePaidRoute(prefix, amount, contract)
		if err != nil {
			return nil, fmt.Errorf("http route %q x402 payment: %w", prefix, err)
		}
		paid.prefix = prefix
		paid.methods = paymentMethodSet(methods)
		servesX402 = true
		policies = append(policies, *paid)
	}

	sort.Slice(policies, func(i, j int) bool {
		if len(policies[i].prefix) == len(policies[j].prefix) {
			return policies[i].prefix < policies[j].prefix
		}
		return len(policies[i].prefix) > len(policies[j].prefix)
	})

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

// composePaidRoute builds the payment layer for one paid route: the settling
// gate and, for Sui routes, the shared-prepare delegate. The underlying
// facilitators live as long as the gateway — the agent owns the composition
// for its whole process lifetime, so no per-route Close is wired (the same
// lifetime the previous portal/x402 composition had).
func composePaidRoute(prefix, amount string, contract types.X402Payment) (*routePolicy, error) {
	network := strings.ToLower(strings.TrimSpace(contract.Network))
	switch {
	case network == "" || network == suiMainnetNetwork || network == suiTestnetNetwork:
		return composeSuiRoute(prefix, amount, contract)
	case casperscheme.IsCasperNetwork(network):
		return composeCasperRoute(prefix, amount, contract)
	default:
		return nil, fmt.Errorf("unsupported x402 network %q", network)
	}
}

func composeSuiRoute(prefix, amount string, contract types.X402Payment) (*routePolicy, error) {
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
		return nil, errors.New("x402 USDC payment requires a Sui pay-to address")
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
		MaxTimeoutSeconds: orDefaultMaxTimeout(contract),
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
		// The gate re-publishes this descriptor in every 402 challenge, so
		// it carries the route prefix rather than a per-request URL; the
		// prepare delegate below keeps the per-request absolute URL.
		Resource: &facilitatortypes.ResourceInfo{URL: prefix, MimeType: "text/html"},
		// Zero lets the gate apply its own settle deadline instead of the
		// previous unbounded settlement.
		RequestTimeout: contract.RequestTimeout,
	})
	if err != nil {
		return nil, err
	}
	preparer, err := suihttp.NewPreparer(suihttp.Config{
		Requirements:     requirements,
		ResourcePath:     prefix,
		ResourceMimeType: "text/html",
		Endpoints:        contract.Endpoints,
		RequestTimeout:   contract.RequestTimeout,
	})
	if err != nil {
		return nil, err
	}
	return &routePolicy{requirements: canonicalRequirements(requirements), gate: gate, preparer: preparer}, nil
}

func composeCasperRoute(prefix, amount string, contract types.X402Payment) (*routePolicy, error) {
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
		return nil, errors.New("x402 wCSPR payment requires the wCSPR CEP-18 contract hash")
	}
	// casperscheme.NormalizeAddress is strict: only account-hash-<64 hex>
	// and hex-encoded public keys survive, so a malformed pay-to dies at
	// composition instead of publishing an unpayable contract.
	payTo := casperscheme.NormalizeAddress(contract.PayTo)
	if payTo == "" {
		return nil, errors.New("x402 wCSPR payment requires a Casper pay-to address")
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
		MaxTimeoutSeconds: orDefaultMaxTimeout(contract),
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
		Requirements:   requirements,
		Facilitator:    facilitator,
		Resource:       &facilitatortypes.ResourceInfo{URL: prefix, MimeType: "text/html"},
		RequestTimeout: contract.RequestTimeout,
	})
	if err != nil {
		return nil, err
	}
	return &routePolicy{requirements: canonicalRequirements(requirements), gate: gate}, nil
}

// newCasperFacilitatorClient delegates Casper verify/settle to the hosted
// CSPR.cloud x402 facilitator (or a configured endpoint): Casper has no Go
// chain SDK, so the remote HTTP facilitator is the settlement backend.
func newCasperFacilitatorClient(contract types.X402Payment) (*facilitatorclient.Client, error) {
	endpoint := cmp.Or(firstEndpoint(contract.Endpoints), casperscheme.DefaultFacilitatorURL)
	token := strings.TrimSpace(contract.FacilitatorToken)
	if token == "" && strings.EqualFold(strings.TrimRight(endpoint, "/"), casperscheme.DefaultFacilitatorURL) {
		return nil, errors.New("CSPR.cloud x402 facilitator requires an authorization token")
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

func orDefaultMaxTimeout(contract types.X402Payment) int {
	if contract.MaxTimeoutSeconds <= 0 {
		return defaultMaxTimeoutSeconds
	}
	return contract.MaxTimeoutSeconds
}

// canonicalRequirements returns the gate-canonical published contract: the
// same normalized copy x402http.New keeps internally, with extra.paymentFlow
// pinned to the upfront flow. Clients echo published requirements as their
// accepted contract, and the gate's accepted-requirements match requires its
// pinned paymentFlow to survive the round trip. New has already rejected any
// conflicting paymentFlow, so this pin cannot mask a misconfiguration.
func canonicalRequirements(requirements facilitatortypes.PaymentRequirements) facilitatortypes.PaymentRequirements {
	extra := make(map[string]any, len(requirements.Extra)+1)
	for key, value := range requirements.Extra {
		extra[key] = value
	}
	extra["paymentFlow"] = x402http.PaymentFlowUpfront
	requirements.Extra = extra
	return requirements
}

// routePolicy is one route's payment layer: the composed gate, the Sui
// prepare delegate, and the normalized paid-method set. gate is nil for
// unpaid routes.
type routePolicy struct {
	prefix       string
	requirements facilitatortypes.PaymentRequirements
	gate         *x402http.Gate
	preparer     *suihttp.Preparer
	methods      map[string]struct{}
}

// paidMethod reports whether method is subject to payment. An empty method
// set pays every method.
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
	policies   []routePolicy
	servesX402 bool
	clientJS   http.Handler
}

func (g *httpGateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := "/"
	if r.URL != nil {
		path = r.URL.Path
	}
	path = utils.NormalizeURLPath(path)

	if g.servesX402 {
		if path == types.X402ClientPath {
			g.clientJS.ServeHTTP(w, r)
			return
		}
		if path == types.X402PreparePath {
			g.servePrepare(w, r)
			return
		}
	}

	if policy := g.matchPolicy(path); policy.paidMethod(r.Method) {
		policy.gate.Wrap(g.routes).ServeHTTP(w, r)
		return
	}
	g.routes.ServeHTTP(w, r)
}

func (g *httpGateway) servePrepare(w http.ResponseWriter, r *http.Request) {
	if !utils.RequireMethod(w, r, http.MethodPost) {
		return
	}
	req, ok := utils.DecodeJSONRequestAs[types.X402PreparePaymentRequest](w, r, types.X402RequestBodyLimit, utils.APIErrorResponse{
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

	policy := g.matchPolicy(path)
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
	// Casper wallets sign the published requirements directly, so there is
	// no server-built transaction to prepare: the prepare endpoint answers
	// with the route's challenge instead.
	g.writeRouteChallenge(w, r, policy)
}

// matchPolicy selects the same longest canonical prefix as the SDK router.
func (g *httpGateway) matchPolicy(path string) *routePolicy {
	for i := range g.policies {
		policy := &g.policies[i]
		if policy.prefix == "/" || path == policy.prefix || strings.HasPrefix(path, policy.prefix+"/") {
			return policy
		}
	}
	return nil
}

// writeRouteChallenge answers a Casper prepare request with the payment
// challenge. Casper has no server-built prepare transaction, so the shared
// prepare endpoint re-publishes the route contract in Portal's long-standing
// wire shape: the JSON body is echoed base64-encoded in both challenge
// headers. The paid route itself carries the upstream x402http canonical
// challenge; only this convenience endpoint keeps the dual-header form.
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
	w.Header().Set(types.HeaderPaymentRequired, encoded)
	w.Header().Set(types.HeaderXPaymentRequired, encoded)
	w.WriteHeader(http.StatusPaymentRequired)
	_, _ = w.Write(raw)
}

// normalizedPaymentMethods canonicalizes configured payment methods: trimmed,
// uppercased, de-duplicated, and ordered for deterministic publication. A
// blank method is a configuration error rather than an omission: an empty
// method list pays every method, so dropping a blank entry would widen the
// payment gate instead of narrowing it.
func normalizedPaymentMethods(methods []string) ([]string, error) {
	set := make(map[string]struct{}, len(methods))
	for _, raw := range methods {
		method := strings.ToUpper(strings.TrimSpace(raw))
		if method == "" {
			return nil, errors.New("x402 payment method is required")
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

// paymentMethodSet indexes already-normalized payment methods.
func paymentMethodSet(methods []string) map[string]struct{} {
	set := make(map[string]struct{}, len(methods))
	for _, method := range methods {
		set[method] = struct{}{}
	}
	return set
}
