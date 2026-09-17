package agent

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"

	"github.com/gosuda/portal-tunnel/v2/portal/x402"
	"github.com/gosuda/portal-tunnel/v2/sdk"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
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
	// Amount enables x402 payment for this route. It is a human USDC amount
	// such as "0.01"; empty means the route is unpaid.
	Amount string
}

// ComposeHTTPRoutes builds the payment-agnostic sdk router and explicitly
// wraps only the routes carrying an x402 amount with payment gates. The
// returned handler also serves the shared x402 client and prepare endpoints.
func ComposeHTTPRoutes(routes []ExposedHTTPRoute, contract types.X402Payment) (http.Handler, error) {
	if len(routes) == 0 {
		return nil, errors.New("at least one http route is required")
	}
	contract.PayTo = strings.TrimSpace(contract.PayTo)

	sdkConfigs := make([]sdk.HTTPRouteConfig, 0, len(routes))
	paid := make([]paidRoute, 0, len(routes))
	for _, route := range routes {
		prefix := strings.TrimSpace(route.Prefix)
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
			continue
		}
		if contract.PayTo == "" {
			return nil, fmt.Errorf("http route %q amount requires x402 pay-to", prefix)
		}
		methods, err := normalizeX402Methods(route.Methods)
		if err != nil {
			return nil, fmt.Errorf("http route %q: %w", prefix, err)
		}
		methodSet := make(map[string]struct{}, len(methods))
		for _, method := range methods {
			methodSet[method] = struct{}{}
		}

		paymentConfig := contract
		paymentConfig.Amount = amount
		paymentConfig.ResourcePath = prefix
		paymentConfig.Methods = slices.Clone(methods)
		payment, err := x402.NewPayment(paymentConfig)
		if err != nil {
			return nil, fmt.Errorf("http route %q x402 payment: %w", prefix, err)
		}
		paid = append(paid, paidRoute{prefix: prefix, methods: methodSet, payment: payment})
	}

	sort.Slice(paid, func(i, j int) bool {
		if len(paid[i].prefix) == len(paid[j].prefix) {
			return paid[i].prefix < paid[j].prefix
		}
		return len(paid[i].prefix) > len(paid[j].prefix)
	})

	routed, err := sdk.NewHTTPRoutes(sdkConfigs)
	if err != nil {
		return nil, err
	}

	var clientJS http.Handler = http.HandlerFunc(x402.ServeClientJS)
	if len(paid) > 0 {
		clientJS = paid[0].payment.ClientJSHandler()
	}
	prefixes := make([]string, 0, len(sdkConfigs))
	for _, config := range sdkConfigs {
		prefixes = append(prefixes, strings.TrimSpace(config.Prefix))
	}
	sort.Slice(prefixes, func(i, j int) bool {
		if len(prefixes[i]) == len(prefixes[j]) {
			return prefixes[i] < prefixes[j]
		}
		return len(prefixes[i]) > len(prefixes[j])
	})
	return &httpGateway{
		routes:   routed,
		clientJS: clientJS,
		prefixes: prefixes,
		paid:     paid,
	}, nil
}

type paidRoute struct {
	prefix  string
	methods map[string]struct{}
	payment *x402.Payment
}

type httpGateway struct {
	routes   *sdk.HTTPRoutes
	clientJS http.Handler
	prefixes []string
	paid     []paidRoute
}

func (g *httpGateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := "/"
	if r.URL != nil {
		path = r.URL.Path
	}
	path = utils.NormalizeURLPath(path)

	if path == types.X402ClientPath {
		g.clientJS.ServeHTTP(w, r)
		return
	}
	if path == types.X402PreparePath {
		g.servePrepare(w, r)
		return
	}

	if route := g.matchPaid(path); route != nil {
		route.payment.Wrap(g.routes).ServeHTTP(w, r)
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

	if !g.matchesRoute(path) {
		http.NotFound(w, r)
		return
	}
	route := g.matchPaid(path)
	if route == nil || !route.allowsMethod(method) {
		http.Error(w, "x402 payment is not enabled for path", http.StatusNotFound)
		return
	}
	route.payment.WritePrepare(w, r, req.Sender, path)
}

// matchesRoute mirrors the sdk router's longest-prefix match.
func (g *httpGateway) matchesRoute(path string) bool {
	for _, prefix := range g.prefixes {
		if prefix == "/" || path == prefix || strings.HasPrefix(path, prefix+"/") {
			return true
		}
	}
	return false
}

// matchPaid returns the first matching paid route, mirroring the sdk router's
// longest-prefix match. Wrap enforces the route's payment methods itself.
func (g *httpGateway) matchPaid(path string) *paidRoute {
	for i := range g.paid {
		route := &g.paid[i]
		if route.prefix == "/" || path == route.prefix || strings.HasPrefix(path, route.prefix+"/") {
			return route
		}
	}
	return nil
}

func (r *paidRoute) allowsMethod(method string) bool {
	if len(r.methods) == 0 {
		return true
	}
	_, ok := r.methods[strings.ToUpper(strings.TrimSpace(method))]
	return ok
}

func normalizeX402Methods(raw []string) ([]string, error) {
	methods := make([]string, 0, len(raw))
	for _, value := range raw {
		method := strings.ToUpper(strings.TrimSpace(value))
		if method == "" {
			return nil, errors.New("payment method is required")
		}
		if !slices.Contains(methods, method) {
			methods = append(methods, method)
		}
	}
	return methods, nil
}
