package agent

import (
	"errors"
	"fmt"
	"net/http"
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
	policies := make([]routePolicy, 0, len(routes))
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
		paymentConfig := contract
		paymentConfig.Amount = amount
		paymentConfig.ResourcePath = prefix
		paymentConfig.Methods = route.Methods
		payment, err := x402.NewPayment(paymentConfig)
		if err != nil {
			return nil, fmt.Errorf("http route %q x402 payment: %w", prefix, err)
		}
		policy.paid = payment
		policies = append(policies, policy)
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

	var clientJS http.Handler = http.HandlerFunc(x402.ServeClientJS)
	for _, policy := range policies {
		if policy.paid != nil {
			clientJS = policy.paid.ClientJSHandler()
			break
		}
	}
	return &httpGateway{
		routes:   routed,
		clientJS: clientJS,
		policies: policies,
	}, nil
}

type routePolicy struct {
	prefix string
	paid   *x402.Payment
}

type httpGateway struct {
	routes   *sdk.HTTPRoutes
	clientJS http.Handler
	policies []routePolicy
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

	if policy := g.matchPolicy(path); policy != nil && policy.paid != nil {
		policy.paid.Wrap(g.routes).ServeHTTP(w, r)
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
	payment := policy.paid
	if payment == nil || !payment.PaidMethod(method) {
		http.Error(w, "x402 payment is not enabled for path", http.StatusNotFound)
		return
	}
	payment.WritePrepare(w, r, req.Sender, path)
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
