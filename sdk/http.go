package sdk

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sort"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/portal/x402"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func RunHTTP(ctx context.Context, relayListener net.Listener, handler http.Handler, localAddr string) error {
	if relayListener == nil && localAddr == "" {
		return errors.New("relay listener or local address is required")
	}

	if handler == nil {
		handler = http.NotFoundHandler()
	}

	var relaySrv *http.Server
	if relayListener != nil {
		relaySrv = &http.Server{
			Handler:           handler,
			ReadHeaderTimeout: defaultRequestTimeout,
			IdleTimeout:       defaultIdleTimeout,
		}
	}

	var localSrv *http.Server
	if localAddr != "" {
		localSrv = &http.Server{
			Addr:              localAddr,
			Handler:           handler,
			ReadHeaderTimeout: defaultRequestTimeout,
			IdleTimeout:       defaultIdleTimeout,
		}
	}

	serverCount := 0
	if relaySrv != nil {
		serverCount++
	}
	if localSrv != nil {
		serverCount++
	}

	results := make(chan error, serverCount)
	normalizeServeErr := func(err error, prefix string) error {
		if err == nil || errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
			return nil
		}
		return fmt.Errorf("%s: %w", prefix, err)
	}

	var (
		shutdownOnce sync.Once
		shutdownErr  error
	)
	shutdown := func() error {
		shutdownOnce.Do(func() {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), defaultHTTPShutdownTimeout)
			defer cancel()

			var localErr error
			if localSrv != nil {
				localErr = localSrv.Shutdown(shutdownCtx)
				if errors.Is(localErr, http.ErrServerClosed) {
					localErr = nil
				}
			}

			var relayErr error
			if relaySrv != nil {
				relayErr = relaySrv.Shutdown(shutdownCtx)
				if errors.Is(relayErr, http.ErrServerClosed) {
					relayErr = nil
				}
			}

			shutdownErr = errors.Join(localErr, relayErr)
		})
		return shutdownErr
	}

	if localSrv != nil {
		go func() {
			results <- normalizeServeErr(localSrv.ListenAndServe(), "serve local http")
		}()
	}
	if relaySrv != nil {
		go func() {
			results <- normalizeServeErr(relaySrv.Serve(relayListener), "serve relay http")
		}()
	}

	var serveErr error
	remaining := serverCount
	ctxDone := ctx.Done()
	for remaining > 0 {
		select {
		case err := <-results:
			remaining--
			if err != nil {
				serveErr = errors.Join(serveErr, err)
				_ = shutdown()
			}
		case <-ctxDone:
			_ = shutdown()
			ctxDone = nil
		}
	}

	return errors.Join(serveErr, shutdownErr)
}

// HTTPRouteConfig maps one public path prefix to one local HTTP upstream and optional x402 payment.
type HTTPRouteConfig struct {
	// Prefix is the public request path prefix, such as "/api" or "/".
	Prefix string
	// Upstream is the target HTTP URL, or a loopback host:port shorthand.
	// Leave empty when StaticRoot is set.
	Upstream string
	// StaticRoot, when set, serves files from this local directory as a static
	// SPA instead of proxying to an Upstream. Unknown paths fall back to
	// StaticIndex (CSR routing); paths escaping the directory are refused.
	StaticRoot string
	// StaticIndex is the SPA entry file served for the root and any unknown
	// path under a static route. Defaults to "index.html" when empty.
	StaticIndex string
	// Methods limits payment to these HTTP methods. Empty means every method.
	Methods []string
	// Amount enables Sui USDC x402 payment for this public path prefix.
	// It is a human USDC amount such as "0.01"; x402 converts it to atomic units.
	Amount string
}

// HTTPRoutes serves HTTPRouteConfig upstreams and the shared x402 prepare endpoint.
type HTTPRoutes struct {
	routes []*httpRoute
}

// NewHTTPRoutes creates routed HTTP handling with an explicit x402
// payment contract shared by every paid route. All paid routes share one
// spent-digest store so a settlement digest is single-use across the whole
// HTTP surface; the optional journal path comes from the shared contract.
func NewHTTPRoutes(routeConfigs []HTTPRouteConfig, x402Payment types.X402Payment) (*HTTPRoutes, error) {
	if len(routeConfigs) == 0 {
		return nil, errors.New("at least one http route is required")
	}

	x402Payment.PayTo = strings.TrimSpace(x402Payment.PayTo)
	x402Payment.SpentLedgerPath = strings.TrimSpace(x402Payment.SpentLedgerPath)
	var spent *x402.SpentDigests
	ensureSpent := func() (*x402.SpentDigests, error) {
		if spent == nil {
			store, err := x402.NewSpentDigests(x402Payment.SpentLedgerPath)
			if err != nil {
				return nil, fmt.Errorf("x402 spent-payment ledger: %w", err)
			}
			spent = store
		}
		return spent, nil
	}
	routes := make([]*httpRoute, 0, len(routeConfigs))
	seen := make(map[string]struct{}, len(routeConfigs))
	for _, routeConfig := range routeConfigs {
		route, err := newHTTPRoute(routeConfig, x402Payment, ensureSpent)
		if err != nil {
			if spent != nil {
				_ = spent.Close()
			}
			return nil, err
		}
		if _, ok := seen[route.prefix]; ok {
			if spent != nil {
				_ = spent.Close()
			}
			return nil, fmt.Errorf("duplicate http route prefix %q", route.prefix)
		}
		seen[route.prefix] = struct{}{}
		route.handler = route.newHandler()
		routes = append(routes, route)
	}
	sort.Slice(routes, func(i, j int) bool {
		if len(routes[i].prefix) == len(routes[j].prefix) {
			return routes[i].prefix < routes[j].prefix
		}
		return len(routes[i].prefix) > len(routes[j].prefix)
	})

	return &HTTPRoutes{routes: routes}, nil
}

func (h *HTTPRoutes) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := "/"
	if r.URL != nil {
		path = r.URL.Path
	}
	path = utils.NormalizeURLPath(path)
	if path == types.X402ClientPath {
		x402.ServeClientJS(w, r)
		return
	}
	prepare := path == types.X402PreparePath
	var paymentSender string
	paymentMethod := http.MethodGet
	if prepare {
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
		path = utils.NormalizeURLPath(req.Path)
		paymentSender = req.Sender
		if method := strings.ToUpper(strings.TrimSpace(req.Method)); method != "" {
			paymentMethod = method
		}
	}

	for _, route := range h.routes {
		if route.prefix != "/" && path != route.prefix && !strings.HasPrefix(path, route.prefix+"/") {
			continue
		}

		if prepare {
			paid := route.payment != nil
			if paid && len(route.paymentMethods) > 0 {
				_, paid = route.paymentMethods[paymentMethod]
			}
			if !paid {
				http.Error(w, "x402 payment is not enabled for path", http.StatusNotFound)
				return
			}
			route.payment.WritePrepare(w, r, paymentSender, path)
			return
		}

		route.handler.ServeHTTP(w, r)
		return
	}
	http.NotFound(w, r)
}

type httpRoute struct {
	prefix         string
	upstream       *url.URL
	upstreamPath   string
	upstreamDomain string
	staticRoot     string
	staticIndex    string
	payment        *x402.Payment
	paymentMethods map[string]struct{}
	handler        http.Handler
}

func newHTTPRoute(routeConfig HTTPRouteConfig, x402Payment types.X402Payment, ensureSpent func() (*x402.SpentDigests, error)) (*httpRoute, error) {
	prefix := strings.TrimSpace(routeConfig.Prefix)
	if prefix == "" {
		return nil, errors.New("http route prefix is required")
	}
	if !strings.HasPrefix(prefix, "/") {
		return nil, fmt.Errorf("http route prefix %q must start with /", prefix)
	}
	prefix = utils.NormalizeURLPath(prefix)

	var route *httpRoute
	if staticRoot := strings.TrimSpace(routeConfig.StaticRoot); staticRoot != "" {
		staticIndex := strings.TrimSpace(routeConfig.StaticIndex)
		if staticIndex == "" {
			staticIndex = utils.DefaultStaticIndex
		}
		route = &httpRoute{
			prefix:      prefix,
			staticRoot:  staticRoot,
			staticIndex: staticIndex,
		}
	} else {
		upstreamInput := strings.TrimSpace(routeConfig.Upstream)
		if upstreamInput == "" {
			return nil, fmt.Errorf("http route %q upstream is required", prefix)
		}
		if !strings.Contains(upstreamInput, "://") {
			target, err := utils.NormalizeLoopbackTarget(upstreamInput)
			if err != nil {
				return nil, fmt.Errorf("http route %q upstream: %w", prefix, err)
			}
			upstreamInput = "http://" + target
		}

		upstream, err := url.Parse(upstreamInput)
		if err != nil {
			return nil, fmt.Errorf("http route %q upstream: %w", prefix, err)
		}
		if upstream.Host == "" {
			return nil, fmt.Errorf("http route %q upstream host is required", prefix)
		}
		if upstream.Scheme != "http" && upstream.Scheme != "https" {
			return nil, fmt.Errorf("http route %q upstream scheme must be http or https", prefix)
		}
		upstream.Fragment = ""
		upstream.Path = utils.NormalizeURLPath(upstream.Path)

		route = &httpRoute{
			prefix:         prefix,
			upstream:       upstream,
			upstreamPath:   upstream.Path,
			upstreamDomain: utils.NormalizeHostname(upstream.Hostname()),
		}
	}
	amount := strings.TrimSpace(routeConfig.Amount)
	if amount == "" && len(routeConfig.Methods) > 0 {
		return nil, fmt.Errorf("http route %q payment methods require amount", route.prefix)
	}
	if amount != "" {
		if x402Payment.PayTo == "" {
			return nil, fmt.Errorf("http route %q amount requires x402 pay-to", route.prefix)
		}
		methods := make(map[string]struct{}, len(routeConfig.Methods))
		for _, rawMethod := range routeConfig.Methods {
			method := strings.ToUpper(strings.TrimSpace(rawMethod))
			if method == "" {
				return nil, fmt.Errorf("http route %q payment method is required", route.prefix)
			}
			methods[method] = struct{}{}
		}
		paymentConfig := x402Payment
		paymentConfig.Amount = amount
		paymentConfig.ResourcePath = route.prefix
		spent, err := ensureSpent()
		if err != nil {
			return nil, fmt.Errorf("http route %q x402 payment: %w", route.prefix, err)
		}
		payment, err := x402.NewPaymentWithSpent(paymentConfig, spent)
		if err != nil {
			return nil, fmt.Errorf("http route %q x402 payment: %w", route.prefix, err)
		}
		route.payment = payment
		route.paymentMethods = methods
	}
	return route, nil
}

func (r *httpRoute) newHandler() http.Handler {
	base := r.baseHandler()
	if r.payment == nil {
		return base
	}
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if len(r.paymentMethods) > 0 {
			if _, ok := r.paymentMethods[strings.ToUpper(req.Method)]; !ok {
				base.ServeHTTP(w, req)
				return
			}
		}

		settled, ok := r.payment.Settle(req.Context(), w, req)
		if !ok {
			return
		}
		utils.SetPaymentResponseHeaders(w.Header(), settled)
		base.ServeHTTP(w, req)
	})
}

func (r *httpRoute) baseHandler() http.Handler {
	if r.staticRoot != "" {
		return utils.NewStaticSiteHandler(r.prefix, r.staticRoot, r.staticIndex)
	}
	return &httputil.ReverseProxy{
		Rewrite:        r.rewriteProxyRequest,
		ModifyResponse: r.rewriteProxyResponse,
		ErrorHandler: func(w http.ResponseWriter, req *http.Request, err error) {
			log.Error().Err(err).
				Str("route_prefix", r.prefix).
				Str("upstream", r.upstream.String()).
				Msg("http route proxy failed")
			http.Error(w, "bad gateway", http.StatusBadGateway)
		},
	}
}

func (r *httpRoute) rewriteProxyRequest(pr *httputil.ProxyRequest) {
	path := utils.NormalizeURLPath(pr.In.URL.Path)
	rawPath := pr.In.URL.RawPath
	if r.prefix != "/" {
		switch path {
		case r.prefix:
			path = "/"
		default:
			path = strings.TrimPrefix(path, r.prefix)
			if path == "" {
				path = "/"
			}
		}

		if rawPath != "" {
			if rawPath == r.prefix {
				rawPath = "/"
			} else if strings.HasPrefix(rawPath, r.prefix+"/") {
				rawPath = strings.TrimPrefix(rawPath, r.prefix)
			}
		}
	}

	pr.Out.URL.Path = path
	pr.Out.URL.RawPath = rawPath
	pr.Out.URL.RawQuery = pr.In.URL.RawQuery
	pr.SetURL(r.upstream)
	pr.SetXForwarded()
	paid := r.payment != nil
	if paid && len(r.paymentMethods) > 0 {
		_, paid = r.paymentMethods[strings.ToUpper(pr.In.Method)]
	}
	if paid {
		utils.StripPaymentHeaders(pr.Out.Header)
	}

	// SetXForwarded checks pr.In.TLS, but behind a TLS-terminating proxy
	// the inbound X-Forwarded-Proto carries the real client scheme.
	if pr.In.TLS == nil {
		proto, _, _ := strings.Cut(pr.In.Header.Get("X-Forwarded-Proto"), ",")
		if proto = strings.ToLower(strings.TrimSpace(proto)); proto != "" {
			pr.Out.Header.Set("X-Forwarded-Proto", proto)
		}
	}

	if r.prefix != "/" {
		pr.Out.Header.Set("X-Forwarded-Prefix", r.prefix)
	}
}

func (r *httpRoute) rewriteProxyResponse(resp *http.Response) error {
	if resp == nil || resp.Request == nil {
		return nil
	}

	header := resp.Header
	paid := r.payment != nil
	if paid && len(r.paymentMethods) > 0 {
		_, paid = r.paymentMethods[strings.ToUpper(resp.Request.Method)]
	}
	if paid {
		utils.StripPaymentHeaders(header)
	}
	publicHost := resp.Request.Header.Get("X-Forwarded-Host")
	publicScheme := resp.Request.Header.Get("X-Forwarded-Proto")
	publicPath := func(raw string) string {
		raw = utils.NormalizeURLPath(raw)
		if r.prefix != "/" && (raw == r.prefix || strings.HasPrefix(raw, r.prefix+"/")) {
			return raw
		}

		rest := raw
		if r.upstreamPath != "/" {
			switch {
			case raw == r.upstreamPath:
				rest = "/"
			case strings.HasPrefix(raw, r.upstreamPath+"/"):
				rest = strings.TrimPrefix(raw, r.upstreamPath)
			}
		}

		if r.prefix == "/" {
			return rest
		}
		if rest == "/" {
			return r.prefix
		}
		return r.prefix + rest
	}

	location := header.Get("Location")
	if location != "" {
		parsed, err := url.Parse(location)
		if err == nil {
			switch {
			case parsed.IsAbs():
				if strings.EqualFold(parsed.Scheme, r.upstream.Scheme) && strings.EqualFold(parsed.Host, r.upstream.Host) {
					parsed.Scheme = publicScheme
					parsed.Host = publicHost
				} else {
					parsed = nil
				}
			case strings.HasPrefix(location, "/") && parsed.Host == "" && (len(location) == 1 || (location[1] != '\\' && location[1] != '/')):
			default:
				parsed = nil
			}

			if parsed != nil {
				mapped := publicPath(parsed.Path)
				if strings.HasPrefix(mapped, "/") && (len(mapped) == 1 || (mapped[1] != '/' && mapped[1] != '\\')) {
					parsed.Path = mapped
					parsed.RawPath = ""
					header.Set("Location", parsed.String())
				}
			}
		}
	}

	values := header.Values("Set-Cookie")
	if len(values) == 0 {
		return nil
	}

	publicDomain := publicHost
	if host, port, err := net.SplitHostPort(publicDomain); err == nil && port != "" {
		publicDomain = host
	}
	publicDomain = utils.NormalizeHostname(strings.Trim(publicDomain, "[]"))

	header.Del("Set-Cookie")
	for _, value := range values {
		cookie, err := http.ParseSetCookie(value)
		if err != nil {
			header.Add("Set-Cookie", value)
			continue
		}

		changed := false
		if cookie.Path != "" {
			if rewritten := publicPath(cookie.Path); rewritten != cookie.Path {
				cookie.Path = rewritten
				changed = true
			}
		}

		domain := utils.NormalizeHostname(strings.TrimPrefix(cookie.Domain, "."))
		if domain != "" && domain != publicDomain &&
			(domain == r.upstreamDomain || utils.IsLocalRelayHost(domain)) {
			cookie.Domain = ""
			changed = true
		}

		if changed {
			header.Add("Set-Cookie", cookie.String())
			continue
		}
		header.Add("Set-Cookie", value)
	}

	return nil
}
