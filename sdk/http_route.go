package sdk

import (
	"cmp"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sort"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/sdk/staticsite"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

// HTTPRouteConfig maps one public path prefix to one local HTTP upstream.
type HTTPRouteConfig struct {
	// Prefix is the public request path prefix, such as "/api" or "/".
	Prefix string
	// Upstream is the target HTTP URL, or a loopback host:port shorthand. It
	// says where to connect; the upstream still receives the request's public
	// Host. Leave empty when StaticRoot is set.
	Upstream string
	// StaticRoot, when set, serves files from this local directory as a static
	// SPA instead of proxying to an Upstream. Unknown paths fall back to
	// StaticIndex (CSR routing); paths escaping the directory are refused.
	StaticRoot string
	// StaticIndex is the SPA entry file served for the root and any unknown
	// path under a static route. Defaults to "index.html" when empty.
	StaticIndex string
}

// HTTPRoutes serves HTTPRouteConfig upstreams over one shared handler.
type HTTPRoutes struct {
	routes []*httpRoute
}

// NewHTTPRoutes creates routed HTTP handling for the given route configs.
func NewHTTPRoutes(routeConfigs []HTTPRouteConfig) (*HTTPRoutes, error) {
	if len(routeConfigs) == 0 {
		return nil, errLeastOneHTTPRouteRequired
	}

	routes := make([]*httpRoute, 0, len(routeConfigs))
	seen := make(map[string]struct{}, len(routeConfigs))
	for _, routeConfig := range routeConfigs {
		route, err := newHTTPRoute(routeConfig)
		if err != nil {
			return nil, err
		}
		if _, ok := seen[route.prefix]; ok {
			return nil, fmt.Errorf("duplicate http route prefix %q", route.prefix)
		}
		seen[route.prefix] = struct{}{}
		route.handler = route.baseHandler()
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
	_, handler := h.Match(path)
	if handler == nil {
		http.NotFound(w, r)
		return
	}
	handler.ServeHTTP(w, r)
}

// Match returns the canonical prefix and handler of the longest matching route.
// It returns an empty prefix and nil handler when no route matches. The handler
// applies the same upstream path rewriting as ServeHTTP.
func (h *HTTPRoutes) Match(path string) (string, http.Handler) {
	path = utils.NormalizeURLPath(path)
	for _, route := range h.routes {
		if route.prefix != "/" && path != route.prefix && !strings.HasPrefix(path, route.prefix+"/") {
			continue
		}

		return route.prefix, route.handler
	}
	return "", nil
}

type httpRoute struct {
	prefix         string
	upstream       *url.URL
	upstreamPath   string
	upstreamDomain string
	staticRoot     string
	staticIndex    string
	handler        http.Handler
}

func newHTTPRoute(routeConfig HTTPRouteConfig) (*httpRoute, error) {
	prefix := strings.TrimSpace(routeConfig.Prefix)
	if prefix == "" {
		return nil, errHTTPRoutePrefixIsRequired
	}
	if !strings.HasPrefix(prefix, "/") {
		return nil, fmt.Errorf("http route prefix %q must start with /", prefix)
	}
	prefix = utils.NormalizeURLPath(prefix)

	if staticRoot := strings.TrimSpace(routeConfig.StaticRoot); staticRoot != "" {
		return &httpRoute{
			prefix:      prefix,
			staticRoot:  staticRoot,
			staticIndex: strings.TrimSpace(routeConfig.StaticIndex),
		}, nil
	}

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

	return &httpRoute{
		prefix:         prefix,
		upstream:       upstream,
		upstreamPath:   upstream.Path,
		upstreamDomain: utils.NormalizeHostname(upstream.Hostname()),
	}, nil
}

func (r *httpRoute) baseHandler() http.Handler {
	if r.staticRoot != "" {
		return staticsite.NewHandler(r.prefix, r.staticRoot, r.staticIndex)
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
			path = cmp.Or(path, "/")
		}

		if rawPath == r.prefix {
			rawPath = "/"
		} else if rest, ok := strings.CutPrefix(rawPath, r.prefix+"/"); ok {
			rawPath = "/" + rest
		}
	}

	pr.Out.URL.Path = path
	pr.Out.URL.RawPath = rawPath
	pr.Out.URL.RawQuery = pr.In.URL.RawQuery
	pr.SetURL(r.upstream)

	pr.Out.Host = pr.In.Host

	utils.DelHeaderSpellings(pr.Out.Header, "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Forwarded-Prefix")
	pr.SetXForwarded()

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

func isSafeAbsoluteURLPath(value string) bool {
	return strings.HasPrefix(value, "/") &&
		(len(value) == 1 || (value[1] != '/' && value[1] != '\\'))
}

func (r *httpRoute) rewriteProxyResponse(resp *http.Response) error {
	if resp == nil || resp.Request == nil {
		return nil
	}

	header := resp.Header
	publicHost := resp.Request.Header.Get("X-Forwarded-Host")
	publicScheme := resp.Request.Header.Get("X-Forwarded-Proto")
	r.rewriteProxyLocation(header, publicHost, publicScheme)
	r.rewriteProxyCookies(header, publicHost)
	return nil
}

func (r *httpRoute) mapPublicPath(raw string) string {
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

func (r *httpRoute) rewriteProxyLocation(header http.Header, publicHost, publicScheme string) {
	location := header.Get("Location")
	if location == "" {
		return
	}
	parsed, err := url.Parse(location)
	if err != nil {
		return
	}
	target := r.rewriteProxyLocationTarget(parsed, location, publicHost, publicScheme)
	if target == nil {
		return
	}
	mapped := r.mapPublicPath(target.Path)
	if isSafeAbsoluteURLPath(mapped) {
		target.Path = mapped
		target.RawPath = ""
		header.Set("Location", target.String())
	}
}

func (r *httpRoute) rewriteProxyLocationTarget(parsed *url.URL, location, publicHost, publicScheme string) *url.URL {
	switch {
	case parsed.IsAbs():
		if (strings.EqualFold(parsed.Scheme, r.upstream.Scheme) && strings.EqualFold(parsed.Host, r.upstream.Host)) ||
			strings.EqualFold(parsed.Host, publicHost) {
			parsed.Scheme = publicScheme
			parsed.Host = publicHost
		} else {
			return nil
		}
	case parsed.Host == "" && isSafeAbsoluteURLPath(location):
	default:
		return nil
	}
	return parsed
}

func (r *httpRoute) rewriteProxyCookies(header http.Header, publicHost string) {
	values := header.Values("Set-Cookie")
	if len(values) == 0 {
		return
	}
	publicDomain := publicHost
	if host, port, err := net.SplitHostPort(publicDomain); err == nil && port != "" {
		publicDomain = host
	}
	publicDomain = utils.NormalizeHostname(strings.Trim(publicDomain, "[]"))
	header.Del("Set-Cookie")
	for _, value := range values {
		header.Add("Set-Cookie", r.rewriteProxyCookiesValue(value, publicDomain))
	}
}

func (r *httpRoute) rewriteProxyCookiesValue(value, publicDomain string) string {
	cookie, err := http.ParseSetCookie(value)
	if err != nil {
		return value
	}
	changed := false
	if cookie.Path != "" {
		if rewritten := r.mapPublicPath(cookie.Path); rewritten != cookie.Path {
			cookie.Path = rewritten
			changed = true
		}
	}
	domain := utils.NormalizeHostname(strings.TrimPrefix(cookie.Domain, "."))
	rewriteDomain := domain != "" && domain != publicDomain &&
		(domain == r.upstreamDomain || utils.IsLocalRelayHost(domain))
	if rewriteDomain {
		cookie.Domain = ""
		changed = true
	}
	if changed {
		return cookie.String()
	}
	return value
}
