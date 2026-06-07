package sdk

import (
	"bufio"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/andybalholm/brotli"
	"github.com/rs/zerolog/log"

	portalx402 "github.com/gosuda/portal-tunnel/v2/portal/x402"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func RunHTTP(ctx context.Context, relayListener net.Listener, handler http.Handler, localAddr string) error {
	if relayListener == nil && localAddr == "" {
		return errors.New("relay listener or local address is required")
	}

	serverHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serveCompressedHTTP(handler, w, r)
	})

	var relaySrv *http.Server
	if relayListener != nil {
		relaySrv = &http.Server{
			Handler:           serverHandler,
			ReadHeaderTimeout: defaultRequestTimeout,
		}
	}

	var localSrv *http.Server
	if localAddr != "" {
		localSrv = &http.Server{
			Addr:              localAddr,
			Handler:           serverHandler,
			ReadHeaderTimeout: defaultRequestTimeout,
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

// HTTPRoute maps one public path prefix to one local HTTP upstream.
type HTTPRoute struct {
	// Prefix is the public request path prefix, such as "/api" or "/".
	Prefix string
	// Upstream is the target HTTP URL, or a loopback host:port shorthand.
	Upstream string
	// X402 enables payment enforcement for this public route.
	X402 *types.X402Config
}

type httpRoute struct {
	prefix            string
	prefixSlash       string
	upstream          *url.URL
	upstreamPath      string
	upstreamPathSlash string
	upstreamDomain    string
	handler           http.Handler
}

func newHTTPRouteHandler(routeConfigs []HTTPRoute, tunnelIdentity types.Identity, metadata types.LeaseMetadata) (http.Handler, error) {
	if len(routeConfigs) == 0 {
		return nil, errors.New("at least one http route is required")
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
		var handler http.Handler = route.newReverseProxy()
		if routeConfig.X402 != nil && !routeConfig.X402.Empty() {
			handler, err = portalx402.NewHTTPRouteHandler(portalx402.HTTPRouteHandlerConfig{
				Prefix:         route.prefix,
				Next:           handler,
				X402:           *routeConfig.X402,
				TunnelIdentity: tunnelIdentity,
				Metadata:       metadata,
			})
			if err != nil {
				return nil, err
			}
		}
		route.handler = handler
		routes = append(routes, route)
	}

	sort.Slice(routes, func(i, j int) bool {
		if len(routes[i].prefix) == len(routes[j].prefix) {
			return routes[i].prefix < routes[j].prefix
		}
		return len(routes[i].prefix) > len(routes[j].prefix)
	})

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if p == "" {
			p = "/"
		}
		for _, route := range routes {
			if route.prefix == "/" || p == route.prefix || strings.HasPrefix(p, route.prefixSlash) {
				route.handler.ServeHTTP(w, r)
				return
			}
		}
		http.NotFound(w, r)
	}), nil
}

func newHTTPRoute(routeConfig HTTPRoute) (*httpRoute, error) {
	prefix := strings.TrimSpace(routeConfig.Prefix)
	if prefix == "" {
		return nil, errors.New("http route prefix is required")
	}
	if !strings.HasPrefix(prefix, "/") {
		return nil, fmt.Errorf("http route prefix %q must start with /", prefix)
	}
	prefix = utils.NormalizeURLPath(prefix)

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

	route := &httpRoute{
		prefix:         prefix,
		upstream:       upstream,
		upstreamPath:   upstream.Path,
		upstreamDomain: utils.NormalizeHostname(upstream.Hostname()),
	}
	if prefix != "/" {
		route.prefixSlash = prefix + "/"
	}
	if upstream.Path != "/" {
		route.upstreamPathSlash = upstream.Path + "/"
	}
	return route, nil
}

func (r *httpRoute) newReverseProxy() *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Rewrite:        r.rewriteRequest,
		ModifyResponse: r.rewriteResponse,
		ErrorHandler: func(w http.ResponseWriter, req *http.Request, err error) {
			log.Error().Err(err).
				Str("route_prefix", r.prefix).
				Str("upstream", r.upstream.String()).
				Msg("http route proxy failed")
			http.Error(w, "bad gateway", http.StatusBadGateway)
		},
	}
}

func (r *httpRoute) rewriteRequest(pr *httputil.ProxyRequest) {
	pr.Out.URL.Path, pr.Out.URL.RawPath = r.publicRequestPathToUpstream(pr.In.URL.Path, pr.In.URL.RawPath)
	pr.Out.URL.RawQuery = pr.In.URL.RawQuery
	pr.SetURL(r.upstream)
	pr.SetXForwarded()

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

func (r *httpRoute) rewriteResponse(resp *http.Response) error {
	if resp == nil || resp.Request == nil {
		return nil
	}

	header := resp.Header
	publicHost := resp.Request.Header.Get("X-Forwarded-Host")
	publicScheme := resp.Request.Header.Get("X-Forwarded-Proto")

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
				mapped := r.upstreamPathToPublic(parsed.Path)
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
			if rewritten := r.upstreamPathToPublic(cookie.Path); rewritten != cookie.Path {
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

func (r *httpRoute) publicRequestPathToUpstream(path, rawPath string) (string, string) {
	path = utils.NormalizeURLPath(path)
	if r.prefix == "/" {
		return path, rawPath
	}
	if path == r.prefix {
		return "/", ""
	}
	path = strings.TrimPrefix(path, r.prefix)
	if path == "" {
		path = "/"
	}

	if rawPath != "" {
		switch {
		case rawPath == r.prefix:
			rawPath = "/"
		case strings.HasPrefix(rawPath, r.prefixSlash):
			rawPath = strings.TrimPrefix(rawPath, r.prefix)
		}
	}
	return path, rawPath
}

func (r *httpRoute) upstreamPathToPublic(raw string) string {
	raw = utils.NormalizeURLPath(raw)
	if r.prefix != "/" && (raw == r.prefix || strings.HasPrefix(raw, r.prefixSlash)) {
		return raw
	}

	rest := raw
	if r.upstreamPath != "/" {
		if raw == r.upstreamPath {
			rest = "/"
		} else if strings.HasPrefix(raw, r.upstreamPathSlash) {
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

func serveCompressedHTTP(handler http.Handler, w http.ResponseWriter, r *http.Request) {
	if handler == nil {
		http.NotFound(w, r)
		return
	}

	format := ""
	parseQuality := func(params string) float64 {
		for param := range strings.SplitSeq(params, ";") {
			key, value, ok := strings.Cut(strings.TrimSpace(param), "=")
			if !ok || !strings.EqualFold(strings.TrimSpace(key), "q") {
				continue
			}

			q, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
			if err != nil || q < 0 {
				return 0
			}
			if q > 1 {
				return 1
			}
			return q
		}
		return 1
	}

	bestQ := 0.0
	for rawPart := range strings.SplitSeq(r.Header.Get("Accept-Encoding"), ",") {
		part := strings.TrimSpace(strings.ToLower(rawPart))
		if part == "" {
			continue
		}

		name, params, _ := strings.Cut(part, ";")
		candidate := strings.TrimSpace(name)
		if candidate != "br" && candidate != "gzip" {
			continue
		}

		q := parseQuality(params)
		if q <= 0 {
			continue
		}

		if q > bestQ || (q == bestQ && candidate == "br") {
			format = candidate
			bestQ = q
		}
	}
	if format == "" || strings.TrimSpace(r.Header.Get("Range")) != "" {
		handler.ServeHTTP(w, r)
		return
	}
	if headerContainsToken(r.Header.Values("Connection"), "upgrade") && strings.TrimSpace(r.Header.Get("Upgrade")) != "" {
		handler.ServeHTTP(w, r)
		return
	}

	writer := &compressedResponseWriter{
		ResponseWriter: w,
		format:         format,
	}
	defer func() {
		_ = writer.Close()
	}()

	handler.ServeHTTP(writer, r)
}

func headerContainsToken(values []string, target string) bool {
	target = strings.ToLower(strings.TrimSpace(target))
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			if strings.ToLower(strings.TrimSpace(part)) == target {
				return true
			}
		}
	}
	return false
}

type compressedResponseWriter struct {
	http.ResponseWriter
	format      string
	writer      io.WriteCloser
	flushWriter func() error
	wroteHeader bool
	passthrough bool
}

func (w *compressedResponseWriter) WriteHeader(statusCode int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true

	header := w.Header()
	contentType, _, _ := strings.Cut(strings.ToLower(strings.TrimSpace(header.Get("Content-Type"))), ";")
	contentType = strings.TrimSpace(contentType)
	compressible := strings.HasPrefix(contentType, "text/")
	switch contentType {
	case "application/json", "application/javascript", "application/xml", "image/svg+xml":
		compressible = true
	}
	smallResponse := false
	if contentLength := strings.TrimSpace(header.Get("Content-Length")); contentLength != "" {
		if n, err := strconv.ParseInt(contentLength, 10, 64); err == nil && n >= 0 && n <= 1024 {
			smallResponse = true
		}
	}
	switch {
	case statusCode >= 100 && statusCode < 200:
		w.passthrough = true
	case statusCode == http.StatusNoContent || statusCode == http.StatusNotModified:
		w.passthrough = true
	case !compressible:
		w.passthrough = true
	case smallResponse:
		w.passthrough = true
	case strings.TrimSpace(header.Get("Content-Encoding")) != "":
		w.passthrough = true
	case strings.TrimSpace(header.Get("Content-Range")) != "":
		w.passthrough = true
	case strings.HasPrefix(contentType, "text/event-stream"):
		w.passthrough = true
	case headerContainsToken(header.Values("Cache-Control"), "no-transform"):
		w.passthrough = true
	}
	if w.passthrough {
		w.ResponseWriter.WriteHeader(statusCode)
		return
	}

	switch w.format {
	case "br":
		writer := brotli.NewWriter(w.ResponseWriter)
		w.writer = writer
		w.flushWriter = writer.Flush
	case "gzip":
		writer := gzip.NewWriter(w.ResponseWriter)
		w.writer = writer
		w.flushWriter = writer.Flush
	default:
		w.passthrough = true
		w.ResponseWriter.WriteHeader(statusCode)
		return
	}

	header.Del("Content-Length")
	header.Set("Content-Encoding", w.format)
	if !headerContainsToken(header.Values("Vary"), "accept-encoding") {
		header.Add("Vary", "Accept-Encoding")
	}
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *compressedResponseWriter) Write(p []byte) (int, error) {
	if !w.wroteHeader {
		header := w.Header()
		if strings.TrimSpace(header.Get("Content-Type")) == "" && len(p) > 0 {
			header.Set("Content-Type", http.DetectContentType(p))
		}
		w.WriteHeader(http.StatusOK)
	}
	if w.passthrough {
		return w.ResponseWriter.Write(p)
	}
	return w.writer.Write(p)
}

func (w *compressedResponseWriter) Flush() {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if !w.passthrough && w.flushWriter != nil {
		_ = w.flushWriter()
	}
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w *compressedResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	return hijacker.Hijack()
}

func (w *compressedResponseWriter) Close() error {
	if w.writer == nil {
		return nil
	}
	err := w.writer.Close()
	w.writer = nil
	w.flushWriter = nil
	return err
}
