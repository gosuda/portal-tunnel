package sdk

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHTTPRoutesUseLongestPrefix(t *testing.T) {
	t.Parallel()

	gotPath := make(chan string, 1)
	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath <- r.URL.RequestURI()
		_, _ = w.Write([]byte("api"))
	}))
	defer apiServer.Close()

	rootServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("root"))
	}))
	defer rootServer.Close()

	handler, err := NewHTTPRoutes([]HTTPRouteConfig{
		{Prefix: "/", Upstream: rootServer.URL},
		{Prefix: "/api", Upstream: apiServer.URL},
	})
	if err != nil {
		t.Fatalf("NewHTTPRoutes() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "https://public.example/api/users?active=true", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if got := rec.Body.String(); got != "api" {
		t.Fatalf("body = %q, want api", got)
	}
	if got := <-gotPath; got != "/users?active=true" {
		t.Fatalf("upstream path = %q, want /users?active=true", got)
	}
}

func TestHTTPRoutesRewriteResponseHeaders(t *testing.T) {
	t.Parallel()

	var upstreamURL string
	upstreamServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", upstreamURL+"/base/login")
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "1", Path: "/base/session"})
		w.WriteHeader(http.StatusFound)
	}))
	defer upstreamServer.Close()
	upstreamURL = upstreamServer.URL

	handler, err := NewHTTPRoutes([]HTTPRouteConfig{
		{Prefix: "/app", Upstream: upstreamURL + "/base"},
	})
	if err != nil {
		t.Fatalf("NewHTTPRoutes() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://public.example/app/dashboard", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if got := rec.Header().Get("Location"); got != "https://public.example/app/login" {
		t.Fatalf("Location = %q, want https://public.example/app/login", got)
	}
	if got := rec.Header().Get("Set-Cookie"); !strings.Contains(got, "Path=/app/session") {
		t.Fatalf("Set-Cookie = %q, want rewritten path", got)
	}
}

func TestHTTPRoutesRewriteRedirectsToThePublicAuthority(t *testing.T) {
	t.Parallel()

	// The upstream receives the public Host, so an app that builds an absolute
	// Location from it names the public authority, with whichever scheme it assumes.
	tests := []struct {
		name     string
		location string
		want     string
	}{
		{name: "app assumes http", location: "http://public.example/base/login", want: "https://public.example/app/login"},
		{name: "app assumes https", location: "https://public.example/base/login", want: "https://public.example/app/login"},
		{name: "unrelated authority", location: "https://other.example/base/login", want: "https://other.example/base/login"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", tt.location)
				w.WriteHeader(http.StatusFound)
			}))
			defer upstream.Close()

			handler, err := NewHTTPRoutes([]HTTPRouteConfig{{Prefix: "/app", Upstream: upstream.URL + "/base"}})
			if err != nil {
				t.Fatalf("NewHTTPRoutes() error = %v", err)
			}
			req := httptest.NewRequest(http.MethodGet, "http://public.example/app/dashboard", nil)
			req.Header.Set("X-Forwarded-Proto", "https")
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if got := rec.Header().Get("Location"); got != tt.want {
				t.Fatalf("Location = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRunHTTPRelayRequestsReachUpstreamAsPublicHTTPS(t *testing.T) {
	t.Parallel()

	gotHeader := make(chan http.Header, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Clone()
		header.Set("Host", r.Host)
		gotHeader <- header
	}))
	defer upstream.Close()

	routes, err := NewHTTPRoutes([]HTTPRouteConfig{{Prefix: "/", Upstream: upstream.URL}})
	if err != nil {
		t.Fatalf("NewHTTPRoutes() error = %v", err)
	}
	relay, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- RunHTTP(ctx, relay, routes, "") }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("RunHTTP() error = %v", err)
		}
	}()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+relay.Addr().String()+"/", nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext() error = %v", err)
	}
	req.Host = "app.relay.example"
	// The tunnel ended TLS, so a client cannot downgrade the public scheme.
	req.Header.Set("X-Forwarded-Proto", "http")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do() error = %v", err)
	}
	_ = resp.Body.Close()

	header := <-gotHeader
	if got := header.Get("Host"); got != "app.relay.example" {
		t.Fatalf("upstream Host = %q, want app.relay.example", got)
	}
	if got := header.Get("X-Forwarded-Proto"); got != "https" {
		t.Fatalf("upstream X-Forwarded-Proto = %q, want https", got)
	}
	if got := header.Get("X-Forwarded-For"); got == "" {
		t.Fatalf("upstream X-Forwarded-For is empty, want the peer address")
	}
}

func TestHTTPRoutePreservesPublicHostForEveryUpstream(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		upstream string
	}{
		{name: "loopback ip", upstream: "http://127.0.0.1:3000"},
		{name: "container host name", upstream: "http://host.docker.internal:3000"},
		{name: "remote https backend", upstream: "https://backend.example.com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			route, err := newHTTPRoute(HTTPRouteConfig{Prefix: "/", Upstream: tt.upstream})
			if err != nil {
				t.Fatalf("newHTTPRoute() error = %v", err)
			}
			in := httptest.NewRequest(http.MethodGet, "http://app.relay.example/", nil)
			pr := &httputil.ProxyRequest{In: in, Out: in.Clone(t.Context())}
			route.rewriteProxyRequest(pr)

			if pr.Out.Host != "app.relay.example" {
				t.Fatalf("outbound Host = %q, want app.relay.example", pr.Out.Host)
			}
		})
	}
}

func TestHTTPRoutesProxyUpgradedConnections(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, rw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Errorf("Hijack() error = %v", err)
			return
		}
		defer conn.Close()
		_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: portal-test\r\n\r\n")
		_ = rw.Flush()
		line, err := rw.ReadString('\n')
		if err != nil {
			return
		}
		_, _ = rw.WriteString(line)
		_ = rw.Flush()
	}))
	defer upstream.Close()

	routes, err := NewHTTPRoutes([]HTTPRouteConfig{{Prefix: "/", Upstream: upstream.URL}})
	if err != nil {
		t.Fatalf("NewHTTPRoutes() error = %v", err)
	}
	front := httptest.NewServer(routes)
	defer front.Close()

	conn, err := new(net.Dialer).DialContext(t.Context(), "tcp", front.Listener.Addr().String())
	if err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := fmt.Fprint(conn, "GET / HTTP/1.1\r\nHost: app.relay.example\r\nConnection: Upgrade\r\nUpgrade: portal-test\r\n\r\n"); err != nil {
		t.Fatalf("write upgrade request error = %v", err)
	}
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("ReadResponse() error = %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101", resp.StatusCode)
	}

	if _, err := fmt.Fprint(conn, "ping\n"); err != nil {
		t.Fatalf("write upgraded payload error = %v", err)
	}
	got, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read upgraded payload error = %v", err)
	}
	if got != "ping\n" {
		t.Fatalf("echo = %q, want ping", got)
	}
}

func TestHTTPRoutesRejectDuplicatePrefixes(t *testing.T) {
	t.Parallel()

	_, err := NewHTTPRoutes([]HTTPRouteConfig{
		{Prefix: "/api", Upstream: "http://127.0.0.1:3001"},
		{Prefix: "/api", Upstream: "http://127.0.0.1:3002"},
	})
	if err == nil {
		t.Fatalf("NewHTTPRoutes() error = nil, want duplicate prefix error")
	}
}

func newStaticSiteDir(t *testing.T, name, content string) string {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", name, err)
	}
	return root
}

// Static route behavior is covered in utils; these cases pin the wiring from
// HTTPRouteConfig through to the static handler.
func TestHTTPRoutesServeStaticRoute(t *testing.T) {
	t.Parallel()

	root := newStaticSiteDir(t, "main.html", "<html>main</html>")
	handler, err := NewHTTPRoutes([]HTTPRouteConfig{
		{Prefix: "/", StaticRoot: root, StaticIndex: "main.html"},
	})
	if err != nil {
		t.Fatalf("NewHTTPRoutes() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "https://public.example/deep/route", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Body.String(); got != "<html>main</html>" {
		t.Fatalf("body = %q, want the configured entry file", got)
	}
}

func TestHTTPRoutesStripRequestHeaders(t *testing.T) {
	t.Parallel()
	var gotHeaders http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	handler, err := NewHTTPRoutes([]HTTPRouteConfig{
		{Prefix: "/", Upstream: upstream.URL, StripRequestHeaders: []string{"X-Custom", "Authorization"}},
	})
	if err != nil {
		t.Fatalf("NewHTTPRoutes() error = %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	req.Header.Set("X-Custom", "secret")
	req.Header.Set("Authorization", "Bearer abc")
	req.Header.Set("X-Keep", "keep")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if gotHeaders.Get("X-Custom") != "" {
		t.Fatalf("X-Custom forwarded: %q", gotHeaders.Get("X-Custom"))
	}
	if gotHeaders.Get("Authorization") != "" {
		t.Fatalf("Authorization forwarded: %q", gotHeaders.Get("Authorization"))
	}
	if gotHeaders.Get("X-Keep") != "keep" {
		t.Fatalf("X-Keep = %q, want keep", gotHeaders.Get("X-Keep"))
	}
	req2 := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	req2.Header.Set("x-custom", "secret")
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	if gotHeaders.Get("X-Custom") != "" {
		t.Fatalf("x-custom forwarded after case-insensitive strip")
	}
}
