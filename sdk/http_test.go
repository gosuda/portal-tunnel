package sdk

import (
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
