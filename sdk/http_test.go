package sdk

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gosuda/portal-tunnel/v2/types"
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
	}, types.X402Payment{})
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
	}, types.X402Payment{})
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

func TestHTTPRoutesRejectDuplicateNormalizedPrefixes(t *testing.T) {
	t.Parallel()

	_, err := NewHTTPRoutes([]HTTPRouteConfig{
		{Prefix: "/api", Upstream: "127.0.0.1:3001"},
		{Prefix: "/api/", Upstream: "127.0.0.1:3002"},
	}, types.X402Payment{})
	if err == nil {
		t.Fatal("NewHTTPRoutes() error = nil, want duplicate prefix error")
	}
}

func TestHTTPRoutesRejectOversizedPaymentPrepareBody(t *testing.T) {
	t.Parallel()

	handler := &HTTPRoutes{}
	body := `{"sender":"` + strings.Repeat("a", int(types.X402RequestBodyLimit)) + `"}`
	req := httptest.NewRequest(http.MethodPost, types.X402PreparePath, strings.NewReader(body))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusRequestEntityTooLarge)
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
	}, types.X402Payment{})
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

func TestHTTPRoutesStaticPaidRouteChallengesUnpaid(t *testing.T) {
	t.Parallel()

	root := newStaticSiteDir(t, "index.html", "<html>paid</html>")
	payTo := "0x" + strings.Repeat("a", 64)
	handler, err := NewHTTPRoutes([]HTTPRouteConfig{
		{Prefix: "/", StaticRoot: root, Amount: "0.01"},
	}, types.X402Payment{PayTo: payTo, Testnet: true})
	if err != nil {
		t.Fatalf("NewHTTPRoutes() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "https://public.example/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code == http.StatusOK {
		t.Fatalf("unpaid request status = 200, want payment challenge")
	}
	if strings.Contains(rec.Body.String(), "paid") {
		t.Fatalf("unpaid request served the static file body: %q", rec.Body.String())
	}
}
