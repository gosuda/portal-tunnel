package sdk

import (
	"net/http"
	"net/http/httptest"
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
	}, "", false)
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
	}, "", false)
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
	}, "", false)
	if err == nil {
		t.Fatal("NewHTTPRoutes() error = nil, want duplicate prefix error")
	}
}

func newStaticSite(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, content := range files {
		full := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("MkdirAll(%q) error = %v", name, err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatalf("WriteFile(%q) error = %v", name, err)
		}
	}
	return root
}

func TestHTTPRoutesStaticServesConcreteFile(t *testing.T) {
	t.Parallel()

	root := newStaticSite(t, map[string]string{
		"index.html":     "<html>index</html>",
		"assets/app.css": "body{color:red}",
	})
	handler, err := NewHTTPRoutes([]HTTPRouteConfig{
		{Prefix: "/", StaticRoot: root},
	}, "", false)
	if err != nil {
		t.Fatalf("NewHTTPRoutes() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "https://public.example/assets/app.css", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Body.String(); got != "body{color:red}" {
		t.Fatalf("body = %q, want css content", got)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/css") {
		t.Fatalf("Content-Type = %q, want text/css", ct)
	}
}

func TestHTTPRoutesStaticSPAFallback(t *testing.T) {
	t.Parallel()

	root := newStaticSite(t, map[string]string{
		"index.html": "<html>spa</html>",
	})
	handler, err := NewHTTPRoutes([]HTTPRouteConfig{
		{Prefix: "/", StaticRoot: root},
	}, "", false)
	if err != nil {
		t.Fatalf("NewHTTPRoutes() error = %v", err)
	}

	for _, target := range []string{"https://public.example/", "https://public.example/deep/client/route"} {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("%s status = %d, want 200", target, rec.Code)
		}
		if got := rec.Body.String(); got != "<html>spa</html>" {
			t.Fatalf("%s body = %q, want index content", target, got)
		}
	}
}

func TestHTTPRoutesStaticCustomIndex(t *testing.T) {
	t.Parallel()

	root := newStaticSite(t, map[string]string{
		"main.html": "<html>main</html>",
	})
	handler, err := NewHTTPRoutes([]HTTPRouteConfig{
		{Prefix: "/", StaticRoot: root, StaticIndex: "main.html"},
	}, "", false)
	if err != nil {
		t.Fatalf("NewHTTPRoutes() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "https://public.example/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if got := rec.Body.String(); got != "<html>main</html>" {
		t.Fatalf("body = %q, want main.html content", got)
	}
}

func TestHTTPRoutesStaticDirectoryReturnsIndex(t *testing.T) {
	t.Parallel()

	root := newStaticSite(t, map[string]string{
		"index.html":   "<html>index</html>",
		"sub/keep.txt": "keep",
	})
	handler, err := NewHTTPRoutes([]HTTPRouteConfig{
		{Prefix: "/", StaticRoot: root},
	}, "", false)
	if err != nil {
		t.Fatalf("NewHTTPRoutes() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "https://public.example/sub", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Body.String(); got != "<html>index</html>" {
		t.Fatalf("body = %q, want index content (no directory listing)", got)
	}
}

func TestHTTPRoutesStaticRejectsTraversal(t *testing.T) {
	t.Parallel()

	root := newStaticSite(t, map[string]string{
		"index.html": "<html>index</html>",
	})
	// A secret file one level above the served root must never be reachable.
	secret := filepath.Join(filepath.Dir(root), "secret.txt")
	if err := os.WriteFile(secret, []byte("TOP-SECRET"), 0o644); err != nil {
		t.Fatalf("WriteFile(secret) error = %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(secret) })

	handler, err := NewHTTPRoutes([]HTTPRouteConfig{
		{Prefix: "/", StaticRoot: root},
	}, "", false)
	if err != nil {
		t.Fatalf("NewHTTPRoutes() error = %v", err)
	}

	for _, target := range []string{"/../secret.txt", "/../../secret.txt", "/sub/../../secret.txt"} {
		req := httptest.NewRequest(http.MethodGet, "https://public.example/", nil)
		req.URL.Path = target
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if strings.Contains(rec.Body.String(), "TOP-SECRET") {
			t.Fatalf("%s leaked the out-of-root secret file", target)
		}
	}
}

func TestHTTPRoutesStaticPaidRouteChallengesUnpaid(t *testing.T) {
	t.Parallel()

	root := newStaticSite(t, map[string]string{
		"index.html": "<html>paid</html>",
	})
	payTo := "0x" + strings.Repeat("a", 64)
	handler, err := NewHTTPRoutes([]HTTPRouteConfig{
		{Prefix: "/", StaticRoot: root, Amount: "0.01"},
	}, payTo, true)
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
