package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/agent"
	"github.com/gosuda/portal-tunnel/v2/types"
)

func newGatewayStaticSiteDir(t *testing.T, name, content string) string {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", name, err)
	}
	return root
}

func gatewayTestContract() types.X402Payment {
	return types.X402Payment{
		Testnet: true,
		PayTo:   "0x" + strings.Repeat("a", 64),
	}
}

// The sdk router is payment-agnostic; a paid route must still challenge
// unpaid requests through the explicit gateway composition.
func TestComposeHTTPRoutesPaidRouteChallengesUnpaid(t *testing.T) {
	t.Parallel()

	root := newGatewayStaticSiteDir(t, "index.html", "<html>paid</html>")
	handler, err := agent.ComposeHTTPRoutes([]agent.ExposedHTTPRoute{
		{Prefix: "/", StaticRoot: root, Amount: "0.01"},
	}, gatewayTestContract())
	if err != nil {
		t.Fatalf("ComposeHTTPRoutes() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "https://public.example/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusPaymentRequired {
		t.Fatalf("unpaid request status = %d, want %d", rec.Code, http.StatusPaymentRequired)
	}
	if strings.Contains(rec.Body.String(), "paid") {
		t.Fatalf("unpaid request served the static file body: %q", rec.Body.String())
	}
}

func TestComposeHTTPRoutesUnpaidRoutesPassThrough(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("api"))
	}))
	defer upstream.Close()

	handler, err := agent.ComposeHTTPRoutes([]agent.ExposedHTTPRoute{
		{Prefix: "/api", Upstream: upstream.URL},
	}, gatewayTestContract())
	if err != nil {
		t.Fatalf("ComposeHTTPRoutes() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "https://public.example/api/users", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK || rec.Body.String() != "api" {
		t.Fatalf("status = %d body = %q, want unpaid proxy passthrough", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get(types.HeaderPaymentRequired); got != "" {
		t.Fatalf("unpaid route answered with payment challenge header %q", got)
	}
}

func TestComposeHTTPRoutesMethodFilterPassesUnpaidMethods(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	handler, err := agent.ComposeHTTPRoutes([]agent.ExposedHTTPRoute{
		{Prefix: "/paid", Upstream: upstream.URL, Methods: []string{"GET"}, Amount: "0.01"},
	}, gatewayTestContract())
	if err != nil {
		t.Fatalf("ComposeHTTPRoutes() error = %v", err)
	}

	postReq := httptest.NewRequest(http.MethodPost, "https://public.example/paid/x", nil)
	postRec := httptest.NewRecorder()
	handler.ServeHTTP(postRec, postReq)
	if postRec.Code != http.StatusOK || postRec.Body.String() != "ok" {
		t.Fatalf("POST status = %d body = %q, want unpaid passthrough outside paid methods", postRec.Code, postRec.Body.String())
	}

	getReq := httptest.NewRequest(http.MethodGet, "https://public.example/paid/x", nil)
	getRec := httptest.NewRecorder()
	handler.ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusPaymentRequired {
		t.Fatalf("GET status = %d, want payment challenge", getRec.Code)
	}
}

func TestComposeHTTPRoutesServesClientJS(t *testing.T) {
	t.Parallel()

	handler, err := agent.ComposeHTTPRoutes([]agent.ExposedHTTPRoute{
		{Prefix: "/paid", Upstream: "http://127.0.0.1:3001", Amount: "0.01"},
	}, gatewayTestContract())
	if err != nil {
		t.Fatalf("ComposeHTTPRoutes() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "https://public.example"+types.X402ClientPath, nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); !strings.Contains(got, "javascript") {
		t.Fatalf("Content-Type = %q, want javascript", got)
	}
}

func TestComposeHTTPRoutesPrepareEndpoint(t *testing.T) {
	t.Parallel()

	handler, err := agent.ComposeHTTPRoutes([]agent.ExposedHTTPRoute{
		{Prefix: "/paid", Upstream: "http://127.0.0.1:3001", Amount: "0.01"},
		{Prefix: "/api", Upstream: "http://127.0.0.1:3002"},
	}, gatewayTestContract())
	if err != nil {
		t.Fatalf("ComposeHTTPRoutes() error = %v", err)
	}

	getReq := httptest.NewRequest(http.MethodGet, "https://public.example"+types.X402PreparePath, nil)
	getRec := httptest.NewRecorder()
	handler.ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET prepare status = %d, want %d", getRec.Code, http.StatusMethodNotAllowed)
	}

	emptyReq := httptest.NewRequest(http.MethodPost, "https://public.example"+types.X402PreparePath, strings.NewReader("{}"))
	emptyRec := httptest.NewRecorder()
	handler.ServeHTTP(emptyRec, emptyReq)
	if emptyRec.Code != http.StatusBadRequest || !strings.Contains(emptyRec.Body.String(), "path is required") {
		t.Fatalf("prepare without path status = %d body = %q, want path required error", emptyRec.Code, emptyRec.Body.String())
	}

	unpaidReq := httptest.NewRequest(http.MethodPost, "https://public.example"+types.X402PreparePath, strings.NewReader(`{"path":"/api","sender":"0x1234"}`))
	unpaidRec := httptest.NewRecorder()
	handler.ServeHTTP(unpaidRec, unpaidReq)
	if unpaidRec.Code != http.StatusNotFound || !strings.Contains(unpaidRec.Body.String(), "x402 payment is not enabled for path") {
		t.Fatalf("prepare for unpaid path status = %d body = %q, want not enabled error", unpaidRec.Code, unpaidRec.Body.String())
	}
}

func TestComposeHTTPRoutesRejectsMethodsWithoutAmount(t *testing.T) {
	t.Parallel()

	_, err := agent.ComposeHTTPRoutes([]agent.ExposedHTTPRoute{
		{Prefix: "/api", Upstream: "http://127.0.0.1:3001", Methods: []string{"GET"}},
	}, gatewayTestContract())
	if err == nil {
		t.Fatalf("ComposeHTTPRoutes() error = nil, want payment methods require amount error")
	}
}

func TestComposeHTTPRoutesRejectsBlankMethod(t *testing.T) {
	t.Parallel()

	_, err := agent.ComposeHTTPRoutes([]agent.ExposedHTTPRoute{
		{Prefix: "/api", Upstream: "http://127.0.0.1:3001", Methods: []string{"GET", " "}, Amount: "0.01"},
	}, gatewayTestContract())
	if err == nil {
		t.Fatalf("ComposeHTTPRoutes() error = nil, want blank payment method error")
	}
}

func TestComposeHTTPRoutesSelectsCanonicalLongestPrefix(t *testing.T) {
	t.Parallel()
	root := newGatewayStaticSiteDir(t, "index.html", "health")
	handler, err := agent.ComposeHTTPRoutes([]agent.ExposedHTTPRoute{
		{Prefix: "/", StaticRoot: root, Amount: "0.01"},
		{Prefix: "/health", StaticRoot: root},
		{Prefix: "/paid/", StaticRoot: root, Amount: "0.01"},
	}, gatewayTestContract())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		path string
		want int
	}{
		{path: "/health", want: http.StatusOK},
		{path: "/paid", want: http.StatusPaymentRequired},
		{path: "/paid/child", want: http.StatusPaymentRequired},
	} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://public.example"+tc.path, nil))
		if rec.Code != tc.want {
			t.Errorf("%s status = %d, want %d", tc.path, rec.Code, tc.want)
		}
	}
}
