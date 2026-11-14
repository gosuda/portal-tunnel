package gateway

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Per-network payment, conversion and claim tests live with the payment
// owner (x402-facilitator resource/paywall). These tests cover only how the
// tunnel composes its routes with the paywall.

const nanoTestPayTo = "nano_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuohr3"

func checkPrepareRouted(t *testing.T, handler http.Handler, path, method string, status int) {
	t.Helper()
	body, err := json.Marshal(map[string]string{"path": path, "method": method})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "https://tenant.example"+X402PreparePath, strings.NewReader(string(body))))
	if rec.Code != status {
		t.Fatalf("status = %d, body = %q; want %d", rec.Code, rec.Body.String(), status)
	}
}

func TestComposeHTTPRoutesPaymentFollowsSelectedRoute(t *testing.T) {
	t.Parallel()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.URL.RequestURI())
	}))
	t.Cleanup(upstream.Close)
	handler, err := ComposeHTTPRoutes([]ExposedHTTPRoute{
		{Prefix: "/pay", Upstream: upstream.URL, Amount: "0.01"},
		{Prefix: "/pay/free/", Upstream: upstream.URL},
		{Prefix: "/pay/free/locked", Upstream: upstream.URL, Amount: "0.01", Methods: []string{"POST"}},
	}, X402Config{Network: "nano:mainnet", PayTo: nanoTestPayTo})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = handler.Close() })
	checkSelectedRouteResponses(t, handler)
	checkSelectedRoutePrepare(t, handler)
}

func checkSelectedRouteResponses(t *testing.T, handler http.Handler) {
	t.Helper()
	for _, tc := range []struct {
		method string
		path   string
		status int
		body   string
	}{
		{http.MethodGet, "/pay/item", http.StatusPaymentRequired, ""},
		{http.MethodGet, "/pay/free/item?q=1", http.StatusOK, "/item?q=1"},
		{http.MethodGet, "/pay/free/locked/item", http.StatusOK, "/item"},
		{http.MethodPost, "/pay/free/locked/item", http.StatusPaymentRequired, ""},
		{http.MethodGet, "/pay/free/../item", http.StatusPaymentRequired, ""},
		{http.MethodGet, "/payment", http.StatusNotFound, ""},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(tc.method, "https://tenant.example"+tc.path, nil))
			if rec.Code != tc.status || (tc.body != "" && rec.Body.String() != tc.body) {
				t.Fatalf("status = %d, body = %q; want status %d, body %q", rec.Code, rec.Body.String(), tc.status, tc.body)
			}
		})
	}
}

func checkSelectedRoutePrepare(t *testing.T, handler http.Handler) {
	t.Helper()
	for _, tc := range []struct {
		path   string
		method string
		status int
	}{
		{"/pay/item", "GET", http.StatusPaymentRequired},
		{"/pay/free/item", "GET", http.StatusNotFound},
		{"/pay/free/locked/item", "GET", http.StatusNotFound},
		{"/pay/free/locked/item", "POST", http.StatusPaymentRequired},
		{"/payment", "GET", http.StatusNotFound},
	} {
		t.Run("prepare "+tc.method+" "+tc.path, func(t *testing.T) {
			checkPrepareRouted(t, handler, tc.path, tc.method, tc.status)
		})
	}
}

func TestComposeHTTPRoutesRejectsUnpaidMethods(t *testing.T) {
	t.Parallel()
	_, err := ComposeHTTPRoutes([]ExposedHTTPRoute{
		{Prefix: "/free", Upstream: "http://127.0.0.1:1", Methods: []string{"POST"}},
	}, X402Config{Network: "nano:mainnet", PayTo: nanoTestPayTo})
	if err == nil {
		t.Fatal("ComposeHTTPRoutes() error = nil, want rejection of method-scoped payment without an amount")
	}
}

func TestComposeHTTPRoutesUnpaidGatewayPassesHelperPaths(t *testing.T) {
	t.Parallel()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.URL.Path)
	}))
	t.Cleanup(upstream.Close)
	gw, err := ComposeHTTPRoutes([]ExposedHTTPRoute{{Prefix: "/", Upstream: upstream.URL}}, X402Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer gw.Close()
	for _, path := range []string{X402ClientPath, X402PreparePath} {
		rec := httptest.NewRecorder()
		gw.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://tenant.example"+path, nil))
		if rec.Code != http.StatusOK || rec.Body.String() != path {
			t.Fatalf("%s: status %d body %q; want the upstream", path, rec.Code, rec.Body.String())
		}
	}
}

func TestComposeHTTPRoutesPaidGatewayServesClient(t *testing.T) {
	t.Parallel()
	gw, err := ComposeHTTPRoutes([]ExposedHTTPRoute{{Prefix: "/", Upstream: "http://127.0.0.1:1", Amount: "0.01"}},
		X402Config{Network: "nano:mainnet", PayTo: nanoTestPayTo})
	if err != nil {
		t.Fatal(err)
	}
	defer gw.Close()
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://tenant.example"+X402ClientPath, nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Header().Get("Content-Type"), "javascript") {
		t.Fatalf("client.js: status %d type %q", rec.Code, rec.Header().Get("Content-Type"))
	}
}

func TestComposeHTTPRoutesRejectsInvalidPayment(t *testing.T) {
	t.Parallel()
	for name, contract := range map[string]X402Config{
		"unsupported network": {Network: "eip155:8453", PayTo: "0x1"},
		"invalid pay-to":      {Network: "nano:mainnet", PayTo: "0x1"},
	} {
		if gw, err := ComposeHTTPRoutes([]ExposedHTTPRoute{{Prefix: "/", Upstream: "http://127.0.0.1:1", Amount: "0.01"}}, contract); err == nil {
			_ = gw.Close()
			t.Errorf("%s: ComposeHTTPRoutes() error = nil", name)
		}
	}
}

func TestHTTPGatewayCloseIsNilSafe(t *testing.T) {
	t.Parallel()
	var gw *HTTPGateway
	if err := gw.Close(); err != nil {
		t.Fatalf("nil Close() = %v", err)
	}
}

// Network options reach the facilitator's paywall unchanged: a known option
// takes effect, an unknown one is refused instead of silently dropped.
func TestComposeHTTPRoutesPassesX402Options(t *testing.T) {
	t.Parallel()
	routes := []ExposedHTTPRoute{{Prefix: "/", Upstream: "http://127.0.0.1:1", Amount: "0.01"}}
	path := filepath.Join(t.TempDir(), "claims.jsonl")
	gw, err := ComposeHTTPRoutes(routes, X402Config{Network: "nano:mainnet", PayTo: nanoTestPayTo, Options: map[string]string{"nano_claims_file": path}})
	if err != nil {
		t.Fatalf("ComposeHTTPRoutes() error = %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("claim log not created: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("Close() = %v", err)
	}
	if gw, err := ComposeHTTPRoutes(routes, X402Config{Network: "nano:mainnet", PayTo: nanoTestPayTo, Options: map[string]string{"nano_claim_file": path}}); err == nil {
		_ = gw.Close()
		t.Fatal("ComposeHTTPRoutes() accepted an unknown x402 option")
	}
}

func TestX402ConfigNormalizeAndParseOption(t *testing.T) {
	t.Parallel()
	got := X402Config{Options: map[string]string{" nano_require_binding ": " true ", " ": "x"}}.Normalize()
	if len(got.Options) != 1 || got.Options["nano_require_binding"] != "true" {
		t.Fatalf("Normalize().Options = %v", got.Options)
	}
	if empty := (X402Config{Options: map[string]string{}}).Normalize(); empty.Options != nil {
		t.Fatalf("empty options normalized to %v, want nil", empty.Options)
	}
	if key, value, err := ParseX402Option(" nano_claims_file = /a=b "); err != nil || key != "nano_claims_file" || value != "/a=b" {
		t.Fatalf("ParseX402Option() = %q, %q, %v", key, value, err)
	}
	for _, raw := range []string{"novalue", "=x", " = x"} {
		if _, _, err := ParseX402Option(raw); err == nil {
			t.Errorf("ParseX402Option(%q) error = nil", raw)
		}
	}
}
