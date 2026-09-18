package main

import (
	"encoding/base64"
	"encoding/json"
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

// The sdk router is payment-agnostic; the gateway composition is what turns
// x402 metadata into routing decisions. These cases pin that composition:
// which requests are challenged, which pass through, which paths the prepare
// endpoint dispatches to a payment, and which configurations are rejected.
func TestComposeHTTPRoutes(t *testing.T) {
	t.Parallel()

	root := newGatewayStaticSiteDir(t, "index.html", "<html>paid</html>")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("api"))
	}))
	defer upstream.Close()

	handler, err := agent.ComposeHTTPRoutes([]agent.ExposedHTTPRoute{
		{Prefix: "/", StaticRoot: root, Amount: "0.01"},
		{Prefix: "/api", Upstream: upstream.URL},
		{Prefix: "/paid", Upstream: upstream.URL, Methods: []string{"GET"}, Amount: "0.01"},
	}, gatewayTestContract())
	if err != nil {
		t.Fatalf("ComposeHTTPRoutes() error = %v", err)
	}

	t.Run("paid route challenges unpaid request", func(t *testing.T) {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://public.example/", nil))

		if rec.Code != http.StatusPaymentRequired {
			t.Fatalf("unpaid request status = %d, want %d", rec.Code, http.StatusPaymentRequired)
		}
		if strings.Contains(rec.Body.String(), "paid") {
			t.Fatalf("unpaid request served the static file body: %q", rec.Body.String())
		}
	})

	t.Run("unpaid route passes through untouched", func(t *testing.T) {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://public.example/api/users", nil))

		if rec.Code != http.StatusOK || rec.Body.String() != "api" {
			t.Fatalf("status = %d body = %q, want unpaid proxy passthrough", rec.Code, rec.Body.String())
		}
		if got := rec.Header().Get(types.HeaderPaymentRequired); got != "" {
			t.Fatalf("unpaid route answered with payment challenge header %q", got)
		}

		// A fully unpaid gateway has no payment layer at all: even the
		// reserved x402 paths pass through to the routes instead of being
		// answered by the gateway.
		unpaid, err := agent.ComposeHTTPRoutes([]agent.ExposedHTTPRoute{
			{Prefix: "/", Upstream: upstream.URL},
		}, gatewayTestContract())
		if err != nil {
			t.Fatalf("ComposeHTTPRoutes() error = %v", err)
		}
		for _, path := range []string{types.X402ClientPath, types.X402PreparePath} {
			rec := httptest.NewRecorder()
			unpaid.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "https://public.example"+path, strings.NewReader(`{"path":"/x"}`)))
			if rec.Code != http.StatusOK || rec.Body.String() != "api" {
				t.Fatalf("POST %s status = %d body = %q, want a fully unpaid gateway to pass x402 paths through", path, rec.Code, rec.Body.String())
			}
		}
	})

	t.Run("payment scope follows the configured methods", func(t *testing.T) {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "https://public.example/paid/x", nil))
		if rec.Code != http.StatusOK || rec.Body.String() != "api" {
			t.Fatalf("POST status = %d body = %q, want passthrough outside paid methods", rec.Code, rec.Body.String())
		}

		rec = httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://public.example/paid/x", nil))
		if rec.Code != http.StatusPaymentRequired {
			t.Fatalf("GET status = %d, want payment challenge", rec.Code)
		}
	})

	t.Run("prepare endpoint dispatches paid routes only", func(t *testing.T) {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "https://public.example"+types.X402PreparePath, strings.NewReader(`{"path":"/api"}`)))
		if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "x402 payment is not enabled for path") {
			t.Fatalf("prepare for unpaid path status = %d body = %q, want not enabled error", rec.Code, rec.Body.String())
		}

		// A paid path is handed to the x402 payment layer: without a sender
		// the payment's own validation answers instead of the gateway
		// refusing the path. Everything past this dispatch is portal/x402's
		// contract, asserted there.
		rec = httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "https://public.example"+types.X402PreparePath, strings.NewReader(`{"path":"/paid"}`)))
		if rec.Code == http.StatusNotFound || rec.Code == http.StatusInternalServerError {
			t.Fatalf("prepare for paid path status = %d body = %q, want dispatch into the payment layer", rec.Code, rec.Body.String())
		}
	})

	t.Run("payment methods require an amount", func(t *testing.T) {
		_, err := agent.ComposeHTTPRoutes([]agent.ExposedHTTPRoute{
			{Prefix: "/api", Upstream: upstream.URL, Methods: []string{"GET"}},
		}, gatewayTestContract())
		if err == nil {
			t.Fatal("ComposeHTTPRoutes() error = nil, want payment methods require amount error")
		}
	})
}

func TestComposeHTTPRoutesPreservesResourceMetadata(t *testing.T) {
	t.Parallel()

	root := newGatewayStaticSiteDir(t, "index.html", "<html>paid</html>")
	contract := gatewayTestContract()
	contract.ResourceDescription = "Paid JSON API"
	contract.ResourceMimeType = "application/json"

	handler, err := agent.ComposeHTTPRoutes([]agent.ExposedHTTPRoute{
		{Prefix: "/paid", StaticRoot: root, Amount: "0.01"},
	}, contract)
	if err != nil {
		t.Fatalf("ComposeHTTPRoutes() error = %v", err)
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://public.example/paid", nil))
	if rec.Code != http.StatusPaymentRequired {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusPaymentRequired)
	}

	encoded := rec.Header().Get(types.HeaderPaymentRequired)
	if encoded == "" {
		t.Fatal("payment challenge header is empty")
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode payment challenge: %v", err)
	}
	var challenge struct {
		Resource struct {
			Description string `json:"description"`
			MimeType    string `json:"mimeType"`
		} `json:"resource"`
	}
	if err := json.Unmarshal(raw, &challenge); err != nil {
		t.Fatalf("decode payment challenge JSON: %v", err)
	}
	if challenge.Resource.Description != contract.ResourceDescription {
		t.Fatalf("resource description = %q, want %q", challenge.Resource.Description, contract.ResourceDescription)
	}
	if challenge.Resource.MimeType != contract.ResourceMimeType {
		t.Fatalf("resource mime type = %q, want %q", challenge.Resource.MimeType, contract.ResourceMimeType)
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
