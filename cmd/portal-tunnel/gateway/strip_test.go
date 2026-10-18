package gateway

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestStripRequestHeaders(t *testing.T) {
	t.Parallel()
	var gotHeaders http.Header
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	})
	handler, err := NewStripRequestHeaders(next, []string{"X-Custom", "Authorization"})
	if err != nil {
		t.Fatalf("NewStripRequestHeaders() error = %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	req.Header.Set("X-Custom", "secret")
	req.Header.Set("Authorization", "Bearer abc")
	req.Header.Set("X-Keep", "keep")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if gotHeaders.Get("X-Custom") != "" {
		t.Fatalf("X-Custom forwarded: %q", gotHeaders.Get("X-Custom"))
	}
	if gotHeaders.Get("Authorization") != "" {
		t.Fatalf("Authorization forwarded: %q", gotHeaders.Get("Authorization"))
	}
	if gotHeaders.Get("X-Keep") != "keep" {
		t.Fatalf("X-Keep = %q, want keep", gotHeaders.Get("X-Keep"))
	}
	// Case-insensitive: lowercase input is also stripped.
	req2 := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	req2.Header.Set("x-custom", "secret")
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	if gotHeaders.Get("X-Custom") != "" {
		t.Fatal("x-custom forwarded after case-insensitive strip")
	}
}

func TestStripRequestHeadersRejectsHost(t *testing.T) {
	t.Parallel()
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	for _, name := range []string{"Host", "X-Forwarded-Proto"} {
		if _, err := NewStripRequestHeaders(next, []string{name}); err == nil {
			t.Fatalf("NewStripRequestHeaders(%q) error = nil, want rejection", name)
		}
	}
}

func TestStripRequestHeadersRejectsInvalidNames(t *testing.T) {
	t.Parallel()
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	for _, name := range []string{"", "  ", "X Custom", "X-Custom:"} {
		if _, err := NewStripRequestHeaders(next, []string{name}); err == nil {
			t.Fatalf("NewStripRequestHeaders(%q) error = nil, want invalid name error", name)
		}
	}
}

func TestHTTPGatewayAlwaysStripsInboundPortalIdentityHeaders(t *testing.T) {
	t.Parallel()
	var gotUser, gotAuth, gotCredential string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUser = r.Header.Get(types.HeaderPortalUser)
		gotAuth = r.Header.Get(types.HeaderPortalAuth)
		gotCredential = r.Header.Get(types.HeaderAccessCredential)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	gw, err := ComposeHTTPRoutes([]ExposedHTTPRoute{{Prefix: "/", Upstream: upstream.URL}}, X402Payment{})
	if err != nil {
		t.Fatalf("ComposeHTTPRoutes() error = %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "https://app.example/", nil)
	req.Header.Set(types.HeaderPortalUser, "spoofed-user")
	req.Header.Set(types.HeaderPortalAuth, "spoofed-auth")
	req.Header.Set(types.HeaderAccessCredential, "pcred_spoofed")
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d; want 204", rec.Code)
	}
	if gotUser != "" || gotAuth != "" || gotCredential != "" {
		t.Fatalf("spoofed portal headers reached upstream: user=%q auth=%q credential=%q", gotUser, gotAuth, gotCredential)
	}
}
