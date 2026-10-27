package gateway

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/gosuda/portal-tunnel/v2/types"
)

// portalHeaderNames lists the headers of h that a gateway reading underscores as
// hyphens takes for a Portal header, in whatever spelling they arrived.
func portalHeaderNames(h http.Header) []string {
	var names []string
	for key := range h {
		if strings.HasPrefix(strings.ToLower(strings.ReplaceAll(key, "_", "-")), "x-portal-") {
			names = append(names, key)
		}
	}
	slices.Sort(names)
	return names
}

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
	// The underscore spelling goes too: CGI-style upstreams read it as the same header.
	req3 := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	req3.Header["X_custom"] = []string{"secret"}
	req3.Header["X_keep"] = []string{"keep"}
	handler.ServeHTTP(httptest.NewRecorder(), req3)
	if _, ok := gotHeaders["X_custom"]; ok {
		t.Fatal("X_custom forwarded after the strip of X-Custom")
	}
	if _, ok := gotHeaders["X_keep"]; !ok {
		t.Fatal("X_keep removed, but nothing asked for X-Keep to be stripped")
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
	var gotUser, gotAuth, gotProof, gotCredential string
	var gotPortalNames []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPortalNames = portalHeaderNames(r.Header)
		gotUser = r.Header.Get(types.HeaderPortalUser)
		gotAuth = r.Header.Get(types.HeaderPortalAuth)
		gotProof = r.Header.Get(types.HeaderPortalProof)
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
	req.Header.Set(types.HeaderPortalProof, "spoofed-proof")
	req.Header.Set(types.HeaderAccessCredential, "pcred_spoofed")
	// The same headers spelled with underscores, which a CGI-style upstream reads as these.
	for _, name := range []string{"X_Portal_User", "X_portal_auth", "x_portal_proof", "X_Portal_Access_Credential"} {
		req.Header[name] = []string{"spoofed"}
	}
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d; want 204", rec.Code)
	}
	if gotUser != "" || gotAuth != "" || gotProof != "" || gotCredential != "" {
		t.Fatalf("spoofed portal headers reached upstream: user=%q auth=%q proof=%q credential=%q", gotUser, gotAuth, gotProof, gotCredential)
	}
	if len(gotPortalNames) != 0 {
		t.Fatalf("spoofed portal headers reached upstream under other spellings: %q", gotPortalNames)
	}
}
