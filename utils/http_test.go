package utils

import (
	"crypto/tls"
	"net/http"
	"slices"
	"testing"
)

// Every HTTP client owns its mutable transport state: clients never share a
// *http.Transport, and a caller's *tls.Config is cloned so later mutations by
// the caller cannot leak into an already-built client.
func TestNewHTTPClientOwnsItsMutableState(t *testing.T) {
	t.Parallel()

	original := &tls.Config{ServerName: "before"}
	a := NewHTTPClient(WithHTTPTLSConfig(original))
	b := NewHTTPClient()

	ta := mustTransportOf(a)
	tb := mustTransportOf(b)
	if ta == tb || ta == baseTransport || ta == mustTransportOf(DefaultHTTPClient) {
		t.Fatal("NewHTTPClient() returned a client sharing a *http.Transport")
	}

	ta.MaxIdleConns = 7
	if tb.MaxIdleConns == 7 {
		t.Fatal("mutation on client A leaked into client B (MaxIdleConns)")
	}

	original.ServerName = "after"
	original.InsecureSkipVerify = true
	got := ta.TLSClientConfig
	if got == original || got.ServerName != "before" || got.InsecureSkipVerify {
		t.Fatalf("WithHTTPTLSConfig did not clone the caller's tls.Config: got %+v", got)
	}
}

// A gateway that reads underscores as hyphens takes X_Portal_User for
// X-Portal-User, so every such spelling goes with the header and nothing else does.
func TestDelHeaderSpellings(t *testing.T) {
	t.Parallel()

	h := http.Header{
		"X-Portal-User":  {"a"},
		"X_Portal_User":  {"b"},
		"X_portal_user":  {"c"}, // how net/http keeps it after reading it from a connection
		"x-portal-user":  {"d"},
		"X-Portal-Auth":  {"e"},
		"X_Portal_Other": {"f"},
		"X-Portal-User2": {"g"},
		"X-Keep":         {"h"},
		"X_Keep":         {"i"},
	}
	DelHeaderSpellings(h, "X-Portal-User", "x_portal_auth")

	var left []string
	for key := range h {
		left = append(left, key)
	}
	slices.Sort(left)
	want := []string{"X-Keep", "X-Portal-User2", "X_Keep", "X_Portal_Other"}
	if !slices.Equal(left, want) {
		t.Fatalf("headers left = %q; want %q", left, want)
	}

	DelHeaderSpellings(h)
	DelHeaderSpellings(nil, "X-Keep")
	if len(h) != len(want) {
		t.Fatalf("deleting no names changed the headers: %q", h)
	}
}
