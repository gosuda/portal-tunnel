package utils

import (
	"crypto/tls"
	"net/http"
	"slices"
	"testing"
)

func TestNewHTTPClientOwnsItsMutableState(t *testing.T) {
	t.Parallel()

	original := &tls.Config{ServerName: "before"}
	a := NewHTTPClient(WithHTTPTLSConfig(original))
	b := NewHTTPClient()

	ta := a.Transport.(*http.Transport)
	tb := b.Transport.(*http.Transport)
	if ta == tb || ta == baseTransport || ta == DefaultHTTPClient.Transport.(*http.Transport) {
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

func TestDelHeaderSpellings(t *testing.T) {
	t.Parallel()

	h := http.Header{
		"X-Portal-User":  {"a"},
		"X_Portal_User":  {"b"},
		"X_portal_user":  {"c"},
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
