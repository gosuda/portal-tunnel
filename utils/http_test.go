package utils

import (
	"crypto/tls"
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
