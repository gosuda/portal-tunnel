package utils

import (
	"crypto/tls"
	"net/http"
	"testing"
)

func TestNewHTTPClientTransportIsolation(t *testing.T) {
	t.Parallel()

	a := NewHTTPClient()
	b := NewHTTPClient()

	ta := mustTransportOf(a)
	tb := mustTransportOf(b)

	if ta == tb {
		t.Fatalf("NewHTTPClient() returned clients sharing the same *http.Transport")
	}
	if ta == baseTransport {
		t.Fatalf("NewHTTPClient() transport aliases baseTransport; mutations would leak across all clients")
	}
	if ta == mustTransportOf(DefaultHTTPClient) {
		t.Fatalf("NewHTTPClient() transport aliases DefaultHTTPClient's transport")
	}

	// Mutating one client's transport must not affect the other.
	ta.MaxIdleConns = 7
	if tb.MaxIdleConns == 7 {
		t.Fatalf("mutation on client A leaked into client B (MaxIdleConns)")
	}
}

func TestWithHTTPTLSConfigClonesInput(t *testing.T) {
	t.Parallel()

	original := &tls.Config{ServerName: "before", InsecureSkipVerify: false}
	c := NewHTTPClient(WithHTTPTLSConfig(original))

	// Mutate the caller's config after the option was applied; the transport
	// must not observe the change because WithHTTPTLSConfig clones the input.
	original.ServerName = "after"
	original.InsecureSkipVerify = true

	got := mustTransportOf(c).TLSClientConfig
	if got == original {
		t.Fatalf("WithHTTPTLSConfig stored the caller's *tls.Config by reference")
	}
	if got.ServerName != "before" || got.InsecureSkipVerify {
		t.Fatalf("WithHTTPTLSConfig did not clone tls.Config: got %+v", got)
	}
}

func TestWithHTTPTLSConfigNilClearsTransportConfig(t *testing.T) {
	t.Parallel()

	c := NewHTTPClient(WithHTTPTLSConfig(&tls.Config{ServerName: "x"}))
	WithHTTPTLSConfig(nil)(c)

	if mustTransportOf(c).TLSClientConfig != nil {
		t.Fatalf("WithHTTPTLSConfig(nil) did not clear TLSClientConfig")
	}
}

func TestMustTransportOfPanicsOnForeignTransport(t *testing.T) {
	t.Parallel()

	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("mustTransportOf did not panic on non-*http.Transport RoundTripper")
		}
	}()

	c := &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return nil, nil
	})}
	_ = mustTransportOf(c)
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
