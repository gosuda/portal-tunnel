package utils

import "testing"

func TestNormalizeRelayURLRewritesLoopbackHTTP(t *testing.T) {
	t.Parallel()

	got, err := NormalizeRelayURL("http://127.0.0.1:14017")
	if err != nil {
		t.Fatalf("NormalizeRelayURL(loopback http) error = %v", err)
	}
	if got != "https://127.0.0.1:14017" {
		t.Fatalf("NormalizeRelayURL(loopback http) = %q, want https://127.0.0.1:14017", got)
	}
}

func TestNormalizeRelayURLRejectsNonLoopbackHTTP(t *testing.T) {
	t.Parallel()

	_, err := NormalizeRelayURL("http://relay.example")
	if err == nil {
		t.Fatal("NormalizeRelayURL(non-loopback http) error = nil, want https required")
	}
}
