package utils

import "testing"

func TestLeaseHostnameMapsLoopbackIPToLocalhost(t *testing.T) {
	t.Parallel()

	got, err := LeaseHostname("bitcoin-rs-explorer-harness", "127.0.0.1")
	if err != nil {
		t.Fatalf("LeaseHostname() error = %v", err)
	}
	if got != "bitcoin-rs-explorer-harness.localhost" {
		t.Fatalf("LeaseHostname() = %q, want bitcoin-rs-explorer-harness.localhost", got)
	}
}

func TestLeaseHostnameKeepsDNSRoot(t *testing.T) {
	t.Parallel()

	got, err := LeaseHostname("app", "example.com")
	if err != nil {
		t.Fatalf("LeaseHostname() error = %v", err)
	}
	if got != "app.example.com" {
		t.Fatalf("LeaseHostname() = %q, want app.example.com", got)
	}
}
