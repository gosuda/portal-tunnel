package e2e_test

import (
	"crypto/tls"
	"errors"
	"net"
	"net/url"
	"testing"
	"time"
)

func TestReverseConnectionRecoversAfterFailedTenantHandshake(t *testing.T) {
	h := newHarness(t)
	publicURL := h.waitForPublicURL()
	parsed, err := url.Parse(publicURL)
	if err != nil {
		t.Fatalf("parse public URL: %v", err)
	}

	initialLease := h.server.PublicLeases()[0]
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", h.sniAddr, &tls.Config{
		ServerName: parsed.Hostname(),
		MinVersion: tls.VersionTLS12,
	})
	if err == nil {
		_ = conn.Close()
		t.Fatal("untrusted tenant TLS handshake unexpectedly succeeded")
	}
	var verificationErr *tls.CertificateVerificationError
	if !errors.As(err, &verificationErr) {
		t.Fatalf("tenant TLS handshake error = %v, want certificate verification failure", err)
	}

	h.eventually(func() bool {
		leases := h.server.PublicLeases()
		return len(leases) == 1 && leases[0].Ready >= 2 && leases[0].LastSeenAt.After(initialLease.LastSeenAt)
	}, "reverse sessions were not replenished")
	if got := h.get(publicURL); got != marker {
		t.Fatalf("tenant response after reconnect = %q, want %q", got, marker)
	}
}
