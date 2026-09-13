package e2e_test

import (
	"crypto/tls"
	"errors"
	"net"
	"net/url"
	"testing"
	"time"
)

func TestTunnelRemainsUsableAfterFailedTenantHandshake(t *testing.T) {
	h := newHarness(t)
	publicURL := h.waitForPublicURL()
	parsed, err := url.Parse(publicURL)
	if err != nil {
		t.Fatalf("parse public URL: %v", err)
	}

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

	if got := h.get(publicURL); got != marker {
		t.Fatalf("tenant response after failed handshake = %q, want %q", got, marker)
	}
}
