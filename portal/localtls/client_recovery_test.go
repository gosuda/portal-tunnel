package localtls

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"path/filepath"
	"testing"
	"time"
)

func TestExpiredManualCertificateReloadsReplacement(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	writeLocalPair(t, certFile, keyFile, tenantHostname)
	client, err := NewClient(t.Context(), ClientConfig{
		RelayURL: "https://127.0.0.1:1", Hostname: tenantHostname, CertFile: certFile, KeyFile: keyFile,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	probe := client.TenantTLSConfig()
	client.pin.leaf.NotAfter = time.Now().Add(-time.Second)
	writeLocalPair(t, certFile, keyFile, tenantHostname)

	visitor, raw := net.Pipe()
	defer visitor.Close()
	defer raw.Close()
	if _, err := client.TerminateConn(t.Context(), raw, nil); !errors.Is(err, errTenantCertificateNotValid) {
		t.Fatalf("expired handshake = %v, want the expired generation refused", err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	visitor, raw = net.Pipe()
	defer visitor.Close()
	defer raw.Close()
	connection := tls.Client(visitor, probe)
	done := make(chan error, 1)
	go func() { done <- connection.HandshakeContext(ctx) }()
	if _, err := client.TerminateConn(ctx, raw, nil); err != nil {
		t.Fatalf("next handshake did not use replacement files: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
