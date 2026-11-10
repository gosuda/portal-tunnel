package keyless

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func writeLocalPair(t *testing.T, certFile, keyFile, hostname string) []byte {
	t.Helper()
	key, _, certPEM := mustSelfSignedCert(t, hostname, nil)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatal(err)
	}
	return certPEM
}

func TestLocalTenantTLSReplacement(t *testing.T) {
	const hostname = "tenant.test.example"
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	first := writeLocalPair(t, certFile, keyFile, hostname)
	// An unreachable relay proves the local path neither fetches relay material
	// nor calls /v1/sign.
	client, err := NewClient(t.Context(), ClientConfig{RelayURL: "https://127.0.0.1:1", Hostname: hostname, CertFile: certFile, KeyFile: keyFile})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	probeConfig := client.TenantTLSConfig()

	connect := func(config *tls.Config) (*tls.Conn, net.Conn) {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		raw, server := net.Pipe()
		visitor := tls.Client(raw, config)
		result := make(chan error, 1)
		go func() { result <- visitor.HandshakeContext(ctx) }()
		tenant, err := client.TerminateConn(ctx, server, nil)
		if err != nil {
			raw.Close()
			server.Close()
			t.Fatal(err)
		}
		if err := <-result; err != nil {
			t.Fatal(err)
		}
		// Avoid close_notify blocking on net.Pipe during cleanup.
		t.Cleanup(func() { raw.Close(); server.Close() })
		state := visitor.ConnectionState()
		a, err := state.ExportKeyingMaterial("Portal-MITM-Probe-v1", nil, 32)
		if err != nil {
			t.Fatal(err)
		}
		b, err := tenant.(interface {
			ExportKeyingMaterial(string, []byte, int) ([]byte, error)
		}).ExportKeyingMaterial("Portal-MITM-Probe-v1", nil, 32)
		if err != nil || !bytes.Equal(a, b) {
			t.Fatalf("exporter mismatch: %v", err)
		}
		return visitor, tenant
	}
	oldVisitor, oldTenant := connect(probeConfig)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	raw, server := net.Pipe()
	t.Cleanup(func() { raw.Close(); server.Close() })
	gate := &pausedTenantWrite{Conn: server, started: make(chan struct{}), resume: make(chan struct{})}
	inflightVisitor := tls.Client(raw, probeConfig)
	visitorResult := make(chan error, 1)
	tenantResult := make(chan error, 1)
	go func() { visitorResult <- inflightVisitor.HandshakeContext(ctx) }()
	go func() { _, err := client.TerminateConn(ctx, gate, nil); tenantResult <- err }()
	select {
	case <-gate.started:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	second := writeLocalPair(t, certFile, keyFile, hostname)
	if changed, err := client.RefreshChain(t.Context()); err != nil || !changed {
		t.Fatalf("rotation: %v %v", changed, err)
	}
	close(gate.resume)
	if err := <-visitorResult; err != nil {
		t.Fatal(err)
	}
	if err := <-tenantResult; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(inflightVisitor.ConnectionState().PeerCertificates[0].Raw, oldVisitor.ConnectionState().PeerCertificates[0].Raw) {
		t.Fatal("in-flight handshake changed certificate generation")
	}
	newVisitor, _ := connect(probeConfig) // configuration captured before rotation
	if bytes.Equal(oldVisitor.ConnectionState().PeerCertificates[0].Raw, newVisitor.ConnectionState().PeerCertificates[0].Raw) {
		t.Fatal("new handshake did not adopt replacement")
	}
	// Existing application traffic survives replacement.
	done := make(chan error, 1)
	go func() { _, err := oldTenant.Write([]byte("ok")); done <- err }()
	data := make([]byte, 2)
	if _, err := oldVisitor.Read(data); err != nil || string(data) != "ok" {
		t.Fatalf("old connection: %q %v", data, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if changed, err := client.RefreshChain(t.Context()); err == nil || changed {
		t.Fatal("corrupt replacement accepted")
	}
	connect(probeConfig)
	// Both installed generations remain verifiable, but an unrelated key does not.
	for _, material := range [][]byte{first, second} {
		block, _ := pem.Decode(material)
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		if err := probeConfig.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{hostname, "wrong.test.example"} {
		_, _, unrelated := mustSelfSignedCert(t, name, nil)
		block, _ := pem.Decode(unrelated)
		cert, _ := x509.ParseCertificate(block.Bytes)
		if err := probeConfig.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}); err == nil {
			t.Fatal("uninstalled certificate accepted")
		}
	}
	if _, err := NewClient(t.Context(), ClientConfig{RelayURL: "https://127.0.0.1:1", Hostname: hostname, CertFile: certFile, KeyFile: keyFile}); err == nil {
		t.Fatal("restart with corrupt key accepted")
	}
}

func TestLocalTenantCertificateValidation(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	writeLocalPair(t, certFile, keyFile, "tenant.test.example")
	for _, config := range []ClientConfig{
		{Hostname: "tenant.test.example", CertFile: certFile},
		{Hostname: "tenant.test.example", CertFile: " ", KeyFile: " "},
		{Hostname: "other.test.example", CertFile: certFile, KeyFile: keyFile},
		{Hostname: "tenant.test.example", AlternativeHostname: "alias.test.example", CertFile: certFile, KeyFile: keyFile},
	} {
		config.RelayURL = "https://127.0.0.1:1"
		if client, err := NewClient(t.Context(), config); err == nil {
			client.Close()
			t.Fatal("invalid configuration accepted")
		}
	}
	otherCert, otherKey := filepath.Join(dir, "other.pem"), filepath.Join(dir, "other-key.pem")
	writeLocalPair(t, otherCert, otherKey, "tenant.test.example")
	if client, err := NewClient(t.Context(), ClientConfig{RelayURL: "https://127.0.0.1:1", Hostname: "tenant.test.example", CertFile: certFile, KeyFile: otherKey}); err == nil {
		client.Close()
		t.Fatal("mismatched key accepted")
	}
}

type pausedTenantWrite struct {
	net.Conn
	once    sync.Once
	started chan struct{}
	resume  chan struct{}
}

func (c *pausedTenantWrite) Write(p []byte) (int, error) {
	c.once.Do(func() { close(c.started); <-c.resume })
	return c.Conn.Write(p)
}

func TestLocalTenantCertificateValidityAndAlgorithm(t *testing.T) {
	for _, tc := range []struct {
		name          string
		curve         elliptic.Curve
		before, after time.Time
	}{
		{"expired", elliptic.P256(), time.Now().Add(-2 * time.Hour), time.Now().Add(-time.Hour)},
		{"future", elliptic.P256(), time.Now().Add(time.Hour), time.Now().Add(2 * time.Hour)},
		{"unsupported-curve", elliptic.P384(), time.Now().Add(-time.Hour), time.Now().Add(time.Hour)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
			key, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"tenant.test.example"}, NotBefore: tc.before, NotAfter: tc.after, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
			der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
			if err != nil {
				t.Fatal(err)
			}
			keyDER, err := x509.MarshalPKCS8PrivateKey(key)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
				t.Fatal(err)
			}
			if client, err := NewClient(t.Context(), ClientConfig{RelayURL: "https://127.0.0.1:1", Hostname: "tenant.test.example", CertFile: certFile, KeyFile: keyFile}); err == nil {
				client.Close()
				t.Fatal("invalid material accepted")
			}
		})
	}
}

func TestExpiredLocalCertificateClosesConnection(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	writeLocalPair(t, certFile, keyFile, "tenant.test.example")
	client, err := NewClient(t.Context(), ClientConfig{RelayURL: "https://127.0.0.1:1", Hostname: "tenant.test.example", CertFile: certFile, KeyFile: keyFile})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.pin.leaf.NotAfter = time.Now().Add(-time.Second)
	visitor, raw := net.Pipe()
	defer visitor.Close()
	defer raw.Close()
	if _, err := client.TerminateConn(t.Context(), raw, nil); err == nil {
		t.Fatal("expired certificate served")
	}
	_ = visitor.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := visitor.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("raw connection was not closed: %v", err)
	}
}
