package localtls

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
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
			if client, err := NewClient(t.Context(), ClientConfig{RelayURL: "https://127.0.0.1:1", Hostname: "tenant.test.example", CertFile: certFile, KeyFile: keyFile}); err == nil || errors.Is(err, ErrLocalCertificate) {
				if client != nil {
					client.Close()
				}
				t.Fatalf("runtime validity error = %v, want retryable failure", err)
			}
			if err := ValidateCertificateFiles(certFile, keyFile); !errors.Is(err, ErrLocalCertificate) {
				t.Fatalf("preflight accepted invalid material: %v", err)
			}
		})
	}
}

func TestInstalledCertificateEventsNeverOwnTLSMaterial(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	writeLocalPair(t, certFile, keyFile, tenantHostname)
	events := make(chan []byte, 1)
	client, err := NewClient(t.Context(), ClientConfig{RelayURL: "https://127.0.0.1:1", Hostname: tenantHostname, CertFile: certFile, KeyFile: keyFile, InstalledCertificates: events})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	initial := <-events
	if !bytes.Equal(initial, client.pinned().leaf.Raw) {
		t.Fatal("initial certificate event missing")
	}
	initial[0] ^= 0xff
	if bytes.Equal(initial, client.pinned().leaf.Raw) {
		t.Fatal("observer mutated active certificate")
	}
	writeLocalPair(t, certFile, keyFile, tenantHostname)
	if changed, err := client.RefreshChain(t.Context()); err != nil || !changed {
		t.Fatalf("refresh = %v, %v", changed, err)
	}
	// The undrained observer queue cannot stall another activation.
	writeLocalPair(t, certFile, keyFile, tenantHostname)
	done := make(chan error, 1)
	go func() { _, err := client.RefreshChain(t.Context()); done <- err }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("observer blocked activation")
	}
}

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

	_ = visitor.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := visitor.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("expired connection was not closed: %v", err)
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

func TestLocalTLSALPNAndSNI(t *testing.T) {
	const hostname = "blog.0123456789abcdef0123456789abcdef01234567.example"
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	writeLocalPair(t, certFile, keyFile, hostname)
	client, err := NewClient(t.Context(), ClientConfig{RelayURL: "https://127.0.0.1:1", Hostname: hostname, CertFile: certFile, KeyFile: keyFile})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	for _, tc := range []struct {
		name, sni, want string
		protos          []string
	}{
		{name: "h1 default", sni: hostname, want: "http/1.1"},
		{name: "mixed-case canonical", sni: strings.ToUpper(hostname), want: "http/1.1"},
		{name: "h2 enabled consumer", sni: hostname, want: "h2", protos: []string{"h2", "http/1.1"}},
		{name: "sibling SNI", sni: "api.0123456789abcdef0123456789abcdef01234567.example", protos: []string{"h2", "http/1.1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.protos != nil {
				client.SetNextProtos(tc.protos)
			}
			raw, server := net.Pipe()
			defer raw.Close()
			defer server.Close()
			config := client.TenantTLSConfig()
			config.ServerName = tc.sni
			config.NextProtos = []string{"h2", "http/1.1"}
			visitor := tls.Client(raw, config)
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- visitor.HandshakeContext(ctx) }()
			conn, serverErr := client.TerminateConn(ctx, server, nil)
			visitorErr := <-done
			if tc.want == "" {
				if serverErr == nil || visitorErr == nil {
					t.Fatal("sibling SNI accepted")
				}
				return
			}
			if serverErr != nil || visitorErr != nil {
				t.Fatalf("handshake: %v, %v", serverErr, visitorErr)
			}
			native, ok := conn.(*tls.Conn)
			if !ok {
				t.Fatal("not native TLS")
			}
			if native.ConnectionState().NegotiatedProtocol != tc.want {
				t.Fatalf("ALPN = %q", native.ConnectionState().NegotiatedProtocol)
			}
		})
	}
}

func TestUnavailableLocalTLSClosesWithoutFallback(t *testing.T) {
	client := &Client{hostname: "service.example"}
	raw, server := net.Pipe()
	defer raw.Close()
	defer server.Close()
	if _, err := client.TerminateConn(t.Context(), server, nil); err == nil {
		t.Fatal("missing local certificate accepted")
	}
	_ = raw.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := raw.Read(make([]byte, 1)); err == nil {
		t.Fatal("unavailable connection left open")
	}
}

func TestLocalTLSReadinessTracksValidity(t *testing.T) {
	client := &Client{}
	if client.Ready() {
		t.Fatal("missing certificate reported ready")
	}
	now := time.Now()
	client.pin = &pinnedChain{leaf: &x509.Certificate{NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Minute)}}
	if !client.Ready() {
		t.Fatal("usable certificate reported unavailable")
	}
	client.pin.leaf.NotAfter = now.Add(-time.Second)
	if client.Ready() {
		t.Fatal("expired certificate reported ready")
	}
	client.pin.leaf.NotAfter = now.Add(time.Minute)
	client.Close()
	if client.Ready() {
		t.Fatal("closed client reported ready")
	}
}

const tenantHostname = "tenant.test.example"

func mustSelfSignedCert(t *testing.T, hostname string, ips []net.IP) (*ecdsa.PrivateKey, []byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ecdsa key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: hostname},
		DNSNames:              []string{hostname},
		IPAddresses:           ips,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return key, der, certPEM
}
