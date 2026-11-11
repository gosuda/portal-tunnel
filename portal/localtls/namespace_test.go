package localtls

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"path/filepath"
	"testing"
	"time"
)

func TestCanonicalCertificateRejectsSharedSANs(t *testing.T) {
	const hostname = "blog.0123456789abcdef0123456789abcdef01234567.example"
	for _, names := range [][]string{{hostname, "api.0123456789abcdef0123456789abcdef01234567.example"}, {"*.0123456789abcdef0123456789abcdef01234567.example"}} {
		key, der, _ := mustSelfSignedCert(t, hostname, nil)
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		cert.DNSNames = names
		der, err = x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		keyDER, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		_, err = newLocalPin(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), hostname)
		if !errors.Is(err, ErrLocalCertificate) {
			t.Fatalf("shared/wildcard SAN accepted: %v", err)
		}
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
