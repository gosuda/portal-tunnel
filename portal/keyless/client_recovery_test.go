package keyless

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestExpiredRelayCertificateRecovers(t *testing.T) {
	for _, automatic := range []bool{false, true} {
		name := "relay"
		if automatic {
			name = "automatic-bootstrap"
		}
		t.Run(name, func(t *testing.T) {
			issuer := newTestIssuer(t)
			expired := issuer.issue(t, 2)
			expired.leaf.NotBefore = time.Now().Add(-2 * time.Hour)
			expired.leaf.NotAfter = time.Now().Add(-time.Hour)
			der, err := x509.CreateCertificate(rand.Reader, expired.leaf, issuer.cert, expired.leaf.PublicKey, issuer.key)
			if err != nil {
				t.Fatal(err)
			}
			expired.leaf, err = x509.ParseCertificate(der)
			if err != nil {
				t.Fatal(err)
			}
			expired.tls.Certificate[0] = der
			relay := newRelayStandIn(t, expired)
			client := relay.newClient(t)
			if automatic {
				client.automatic = &automaticSource{relaySource: client.relay, certificateDir: t.TempDir()}
				// Expired bootstrap recovery must not wait behind issuance.
				client.refreshMu.Lock()
				defer client.refreshMu.Unlock()
			}
			renewed := issuer.issue(t, 3)
			relay.renew(renewed, true)
			if _, err := relay.visit(t, client, issuer.pool); !errors.Is(err, errTenantCertificateNotValid) {
				t.Fatalf("expired handshake = %v, want the expired generation refused", err)
			}
			if leaf, err := relay.visit(t, client, issuer.pool); err != nil || !leaf.Equal(renewed.leaf) {
				t.Fatalf("next handshake: leaf %v, error %v; want the renewed certificate", leaf, err)
			}
		})
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

func TestExpiredAutomaticLocalCertificateNeverDowngrades(t *testing.T) {
	issuer := newTestIssuer(t)
	relay := newRelayStandIn(t, issuer.issue(t, 2))
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	writeLocalPair(t, certFile, keyFile, tenantHostname)
	client, err := NewClient(t.Context(), ClientConfig{
		RelayURL: relay.url, Hostname: tenantHostname, CertFile: certFile, KeyFile: keyFile,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.automatic = &automaticSource{relaySource: client.relay, certificateDir: t.TempDir()}
	client.pin.leaf.NotAfter = time.Now().Add(-time.Second)
	// The relay can sign, but its issuance endpoint is unavailable. Neither the
	// first expiry rejection nor the next connection may restore relay signing.
	for range 2 {
		if _, err := relay.visit(t, client, issuer.pool); !errors.Is(err, errTenantCertificateNotValid) {
			t.Fatalf("expired local handshake = %v, want fail-closed rejection", err)
		}
	}
	if relay.issuanceRequests.Load() != 0 {
		t.Fatal("incoming connections triggered automatic certificate issuance")
	}
}

func TestTenantProbeAcrossLocalActivationTrustsOnlyRetiredLeaf(t *testing.T) {
	issuer := newTestIssuer(t)
	bootstrap := issuer.issue(t, 2)
	relay := newRelayStandIn(t, bootstrap)
	client := relay.newClient(t)
	probe := client.TenantTLSConfig()

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	visitorRaw, tenantRaw := net.Pipe()
	defer visitorRaw.Close()
	defer tenantRaw.Close()
	gate := &pausedTenantWrite{Conn: tenantRaw, started: make(chan struct{}), resume: make(chan struct{})}
	defer func() {
		select {
		case <-gate.resume:
		default:
			close(gate.resume)
		}
	}()
	binding := relay.bindings.Issue("lease", nil)
	visitor := tls.Client(relay.bindings.FixHelloOnWrite(visitorRaw, binding), probe)
	visitorDone, tenantDone := make(chan error, 1), make(chan error, 1)
	go func() { visitorDone <- visitor.HandshakeContext(ctx) }()
	go func() { _, err := client.TerminateConn(ctx, gate, binding[:]); tenantDone <- err }()
	select {
	case <-gate.started:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}

	client.automatic = &automaticSource{relaySource: client.relay, certificateDir: t.TempDir()}
	certFile, keyFile := filepath.Join(client.automatic.certificateDir, "cert.pem"), filepath.Join(client.automatic.certificateDir, "key.pem")
	certPEM := writeLocalPair(t, certFile, keyFile, tenantHostname)
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.automatic.saveBundle(certificateBundle{Hostname: tenantHostname, CertificatePEM: string(certPEM), KeyPEM: string(keyPEM)}); err != nil {
		t.Fatal(err)
	}
	if changed, err := client.RefreshChain(ctx); err != nil || !changed {
		t.Fatalf("local activation = %v, %v", changed, err)
	}
	close(gate.resume)
	if err := <-visitorDone; err != nil {
		t.Fatalf("probe crossing local activation: %v", err)
	}
	if err := <-tenantDone; err != nil {
		t.Fatalf("tenant handshake crossing local activation: %v", err)
	}
	if !visitor.ConnectionState().PeerCertificates[0].Equal(bootstrap.leaf) {
		t.Fatal("in-flight handshake switched certificate generation")
	}
	sibling := issuer.issue(t, 3)
	if err := probe.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{sibling.leaf, issuer.cert}}); err == nil {
		t.Fatal("probe trusted an uninstalled certificate from the retired relay issuer")
	}
}
