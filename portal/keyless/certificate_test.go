package keyless

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAutomaticCertificateState(t *testing.T) {
	const hostname = "tenant.test.example"
	dir := t.TempDir()
	client := &Client{hostname: hostname, certificateDir: dir, relayURL: "https://127.0.0.1:1", serverName: "127.0.0.1"}
	// Failed initial issuance keeps its generated key for the next attempt.
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if _, err := client.automaticPin(ctx); err == nil {
		t.Fatal("unreachable issuer succeeded")
	}
	pending, err := client.readBundle()
	if err != nil {
		t.Fatal(err)
	}
	if pending.CertificatePEM != "" || pending.KeyPEM == "" {
		t.Fatal("pending key not persisted")
	}
	if _, err := client.automaticPin(ctx); err == nil {
		t.Fatal("unreachable issuer succeeded")
	}
	retried, err := client.readBundle()
	if err != nil {
		t.Fatal(err)
	}
	if retried.KeyPEM != pending.KeyPEM {
		t.Fatal("retry replaced pending private key")
	}

	certFile, keyFile := filepath.Join(dir, "test.pem"), filepath.Join(dir, "test.key")
	cert := writeLocalPair(t, certFile, keyFile, hostname)
	key, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.saveBundle(certificateBundle{Hostname: hostname, KeyPEM: string(key), CertificatePEM: string(cert)}); err != nil {
		t.Fatal(err)
	}
	// A restart with persisted usable material has no dependency on the issuer.
	restarted, err := NewClient(t.Context(), ClientConfig{RelayURL: client.relayURL, Hostname: hostname, CertificateDir: dir, RequireLocal: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.WaitReady(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(restarted.pinned().chainPEM, cert) {
		t.Fatal("restart did not reuse certificate")
	}
	if err := restarted.Close(); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(client.bundlePath(), []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, requireLocal := range []bool{false, true} {
		if got, err := NewClient(t.Context(), ClientConfig{RelayURL: client.relayURL, Hostname: hostname, CertificateDir: dir, RequireLocal: requireLocal}); err == nil {
			got.Close()
			t.Fatal("corrupt state silently selected bootstrap")
		}
	}
}

func TestAutomaticCertificateRequireLocalReadiness(t *testing.T) {
	client, err := NewClient(t.Context(), ClientConfig{RelayURL: "https://127.0.0.1:1", Hostname: "tenant.test.example", CertificateDir: t.TempDir(), RequireLocal: true})
	if err != nil {
		t.Fatal(err)
	}
	if client.pinned() != nil {
		t.Fatal("require-local bootstrapped relay signer")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := client.WaitReady(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("readiness = %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if err := client.WaitReady(t.Context()); err == nil {
		t.Fatal("closed unready client became ready")
	}
}

func TestCertificateIssuanceLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "certificate.lock")
	first, err := lockCertificate(path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if second, err := lockCertificate(path); !errors.Is(err, errAutomaticCertificateBusy) {
		if second != nil {
			second.Close()
		}
		t.Fatalf("concurrent issuer lock = %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	// Persistent lock file is not stale ownership after its descriptor closes.
	next, err := lockCertificate(path)
	if err != nil {
		t.Fatal(err)
	}
	next.Close()
}

func TestExpiredAutomaticCertificateDoesNotBootstrap(t *testing.T) {
	const hostname = "tenant.test.example"
	dir := t.TempDir()
	key, der, _ := mustSelfSignedCert(t, hostname, nil)
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	cert.NotBefore = time.Now().Add(-2 * time.Hour)
	cert.NotAfter = time.Now().Add(-time.Hour)
	der, err = x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	owner := &Client{hostname: hostname, certificateDir: dir}
	if err := owner.saveBundle(certificateBundle{
		Hostname:       hostname,
		KeyPEM:         string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})),
		CertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
	}); err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(t.Context(), ClientConfig{RelayURL: "https://127.0.0.1:1", Hostname: hostname, CertificateDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if client.pinned() != nil {
		t.Fatal("expired persisted certificate restored relay signing")
	}
}

func TestAutomaticBootstrapRefreshDuringIssuanceOutage(t *testing.T) {
	issuer := newTestIssuer(t)
	before, renewed := issuer.issue(t, 2), issuer.issue(t, 3)
	relay := newRelayStandIn(t, before)
	client := relay.newClient(t)
	// The shared refresh owner also operates during automatic bootstrap.
	client.certificateDir = t.TempDir()
	relay.renew(renewed, true)
	changed, err := client.RefreshChain(t.Context())
	if err == nil || !changed {
		t.Fatalf("legacy issuance endpoint: changed=%v error=%v", changed, err)
	}
	leaf, err := relay.visit(t, client, issuer.pool)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(leaf.Raw, renewed.leaf.Raw) {
		t.Fatal("bootstrap did not adopt renewed relay material")
	}
}

func TestAutomaticCertificateRejectsAlias(t *testing.T) {
	client, err := NewClient(t.Context(), ClientConfig{
		RelayURL: "https://127.0.0.1:1", Hostname: "tenant.test.example",
		AlternativeHostname: "alias.test.example", CertificateDir: t.TempDir(),
	})
	if !errors.Is(err, errAutomaticCanonicalHostnameOnly) {
		if client != nil {
			client.Close()
		}
		t.Fatalf("automatic alias configuration = %v", err)
	}
}

func TestStaleBootstrapRecoveryDoesNotWaitForIssuance(t *testing.T) {
	issuer := newTestIssuer(t)
	relay := newRelayStandIn(t, issuer.issue(t, 2))
	client := relay.newClient(t)
	client.certificateDir = t.TempDir()
	stale := client.pinned()
	renewed := issuer.issue(t, 3)
	relay.renew(renewed, true)
	// Issuance owns refreshMu until its potentially long network timeout.
	// Stale TLS recovery must remain independent of that operation.
	client.refreshMu.Lock()
	defer client.refreshMu.Unlock()
	changed, err := client.refreshChain(t.Context(), stale)
	if err != nil || !changed {
		t.Fatalf("stale bootstrap recovery = %v, %v", changed, err)
	}
	// The issuing endpoint is absent, so success proves it was not called.
	leaf, err := relay.visit(t, client, issuer.pool)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(leaf.Raw, renewed.leaf.Raw) {
		t.Fatal("stale bootstrap retained old certificate")
	}
	if _, err := os.Stat(client.bundlePath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale recovery touched issuance state: %v", err)
	}
}
