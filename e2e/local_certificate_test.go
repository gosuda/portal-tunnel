package e2e_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/portal/keyless"
	"github.com/gosuda/portal-tunnel/v2/sdk"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func writeTenantCertificate(t *testing.T, hostnames ...string) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(762),
		Subject:      pkix.Name{CommonName: "local tenant test"},
		DNSNames:     hostnames,
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "tenant.pem"), filepath.Join(dir, "tenant.key")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

// A certificate unrelated to the relay's certificate must work through the
// real relay, exposure, tenant TLS engine, and exporter self-probe.
func TestLocalTenantCertificate(t *testing.T) {
	certFile, keyFile := writeTenantCertificate(t, "*.localhost", "*.127.0.0.1")
	logs := captureSDKLogs(t)
	h := newHarness(t, sdk.WithTLSCertificate(certFile, keyFile), sdk.WithMITMProtection(true))
	publicURL := h.waitForPublicURL()
	if body, ok := tenantGet(h.sniAddr, certFile, publicURL); !ok || body != marker {
		t.Fatalf("local certificate tenant response = %q, success %v", body, ok)
	}
	if _, ok := tenantGet(h.sniAddr, h.certificate, publicURL); ok {
		t.Fatal("tenant unexpectedly used relay certificate")
	}
	deadline := time.Now().Add(20 * time.Second)
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for !logs.contains("tls passthrough self-probe passed") {
		if time.Now().After(deadline) {
			t.Fatalf("local tenant exporter probe failed: %s", logs.snapshot())
		}
		<-tick.C
	}
}

func TestLocalTenantCertificateWrongHostnameFailsReady(t *testing.T) {
	certFile, keyFile := writeTenantCertificate(t, "other.example")
	h := newHarness(t, sdk.WithTLSCertificate(certFile, keyFile))
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	_, err := h.exposure.WaitReady(ctx)
	var hostnameErr x509.HostnameError
	if !errors.Is(err, keyless.ErrLocalCertificate) || !errors.As(err, &hostnameErr) {
		t.Fatalf("WaitReady() = %v, want local hostname error", err)
	}
	statuses := h.exposure.Relays()
	if len(statuses) != 1 || statuses[0].State != sdk.RelayFailed || statuses[0].Failure != sdk.RelayFailureTerminal {
		t.Fatalf("wrong-hostname relay status = %+v", statuses)
	}
	if leases := h.server.PublicLeases(); len(leases) != 0 {
		t.Fatalf("invalid certificate retained a relay lease: %+v", leases)
	}
	publicURL := "https://" + net.JoinHostPort(hostnameErr.Host, strconv.Itoa(h.sniPort))
	if _, ok := tenantGet(h.sniAddr, h.certificate, publicURL); ok {
		t.Fatal("invalid manual certificate fell back to relay signing")
	}
}

func TestLocalTenantCertificateKeepsCoveredRelays(t *testing.T) {
	// The first relay's existing lease owns the friendly alias, so our local
	// certificate only needs the canonical name there. The second relay offers
	// the alias too; that relay alone must fail when the pair does not cover it.
	h := newHarness(t)
	h.waitForPublicURL()
	other := newHarnessWithName(t, "other", "127.0.0.1", "")
	other.waitForPublicURL()
	clientIdentity, err := identity.Generate("e2e")
	if err != nil {
		t.Fatal(err)
	}
	hostname, err := utils.CanonicalLeaseHostname(clientIdentity.Name, clientIdentity.Address, "localhost")
	if err != nil {
		t.Fatal(err)
	}
	certFile, keyFile := writeTenantCertificate(t, hostname)
	exposure, err := sdk.Expose(t.Context(), clientIdentity, []string{"https://" + h.sniAddr}, sdk.WithTLSCertificate(certFile, keyFile))
	if err != nil {
		t.Fatal(err)
	}
	proxyDone := make(chan error, 1)
	go func() { proxyDone <- sdk.Proxy(t.Context(), exposure, h.service.Listener.Addr().String()) }()
	t.Cleanup(func() {
		_ = exposure.Close()
		select {
		case err := <-proxyDone:
			if err != nil && !errors.Is(err, context.Canceled) {
				t.Error(err)
			}
		case <-time.After(5 * time.Second):
			t.Error("proxy did not stop")
		}
	})
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	ready, err := exposure.WaitReady(ctx)
	if err != nil || len(ready) != 1 || ready[0].AliasURL != "" {
		t.Fatalf("canonical-only local relay: %+v, %v", ready, err)
	}
	publicURL := ready[0].PublicURL
	badURL := "https://" + other.sniAddr
	if err := exposure.AddRelay(badURL); err != nil {
		t.Fatal(err)
	}
	for {
		var failed bool
		for _, status := range exposure.Relays() {
			if status.RelayURL == badURL && status.State == sdk.RelayFailed {
				var hostnameErr x509.HostnameError
				if status.Failure != sdk.RelayFailureTerminal || !errors.As(status.Err, &hostnameErr) {
					t.Fatalf("uncovered relay failure = %+v", status)
				}
				failed = true
			}
		}
		if failed {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatalf("uncovered relay did not fail: %+v", exposure.Relays())
		case <-exposure.Updates():
		}
	}
	ready, err = exposure.WaitReady(ctx)
	if err != nil || len(ready) != 1 || ready[0].PublicURL != publicURL {
		t.Fatalf("covered relay lost readiness: %+v, %v", ready, err)
	}
	if body, ok := tenantGet(h.sniAddr, certFile, publicURL); !ok || body != marker {
		t.Fatalf("covered relay stopped serving: %q, %v", body, ok)
	}
}
