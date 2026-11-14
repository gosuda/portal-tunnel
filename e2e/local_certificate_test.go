package e2e_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
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
	"github.com/gosuda/portal-tunnel/v2/portal/localtls"
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

// An exact tenant leaf uses separate trust from the relay and never needs to
// cover the friendly alias, which stays on the Keyless path.
func TestLocalTenantCertificate(t *testing.T) {
	h := newHarness(t)
	h.waitForPublicURL()
	id, err := identity.Generate("manual")
	if err != nil {
		t.Fatal(err)
	}
	hostname, err := utils.LocalTLSLeaseHostname(id.Name, id.Address, "localhost")
	if err != nil {
		t.Fatal(err)
	}
	certFile, keyFile := writeTenantCertificate(t, hostname)
	_, ready := namespaceService(t, h, id, marker, sdk.WithTLSCertificate(certFile, keyFile))
	if body, ok := tenantGet(h.sniAddr, certFile, ready.PublicURL); !ok || body != marker {
		t.Fatalf("manual leaf response=%q ok=%v", body, ok)
	}
	if _, ok := tenantGet(h.sniAddr, h.certificate, ready.PublicURL); ok {
		t.Fatal("tenant unexpectedly used relay certificate")
	}
	if ready.AliasURL == "" {
		t.Fatal("manual leaf unnecessarily suppressed friendly alias")
	}
	if body, ok := tenantGet(h.sniAddr, h.certificate, ready.AliasURL); !ok || body != marker {
		t.Fatalf("friendly keyless response=%q ok=%v", body, ok)
	}
}

func TestLocalTenantCertificateWrongHostnameFailsReady(t *testing.T) {
	certFile, keyFile := writeTenantCertificate(t, "other.example")
	h := newHarness(t, sdk.WithTLSCertificate(certFile, keyFile))
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	_, err := h.exposure.WaitReady(ctx)
	var hostnameErr x509.HostnameError
	if !errors.Is(err, localtls.ErrLocalCertificate) || !errors.As(err, &hostnameErr) {
		t.Fatalf("WaitReady=%v, want local hostname error", err)
	}
	for _, status := range h.exposure.Relays() {
		if status.PublicURL != "" {
			t.Fatalf("invalid certificate advertised canonical: %+v", status)
		}
	}
	publicURL := "https://" + net.JoinHostPort(hostnameErr.Host, strconv.Itoa(h.sniPort))
	if _, ok := tenantGet(h.sniAddr, h.certificate, publicURL); ok {
		t.Fatal("invalid manual certificate fell back to relay signing")
	}
}

func TestLocalCertificateExpiryWithdrawsCanonical(t *testing.T) {
	h := newHarness(t)
	h.waitForPublicURL()
	id, err := identity.Generate("")
	if err != nil {
		t.Fatal(err)
	}
	hostname, err := utils.LocalTLSLeaseHostname(id.Name, id.Address, "localhost")
	if err != nil {
		t.Fatal(err)
	}
	certFile, keyFile := writeTenantCertificate(t, hostname)
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	leaf.NotAfter = time.Now().Add(30 * time.Second).Truncate(time.Second)
	der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, leaf.PublicKey, pair.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	exposure, ready := namespaceService(t, h, id, marker, sdk.WithTLSCertificate(certFile, keyFile))
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	published := false
	for !published {
		for _, lease := range h.server.PublicLeases() {
			if lease.CanonicalHostname == hostname && lease.CanonicalReady {
				published = true
			}
		}
		if !published {
			select {
			case <-tick.C:
			case <-ctx.Done():
				t.Fatal("relay did not receive canonical readiness through lease renewal")
			}
		}
	}
	// Expiry must arrive as a lifecycle event without a request, reconnect,
	// certificate reload, or a caller querying Relays to repair its snapshot.
	for {
		select {
		case update := <-exposure.Updates():
			if update.State != sdk.RelayReady || update.PublicURL != "" || update.LegacyURL != ready.LegacyURL {
				continue
			}
			if status := exposure.Relays()[0]; status.PublicURL != "" || status.LegacyURL != ready.LegacyURL {
				t.Fatalf("snapshot disagrees with expiry event: %+v", status)
			}
			for _, lease := range h.server.PublicLeases() {
				if lease.CanonicalHostname == hostname && lease.CanonicalReady {
					t.Fatal("relay still advertises the expired canonical")
				}
			}
			if body, ok := tenantGet(h.sniAddr, h.certificate, ready.LegacyURL); !ok || body != marker {
				t.Fatalf("expiry removed the separate legacy endpoint: %q, %v", body, ok)
			}
			return
		case <-ctx.Done():
			t.Fatal("no canonical withdrawal event at certificate expiry")
		}
	}
}
