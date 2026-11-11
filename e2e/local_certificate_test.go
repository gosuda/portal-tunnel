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
