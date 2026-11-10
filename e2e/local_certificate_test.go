package e2e_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/sdk"
)

// A certificate unrelated to the relay's certificate must work through the
// real relay, exposure, tenant TLS engine, and exporter self-probe.
func TestLocalTenantCertificate(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(762),
		Subject:      pkix.Name{CommonName: "local tenant test"},
		DNSNames:     []string{"*.localhost", "*.127.0.0.1"},
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
