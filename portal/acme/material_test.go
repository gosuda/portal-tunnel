package acme

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/lego"
)

// Every issuance carries a new private key, so the chain, the key and the
// certificate a TLS handshake presents must change together, and a pair that
// cannot be loaded must leave what is being served alone.
func TestTLSMaterialFollowsTheStoredCertificate(t *testing.T) {
	t.Parallel()

	const baseDomain = "portal.example.com"
	keyDir := t.TempDir()
	certFile, keyFile := certificateFilePaths(keyDir, lego.LEDirectoryProduction)
	manager, err := NewManager(Config{BaseDomain: baseDomain, KeyDir: keyDir, DNSProvider: TypeRoute53})
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	if manager.TLSMaterial() != nil {
		t.Fatal("TLSMaterial() != nil before anything was loaded")
	}
	if _, err := manager.GetCertificate(nil); err == nil {
		t.Fatal("GetCertificate() error = nil before anything was loaded, want one")
	}

	notAfter := time.Now().Add(30 * 24 * time.Hour)
	if err := writeRelayCertificate(t, certFile, keyFile, baseDomain, notAfter); err != nil {
		t.Fatalf("writeRelayCertificate(first) error = %v", err)
	}
	first, err := manager.loadTLSMaterial(certFile, keyFile)
	if err != nil {
		t.Fatalf("loadTLSMaterial(first) error = %v", err)
	}
	served, err := manager.GetCertificate(nil)
	if err != nil || served != &first.Certificate {
		t.Fatalf("GetCertificate() = %p, %v; want the first certificate", served, err)
	}

	if err := writeRelayCertificate(t, certFile, keyFile, baseDomain, notAfter.Add(60*24*time.Hour)); err != nil {
		t.Fatalf("writeRelayCertificate(renewed) error = %v", err)
	}
	renewed, err := manager.loadTLSMaterial(certFile, keyFile)
	if err != nil {
		t.Fatalf("loadTLSMaterial(renewed) error = %v", err)
	}
	if bytes.Equal(renewed.KeyPEM, first.KeyPEM) || bytes.Equal(renewed.CertPEM, first.CertPEM) {
		t.Fatal("the renewed material repeats the first chain or key")
	}
	served, err = manager.GetCertificate(nil)
	if err != nil || served != &renewed.Certificate || manager.TLSMaterial() != renewed {
		t.Fatalf("GetCertificate() = %p, %v; want the renewed certificate", served, err)
	}

	// A chain with a key from another issuance does not form a pair.
	otherCert, otherKey := filepath.Join(keyDir, "other.pem"), filepath.Join(keyDir, "other.key")
	if err := writeRelayCertificate(t, otherCert, otherKey, baseDomain, notAfter); err != nil {
		t.Fatalf("writeRelayCertificate(other) error = %v", err)
	}
	if _, err := manager.loadTLSMaterial(certFile, otherKey); err == nil {
		t.Fatal("loadTLSMaterial(mismatched pair) error = nil, want one")
	}
	if err := os.WriteFile(otherCert, []byte("not a certificate"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.loadTLSMaterial(otherCert, otherKey); err == nil {
		t.Fatal("loadTLSMaterial(garbage) error = nil, want one")
	}
	if manager.TLSMaterial() != renewed {
		t.Fatal("a failed load replaced the material that is being served")
	}
}
