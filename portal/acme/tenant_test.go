package acme

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"net"
	"testing"
	"time"
)

func tenantCSR(t *testing.T, template *x509.CertificateRequest) (string, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), key
}

func TestTenantCSRRestrictsEveryIdentity(t *testing.T) {
	allowed := []string{"canonical.example.com", "alias.example.com"}
	otherName, err := asn1.Marshal([]asn1.RawValue{{Class: 2, Tag: 2, Bytes: []byte(allowed[0])}, {Class: 2, Tag: 8, Bytes: []byte{42, 3, 4}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		template x509.CertificateRequest
		valid    bool
	}{
		{"canonical", x509.CertificateRequest{DNSNames: allowed[:1]}, true},
		{"alias and canonical", x509.CertificateRequest{DNSNames: allowed}, false},
		{"matching CN", x509.CertificateRequest{DNSNames: allowed[:1], Subject: pkix.Name{CommonName: allowed[0]}}, true},
		{"wildcard", x509.CertificateRequest{DNSNames: []string{"*.example.com"}}, false},
		{"apex", x509.CertificateRequest{DNSNames: []string{"example.com"}}, false},
		{"sibling", x509.CertificateRequest{DNSNames: []string{allowed[0], "other.example.com"}}, false},
		{"CN bypass", x509.CertificateRequest{DNSNames: allowed, Subject: pkix.Name{CommonName: "other.example.com"}}, false},
		{"IP", x509.CertificateRequest{DNSNames: allowed, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}, false},
		{"email", x509.CertificateRequest{DNSNames: allowed, EmailAddresses: []string{"admin@example.com"}}, false},
		{"other SAN", x509.CertificateRequest{ExtraExtensions: []pkix.Extension{{Id: []int{2, 5, 29, 17}, Value: otherName}}}, false},
		{"duplicate SAN extension", x509.CertificateRequest{ExtraExtensions: []pkix.Extension{{Id: []int{2, 5, 29, 17}, Value: otherName}, {Id: []int{2, 5, 29, 17}, Value: otherName}}}, false},
		{"CA extension", x509.CertificateRequest{DNSNames: allowed, ExtraExtensions: []pkix.Extension{{Id: []int{2, 5, 29, 19}, Value: []byte{0x30, 0}}}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			encoded, _ := tenantCSR(t, &tc.template)
			_, err := ParseTenantCSR(encoded, allowed)
			if (err == nil) != tc.valid {
				t.Fatalf("ParseTenantCSR() error = %v, valid %v", err, tc.valid)
			}
		})
	}
	encoded, _ := tenantCSR(t, &x509.CertificateRequest{DNSNames: allowed})
	block, _ := pem.Decode([]byte(encoded))
	block.Bytes[len(block.Bytes)-1] ^= 1
	if _, err := ParseTenantCSR(string(pem.EncodeToMemory(block)), allowed); err == nil {
		t.Fatal("bad CSR signature accepted")
	}
}

func TestLocalTenantIssuanceKeepsCSRKey(t *testing.T) {
	manager, err := NewManager(Config{BaseDomain: "localhost", KeyDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.EnsureTLSMaterial(t.Context()); err != nil {
		t.Fatal(err)
	}
	encoded, key := tenantCSR(t, &x509.CertificateRequest{DNSNames: []string{"tenant.localhost"}})
	csr, err := ParseTenantCSR(encoded, []string{"tenant.localhost"})
	if err != nil {
		t.Fatal(err)
	}
	chain, err := manager.ObtainTenantCertificate(t.Context(), csr)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(chain)
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(spki, leaf.RawSubjectPublicKeyInfo) {
		t.Fatal("issuer changed tenant key")
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(manager.TLSMaterial().CertPEM)
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: "tenant.localhost", Roots: roots}); err != nil {
		t.Fatal(err)
	}
	if leaf.IsCA {
		t.Fatal("tenant certificate is a CA")
	}
}

func TestTenantOrderBudgetSurvivesLeaseAndKeyChanges(t *testing.T) {
	const hostname = "tenant.example.com"
	manager := &Manager{
		cfg:                 Config{BaseDomain: "example.com"},
		tenantOrderAttempts: map[string]time.Time{hostname: time.Now()},
	}
	for range 2 {
		encoded, _ := tenantCSR(t, &x509.CertificateRequest{DNSNames: []string{hostname}})
		csr, err := ParseTenantCSR(encoded, []string{hostname})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := manager.ObtainTenantCertificate(t.Context(), csr); !errors.Is(err, ErrTenantOrderLimited) {
			t.Fatalf("new key bypassed hostname budget: %v", err)
		}
	}
	manager.issuanceMu.Lock()
	defer manager.issuanceMu.Unlock()
	if _, err := manager.ObtainTenantCertificate(t.Context(), nil); !errors.Is(err, ErrTenantIssuerBusy) {
		t.Fatalf("concurrent order bypassed serialization: %v", err)
	}
}
