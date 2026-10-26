package acme

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"slices"
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
	if err := manager.loadTLSMaterial(certFile, keyFile); err != nil {
		t.Fatalf("loadTLSMaterial(first) error = %v", err)
	}
	first := manager.TLSMaterial()
	served, err := manager.GetCertificate(nil)
	if err != nil || served != &first.Certificate {
		t.Fatalf("GetCertificate() = %p, %v; want the first certificate", served, err)
	}

	if err := writeRelayCertificate(t, certFile, keyFile, baseDomain, notAfter.Add(60*24*time.Hour)); err != nil {
		t.Fatalf("writeRelayCertificate(renewed) error = %v", err)
	}
	if err := manager.loadTLSMaterial(certFile, keyFile); err != nil {
		t.Fatalf("loadTLSMaterial(renewed) error = %v", err)
	}
	renewed := manager.TLSMaterial()
	if bytes.Equal(renewed.CertPEM, first.CertPEM) || renewed.Certificate.Leaf.PublicKey.(interface{ Equal(crypto.PublicKey) bool }).Equal(first.Certificate.Leaf.PublicKey) {
		t.Fatal("the renewed material repeats the first chain or key")
	}
	served, err = manager.GetCertificate(nil)
	if err != nil || served != &renewed.Certificate || manager.TLSMaterial() != renewed {
		t.Fatalf("GetCertificate() = %p, %v; want the renewed certificate", served, err)
	}
	if manager.SigningKey(first.Certificate.Certificate[0]) == nil {
		t.Fatal("a renewal made through loadTLSMaterial dropped the key of the replaced certificate")
	}

	// A chain with a key from another issuance does not form a pair.
	otherCert, otherKey := filepath.Join(keyDir, "other.pem"), filepath.Join(keyDir, "other.key")
	if err := writeRelayCertificate(t, otherCert, otherKey, baseDomain, notAfter); err != nil {
		t.Fatalf("writeRelayCertificate(other) error = %v", err)
	}
	if err := manager.loadTLSMaterial(certFile, otherKey); err == nil {
		t.Fatal("loadTLSMaterial(mismatched pair) error = nil, want one")
	}
	if err := os.WriteFile(otherCert, []byte("not a certificate"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := manager.loadTLSMaterial(otherCert, otherKey); err == nil {
		t.Fatal("loadTLSMaterial(garbage) error = nil, want one")
	}
	if manager.TLSMaterial() != renewed {
		t.Fatal("a failed load replaced the material that is being served")
	}
}

// A tenant pins the chain the relay served when it registered and keeps
// presenting it to visitors after a renewal, so the relay must keep signing for
// the replaced certificate, and only for as long as it is valid.
func TestSigningKeyFollowsTheServedAndTheUnexpiredCertificates(t *testing.T) {
	t.Parallel()

	const baseDomain = "portal.example.com"
	keyDir := t.TempDir()
	certFile, keyFile := certificateFilePaths(keyDir, lego.LEDirectoryProduction)
	manager, err := NewManager(Config{BaseDomain: baseDomain, KeyDir: keyDir, DNSProvider: TypeRoute53})
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	if manager.SigningKey([]byte("anything")) != nil {
		t.Fatal("SigningKey() != nil before anything was loaded")
	}

	issue := func(notAfter time.Time) *TLSMaterial {
		t.Helper()
		if err := writeRelayCertificate(t, certFile, keyFile, baseDomain, notAfter); err != nil {
			t.Fatalf("writeRelayCertificate() error = %v", err)
		}
		certPEM, err := os.ReadFile(certFile)
		if err != nil {
			t.Fatal(err)
		}
		keyPEM, err := os.ReadFile(keyFile)
		if err != nil {
			t.Fatal(err)
		}
		material, err := newTLSMaterial(certPEM, keyPEM)
		if err != nil {
			t.Fatalf("newTLSMaterial() error = %v", err)
		}
		return material
	}
	leaf := func(material *TLSMaterial) []byte { return material.Certificate.Certificate[0] }
	hasKeyOf := func(material *TLSMaterial) bool {
		signer := manager.SigningKey(leaf(material))
		return signer != nil && material.Certificate.Leaf.PublicKey.(interface{ Equal(crypto.PublicKey) bool }).Equal(signer.Public())
	}

	valid := time.Now().Add(30 * 24 * time.Hour)
	first, second, current := issue(valid), issue(valid.Add(24*time.Hour)), issue(valid.Add(48*time.Hour))
	for _, material := range []*TLSMaterial{first, second, current} {
		manager.serve(material)
	}
	for name, material := range map[string]*TLSMaterial{"served": current, "renewed once": second, "renewed twice": first} {
		if !hasKeyOf(material) {
			t.Errorf("SigningKey(%s certificate) is not the key of that certificate", name)
		}
	}
	// Neither a certificate the relay never served nor garbage gets a key.
	for name, leafDER := range map[string][]byte{"another": leaf(issue(valid)), "garbage": []byte("not a certificate"), "empty": nil} {
		if manager.SigningKey(leafDER) != nil {
			t.Errorf("SigningKey(%s certificate) != nil, want none", name)
		}
	}

	// An expired certificate is dropped when it is replaced, with its key. One
	// that expires while it is retired is refused as well.
	expired := issue(time.Now().Add(-time.Hour))
	manager.serve(expired)
	manager.serve(issue(valid))
	if manager.SigningKey(leaf(expired)) != nil || slices.Contains(manager.material.Load().retired, expired) {
		t.Fatal("an expired certificate that was replaced is still kept")
	}
	served := manager.material.Load()
	served.retired = append(served.retired, expired)
	manager.material.Store(served)
	if manager.SigningKey(leaf(expired)) != nil {
		t.Fatal("SigningKey(a retired certificate that has expired) != nil, want none")
	}
}

// A startup provision serves the issued pair and EnsureTLSMaterial then loads
// the same pair from disk; the copy it replaces is not a replaced certificate.
func TestServingTheSameCertificateAgainRetiresNothing(t *testing.T) {
	t.Parallel()

	const baseDomain = "portal.example.com"
	keyDir := t.TempDir()
	certFile, keyFile := certificateFilePaths(keyDir, lego.LEDirectoryProduction)
	manager, err := NewManager(Config{BaseDomain: baseDomain, KeyDir: keyDir, DNSProvider: TypeRoute53})
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	if err := writeRelayCertificate(t, certFile, keyFile, baseDomain, time.Now().Add(30*24*time.Hour)); err != nil {
		t.Fatalf("writeRelayCertificate() error = %v", err)
	}
	for range 2 {
		if err := manager.loadTLSMaterial(certFile, keyFile); err != nil {
			t.Fatalf("loadTLSMaterial() error = %v", err)
		}
	}
	if retired := manager.material.Load().retired; len(retired) != 0 {
		t.Fatalf("serving the same certificate twice retired %d copies of it, want none", len(retired))
	}
}

// The cache fallback reaches a tenant over TLS, and the tenant presents the
// relay chain it pinned, which can be one a renewal replaced. The fallback must
// trust exactly what SigningKey signs for: the served certificate and the
// replaced ones that have not expired, under the requested name.
func TestTenantTLSConfigTrustsWhatTheRelaySignsFor(t *testing.T) {
	t.Parallel()

	const baseDomain = "portal.example.com"
	keyDir := t.TempDir()
	certFile, keyFile := certificateFilePaths(keyDir, lego.LEDirectoryProduction)
	manager, err := NewManager(Config{BaseDomain: baseDomain, KeyDir: keyDir, DNSProvider: TypeRoute53})
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	issue := func(notAfter time.Time) *TLSMaterial {
		t.Helper()
		if err := writeRelayCertificate(t, certFile, keyFile, baseDomain, notAfter); err != nil {
			t.Fatalf("writeRelayCertificate() error = %v", err)
		}
		certPEM, err := os.ReadFile(certFile)
		if err != nil {
			t.Fatal(err)
		}
		keyPEM, err := os.ReadFile(keyFile)
		if err != nil {
			t.Fatal(err)
		}
		material, err := newTLSMaterial(certPEM, keyPEM)
		if err != nil {
			t.Fatalf("newTLSMaterial() error = %v", err)
		}
		return material
	}
	// reach runs a handshake with a tenant that presents material. Loopback TCP
	// rather than net.Pipe: a refusing client must be able to send its alert
	// while the tenant is still writing its flight.
	reach := func(material *TLSMaterial, serverName string) error {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return err
		}
		defer listener.Close()
		go func() {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			_ = tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{material.Certificate}}).Handshake()
		}()
		conn, err := net.DialTimeout("tcp", listener.Addr().String(), 10*time.Second)
		if err != nil {
			return err
		}
		defer conn.Close()
		if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
			return err
		}
		return tls.Client(conn, manager.TenantTLSConfig(serverName)).Handshake()
	}

	valid := time.Now().Add(30 * 24 * time.Hour)
	expired, replaced, served := issue(time.Now().Add(-time.Hour)), issue(valid), issue(valid.Add(24*time.Hour))
	for _, material := range []*TLSMaterial{expired, replaced, served} {
		manager.serve(material)
	}
	const tenantHost = "tenant." + baseDomain
	for name, material := range map[string]*TLSMaterial{"served": served, "replaced": replaced} {
		if err := reach(material, tenantHost); err != nil {
			t.Errorf("tenant presenting the %s certificate: %v, want it reached", name, err)
		}
	}
	for name, material := range map[string]*TLSMaterial{"expired replaced": expired, "never served": issue(valid)} {
		if err := reach(material, tenantHost); err == nil {
			t.Errorf("tenant presenting the %s certificate was reached, want it refused", name)
		}
	}
	if err := reach(served, "tenant.other.example"); err == nil {
		t.Error("tenant presenting the served certificate under another name was reached, want it refused")
	}
}

// An SDK that pins the relay chain once verifies its /v1/sign connection
// against that chain. A renewal by the same intermediate still verifies; one by
// another intermediate does not, and neither does a certificate for another
// name.
func TestTrustedByFollowsTheIssuingIntermediate(t *testing.T) {
	t.Parallel()

	const relayHost = "portal.example.com"
	intermediate, otherIntermediate := newTestIntermediate(t, "R10", nil), newTestIntermediate(t, "R11", nil)
	root := newTestIntermediate(t, "Root", nil)
	underRoot, otherUnderRoot := newTestIntermediate(t, "R12", &root), newTestIntermediate(t, "R13", &root)
	for name, test := range map[string]struct {
		pinned, renewed *TLSMaterial
		want            bool
	}{
		"same intermediate":             {intermediate.issue(t, relayHost), intermediate.issue(t, relayHost), true},
		"another intermediate":          {intermediate.issue(t, relayHost), otherIntermediate.issue(t, relayHost), false},
		"same intermediate, other name": {intermediate.issue(t, relayHost), intermediate.issue(t, "other.example.com"), false},
		// A bundle that also carries the root lets the presented intermediate
		// of a renewal reach that root.
		"another intermediate under a root the pinned bundle carries": {underRoot.issue(t, relayHost), otherUnderRoot.issue(t, relayHost), true},
	} {
		if got := test.renewed.TrustedBy(test.pinned, relayHost); got != test.want {
			t.Errorf("TrustedBy(%s) = %v, want %v", name, got, test.want)
		}
	}
}

type testIntermediate struct {
	cert   *x509.Certificate
	key    *ecdsa.PrivateKey
	parent *testIntermediate
}

// newTestIntermediate returns an issuing CA, standing for one intermediate of
// the relay's CA, issued by parent or self-signed when parent is nil.
func newTestIntermediate(t *testing.T, name string, parent *testIntermediate) testIntermediate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	issuer, issuerKey := template, key
	if parent != nil {
		issuer, issuerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, &key.PublicKey, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return testIntermediate{cert: cert, key: key, parent: parent}
}

// issue returns relay material for host with a new key, served as the leaf
// followed by this intermediate and its parents, as an ACME bundle is.
func (i testIntermediate) issue(t *testing.T, host string) *TLSMaterial {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host, "*." + host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, i.cert, &key.PublicKey, i.key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	for issuer := &i; issuer != nil; issuer = issuer.parent {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuer.cert.Raw})...)
	}
	material, err := newTLSMaterial(certPEM, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		t.Fatal(err)
	}
	return material
}
