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

type testIntermediate struct {
	cert   *x509.Certificate
	key    *ecdsa.PrivateKey
	parent *testIntermediate
}

func newTestIntermediate(t *testing.T, name string, parent *testIntermediate) testIntermediate {
	t.Helper()
	key := generateIntermediateCAKey(t)
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

func (i testIntermediate) issue(t *testing.T, host string) *TLSMaterial {
	t.Helper()
	key := generateLeafCertKey(t)
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

func generateIntermediateCAKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func generateLeafCertKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func newRoute53BackedManager(t *testing.T, baseDomain string) (manager *Manager, keyDir, certFile, keyFile string) {
	t.Helper()
	keyDir = t.TempDir()
	certFile, keyFile = certificateFilePaths(keyDir, lego.LEDirectoryProduction)
	manager, err := NewManager(Config{BaseDomain: baseDomain, KeyDir: keyDir, DNSProvider: TypeRoute53})
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	return manager, keyDir, certFile, keyFile
}

func TestTLSMaterialFollowsTheStoredCertificate(t *testing.T) {
	t.Parallel()

	fixture := newStoredCertFixture(t)
	checkStoredCertEmpty(t, fixture)
	loadStoredCertFirst(t, fixture)
	loadStoredCertRenewed(t, fixture)
	checkStoredCertFailedLoadsKeep(t, fixture)
}

type storedCertFixture struct {
	manager    *Manager
	keyDir     string
	certFile   string
	keyFile    string
	baseDomain string
	notAfter   time.Time
	first      *TLSMaterial
	renewed    *TLSMaterial
}

func newStoredCertFixture(t *testing.T) *storedCertFixture {
	t.Helper()
	const baseDomain = "portal.example.com"
	manager, keyDir, certFile, keyFile := newRoute53BackedManager(t, baseDomain)
	return &storedCertFixture{manager: manager, keyDir: keyDir, certFile: certFile, keyFile: keyFile, baseDomain: baseDomain, notAfter: time.Now().Add(30 * 24 * time.Hour)}
}

func checkStoredCertEmpty(t *testing.T, fixture *storedCertFixture) {
	t.Helper()
	if fixture.manager.TLSMaterial() != nil {
		t.Fatal("TLSMaterial() != nil before anything was loaded")
	}
	if _, err := fixture.manager.GetCertificate(nil); err == nil {
		t.Fatal("GetCertificate() error = nil before anything was loaded, want one")
	}
}

func loadStoredCertFirst(t *testing.T, fixture *storedCertFixture) {
	t.Helper()
	if err := writeRelayCertificate(t, fixture.certFile, fixture.keyFile, fixture.baseDomain, fixture.notAfter); err != nil {
		t.Fatalf("writeRelayCertificate(first) error = %v", err)
	}
	if err := fixture.manager.loadTLSMaterial(fixture.certFile, fixture.keyFile); err != nil {
		t.Fatalf("loadTLSMaterial(first) error = %v", err)
	}
	first := fixture.manager.TLSMaterial()
	served, err := fixture.manager.GetCertificate(nil)
	if err != nil || served != &first.Certificate {
		t.Fatalf("GetCertificate() = %p, %v; want the first certificate", served, err)
	}
	fixture.first = first
}

func loadStoredCertRenewed(t *testing.T, fixture *storedCertFixture) {
	t.Helper()
	if err := writeRelayCertificate(t, fixture.certFile, fixture.keyFile, fixture.baseDomain, fixture.notAfter.Add(60*24*time.Hour)); err != nil {
		t.Fatalf("writeRelayCertificate(renewed) error = %v", err)
	}
	if err := fixture.manager.loadTLSMaterial(fixture.certFile, fixture.keyFile); err != nil {
		t.Fatalf("loadTLSMaterial(renewed) error = %v", err)
	}
	renewed := fixture.manager.TLSMaterial()
	if bytes.Equal(renewed.CertPEM, fixture.first.CertPEM) || renewed.Certificate.Leaf.PublicKey.(interface{ Equal(crypto.PublicKey) bool }).Equal(fixture.first.Certificate.Leaf.PublicKey) {
		t.Fatal("the renewed material repeats the first chain or key")
	}
	served, err := fixture.manager.GetCertificate(nil)
	if err != nil || served != &renewed.Certificate || fixture.manager.TLSMaterial() != renewed {
		t.Fatalf("GetCertificate() = %p, %v; want the renewed certificate", served, err)
	}
	if fixture.manager.SigningKey(fixture.first.Certificate.Certificate[0]) == nil {
		t.Fatal("a renewal made through loadTLSMaterial dropped the key of the replaced certificate")
	}
	fixture.renewed = renewed
}

func checkStoredCertFailedLoadsKeep(t *testing.T, fixture *storedCertFixture) {
	t.Helper()
	otherCert, otherKey := filepath.Join(fixture.keyDir, "other.pem"), filepath.Join(fixture.keyDir, "other.key")
	if err := writeRelayCertificate(t, otherCert, otherKey, fixture.baseDomain, fixture.notAfter); err != nil {
		t.Fatalf("writeRelayCertificate(other) error = %v", err)
	}
	if err := fixture.manager.loadTLSMaterial(fixture.certFile, otherKey); err == nil {
		t.Fatal("loadTLSMaterial(mismatched pair) error = nil, want one")
	}
	if err := os.WriteFile(otherCert, []byte("not a certificate"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := fixture.manager.loadTLSMaterial(otherCert, otherKey); err == nil {
		t.Fatal("loadTLSMaterial(garbage) error = nil, want one")
	}
	if fixture.manager.TLSMaterial() != fixture.renewed {
		t.Fatal("a failed load replaced the material that is being served")
	}
}
func TestSigningKeyFollowsTheServedAndTheUnexpiredCertificates(t *testing.T) {
	t.Parallel()

	fixture := newServedSigningKeyFixture(t)
	checkServedSigningKeyEmpty(t, fixture)
	valid := time.Now().Add(30 * 24 * time.Hour)
	serveSigningKeyGenerations(t, fixture, valid)
	checkSigningKeyRejectsUnknown(t, fixture, valid)
	checkSigningKeyDropsExpired(t, fixture, valid)
}

type servedSigningKeyFixture struct {
	manager    *Manager
	certFile   string
	keyFile    string
	baseDomain string
}

func newServedSigningKeyFixture(t *testing.T) *servedSigningKeyFixture {
	t.Helper()
	const baseDomain = "portal.example.com"
	manager, _, certFile, keyFile := newRoute53BackedManager(t, baseDomain)
	return &servedSigningKeyFixture{manager: manager, certFile: certFile, keyFile: keyFile, baseDomain: baseDomain}
}

func issueServedCertMaterial(t *testing.T, fixture *servedSigningKeyFixture, notAfter time.Time) *TLSMaterial {
	t.Helper()
	if err := writeRelayCertificate(t, fixture.certFile, fixture.keyFile, fixture.baseDomain, notAfter); err != nil {
		t.Fatalf("writeRelayCertificate() error = %v", err)
	}
	certPEM, err := os.ReadFile(fixture.certFile)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := os.ReadFile(fixture.keyFile)
	if err != nil {
		t.Fatal(err)
	}
	material, err := newTLSMaterial(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("newTLSMaterial() error = %v", err)
	}
	return material
}

func hasSigningKeyForMaterial(t *testing.T, fixture *servedSigningKeyFixture, material *TLSMaterial) bool {
	t.Helper()
	signer := fixture.manager.SigningKey(material.Certificate.Certificate[0])
	return signer != nil && material.Certificate.Leaf.PublicKey.(interface{ Equal(crypto.PublicKey) bool }).Equal(signer.Public())
}

func checkServedSigningKeyEmpty(t *testing.T, fixture *servedSigningKeyFixture) {
	t.Helper()
	if fixture.manager.SigningKey([]byte("anything")) != nil {
		t.Fatal("SigningKey() != nil before anything was loaded")
	}
}

func serveSigningKeyGenerations(t *testing.T, fixture *servedSigningKeyFixture, valid time.Time) {
	t.Helper()
	first := issueServedCertMaterial(t, fixture, valid)
	second := issueServedCertMaterial(t, fixture, valid.Add(24*time.Hour))
	current := issueServedCertMaterial(t, fixture, valid.Add(48*time.Hour))
	for _, material := range []*TLSMaterial{first, second, current} {
		fixture.manager.serve(material)
	}
	for name, material := range map[string]*TLSMaterial{"served": current, "renewed once": second, "renewed twice": first} {
		if !hasSigningKeyForMaterial(t, fixture, material) {
			t.Errorf("SigningKey(%s certificate) is not the key of that certificate", name)
		}
	}
}

func checkSigningKeyRejectsUnknown(t *testing.T, fixture *servedSigningKeyFixture, valid time.Time) {
	t.Helper()
	another := issueServedCertMaterial(t, fixture, valid)
	for name, leafDER := range map[string][]byte{"another": another.Certificate.Certificate[0], "garbage": []byte("not a certificate"), "empty": nil} {
		if fixture.manager.SigningKey(leafDER) != nil {
			t.Errorf("SigningKey(%s certificate) != nil, want none", name)
		}
	}
}

func checkSigningKeyDropsExpired(t *testing.T, fixture *servedSigningKeyFixture, valid time.Time) {
	t.Helper()
	expired := issueServedCertMaterial(t, fixture, time.Now().Add(-time.Hour))
	fixture.manager.serve(expired)
	fixture.manager.serve(issueServedCertMaterial(t, fixture, valid))
	if fixture.manager.SigningKey(expired.Certificate.Certificate[0]) != nil || slices.Contains(fixture.manager.material.Load().retired, expired) {
		t.Fatal("an expired certificate that was replaced is still kept")
	}
	served := fixture.manager.material.Load()
	served.retired = append(served.retired, expired)
	fixture.manager.material.Store(served)
	if fixture.manager.SigningKey(expired.Certificate.Certificate[0]) != nil {
		t.Fatal("SigningKey(a retired certificate that has expired) != nil, want none")
	}
}
func TestServingTheSameCertificateAgainRetiresNothing(t *testing.T) {
	t.Parallel()

	const baseDomain = "portal.example.com"
	manager, _, certFile, keyFile := newRoute53BackedManager(t, baseDomain)
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

func TestTenantTLSConfigTrustsWhatTheRelaySignsFor(t *testing.T) {
	t.Parallel()

	fixture := newTenantTLSFixture(t)
	valid := time.Now().Add(30 * 24 * time.Hour)
	serveTenantTLSGenerations(t, fixture, valid)
	checkTenantTLSReachable(t, fixture)
	checkTenantTLSRefused(t, fixture)
}

type tenantTLSFixture struct {
	manager    *Manager
	certFile   string
	keyFile    string
	baseDomain string
	valid      time.Time
	expired    *TLSMaterial
	replaced   *TLSMaterial
	served     *TLSMaterial
}

func newTenantTLSFixture(t *testing.T) *tenantTLSFixture {
	t.Helper()
	const baseDomain = "portal.example.com"
	manager, _, certFile, keyFile := newRoute53BackedManager(t, baseDomain)
	return &tenantTLSFixture{manager: manager, certFile: certFile, keyFile: keyFile, baseDomain: baseDomain}
}

func issueTenantTLSMaterial(t *testing.T, fixture *tenantTLSFixture, notAfter time.Time) *TLSMaterial {
	t.Helper()
	if err := writeRelayCertificate(t, fixture.certFile, fixture.keyFile, fixture.baseDomain, notAfter); err != nil {
		t.Fatalf("writeRelayCertificate() error = %v", err)
	}
	certPEM, err := os.ReadFile(fixture.certFile)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := os.ReadFile(fixture.keyFile)
	if err != nil {
		t.Fatal(err)
	}
	material, err := newTLSMaterial(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("newTLSMaterial() error = %v", err)
	}
	return material
}

func serveTenantTLSOnce(listener net.Listener, material *TLSMaterial) {
	conn, err := listener.Accept()
	if err != nil {
		return
	}
	defer conn.Close()
	_ = tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{material.Certificate}}).Handshake()
}

func dialTenantTLSConfig(t *testing.T, fixture *tenantTLSFixture, material *TLSMaterial, serverName string) error {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer listener.Close()
	go serveTenantTLSOnce(listener, material)
	conn, err := net.DialTimeout("tcp", listener.Addr().String(), 10*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}
	return tls.Client(conn, fixture.manager.TenantTLSConfig(serverName)).Handshake()
}

func serveTenantTLSGenerations(t *testing.T, fixture *tenantTLSFixture, valid time.Time) {
	t.Helper()
	fixture.valid = valid
	fixture.expired = issueTenantTLSMaterial(t, fixture, time.Now().Add(-time.Hour))
	fixture.replaced = issueTenantTLSMaterial(t, fixture, valid)
	fixture.served = issueTenantTLSMaterial(t, fixture, valid.Add(24*time.Hour))
	for _, material := range []*TLSMaterial{fixture.expired, fixture.replaced, fixture.served} {
		fixture.manager.serve(material)
	}
}

func checkTenantTLSReachable(t *testing.T, fixture *tenantTLSFixture) {
	t.Helper()
	tenantHost := "tenant." + fixture.baseDomain
	for name, material := range map[string]*TLSMaterial{"served": fixture.served, "replaced": fixture.replaced} {
		if err := dialTenantTLSConfig(t, fixture, material, tenantHost); err != nil {
			t.Errorf("tenant presenting the %s certificate: %v, want it reached", name, err)
		}
	}
}

func checkTenantTLSRefused(t *testing.T, fixture *tenantTLSFixture) {
	t.Helper()
	tenantHost := "tenant." + fixture.baseDomain
	neverServed := issueTenantTLSMaterial(t, fixture, fixture.valid)
	for name, material := range map[string]*TLSMaterial{"expired replaced": fixture.expired, "never served": neverServed} {
		if err := dialTenantTLSConfig(t, fixture, material, tenantHost); err == nil {
			t.Errorf("tenant presenting the %s certificate was reached, want it refused", name)
		}
	}
	if err := dialTenantTLSConfig(t, fixture, fixture.served, "tenant.other.example"); err == nil {
		t.Error("tenant presenting the served certificate under another name was reached, want it refused")
	}
}
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
		"another intermediate under a root the pinned bundle carries": {underRoot.issue(t, relayHost), otherUnderRoot.issue(t, relayHost), true},
	} {
		if got := test.renewed.TrustedBy(test.pinned.CertPEM, relayHost); got != test.want {
			t.Errorf("TrustedBy(%s) = %v, want %v", name, got, test.want)
		}
	}
}
