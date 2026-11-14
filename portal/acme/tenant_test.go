package acme

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"testing/synctest"
	"time"

	"github.com/go-acme/lego/v4/platform/wait"

	"github.com/gosuda/portal-tunnel/v2/utils"
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

func TestTenantCSRRequiresP256Key(t *testing.T) {
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	_, ed25519Key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		key   crypto.Signer
		valid bool
	}{
		{"P-256", p256, true},
		{"P-384", p384, false},
		{"RSA", rsaKey, false},
		{"Ed25519", ed25519Key, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			names := []string{"tenant.example.com"}
			der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: names}, tc.key)
			if err != nil {
				t.Fatal(err)
			}
			encoded := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
			_, err = ParseTenantCSR(encoded, names)
			if tc.valid && err != nil {
				t.Fatalf("ParseTenantCSR() error = %v", err)
			}
			if !tc.valid && !errors.Is(err, errTenantCSRKey) {
				t.Fatalf("ParseTenantCSR() error = %v, want unsupported key", err)
			}
		})
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

func TestManualRelayDoesNotOfferTenantIssuance(t *testing.T) {
	const root = "portal.example.com"
	keyDir := t.TempDir()
	if err := writeManualRelayCertificate(t, keyDir, root); err != nil {
		t.Fatal(err)
	}
	manager := &Manager{cfg: Config{BaseDomain: root, KeyDir: keyDir, TenantIssuanceStateDir: t.TempDir()}}
	if manager.TenantIssuanceConfigured() {
		t.Fatal("manual relay advertised automatic tenant issuance")
	}
	encoded, _ := tenantCSR(t, &x509.CertificateRequest{DNSNames: []string{"tenant." + root}})
	csr, err := ParseTenantCSR(encoded, []string{"tenant." + root})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.ObtainTenantCertificate(t.Context(), csr); !errors.Is(err, ErrTenantIssuanceDisabled) {
		t.Fatalf("issuance eligibility = %v, want disabled", err)
	}
	for _, filename := range []string{accountKeyFileName, registrationFileName} {
		if _, err := os.Stat(filepath.Join(keyDir, filename)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("manual relay account file %s: %v", filename, err)
		}
	}
}

func TestTenantIssuanceCapabilityRequiresUsableState(t *testing.T) {
	manager := &Manager{cfg: Config{BaseDomain: "example.com", KeyDir: t.TempDir()}}
	if _, err := loadOrCreateAccountKey(filepath.Join(manager.cfg.KeyDir, accountKeyFileName)); err != nil {
		t.Fatal(err)
	}
	stateDir := t.TempDir()
	filePath := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(filePath, nil, 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, directory string
		want            bool
	}{
		{"missing setting", "", false},
		{"missing directory", filepath.Join(stateDir, "missing"), false},
		{"not a directory", filePath, false},
		{"usable directory", stateDir, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			manager.cfg.TenantIssuanceStateDir = tc.directory
			if got := manager.TenantIssuanceConfigured(); got != tc.want {
				t.Fatalf("TenantIssuanceConfigured() = %v, want %v", got, tc.want)
			}
		})
	}

	manager.cfg.TenantIssuanceStateDir = stateDir
	file, err := utils.TryLockFile(filepath.Join(stateDir, "tenant-orders.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if !manager.TenantIssuanceConfigured() {
		t.Fatal("active order disabled issuance capability")
	}
	manager.cfg.BaseDomain = "localhost"
	manager.cfg.TenantIssuanceStateDir = ""
	if !manager.TenantIssuanceConfigured() {
		t.Fatal("local issuance requires public quota state")
	}
}

func TestTenantOrderBudgetSurvivesLeaseAndKeyChanges(t *testing.T) {
	const hostname = "tenant.example.com"
	manager := &Manager{cfg: Config{BaseDomain: "example.com", KeyDir: t.TempDir(), CADirURL: "https://ca.example/directory", TenantIssuanceStateDir: t.TempDir()}}
	if _, err := loadOrCreateAccountKey(filepath.Join(manager.cfg.KeyDir, accountKeyFileName)); err != nil {
		t.Fatal(err)
	}
	reservation, err := manager.reserveTenantOrder(hostname, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := reservation.file.Close(); err != nil {
		t.Fatal(err)
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

type slowPropagationProvider struct{}

func (slowPropagationProvider) Present(string, string, string) error { return nil }
func (slowPropagationProvider) CleanUp(string, string, string) error { return nil }
func (slowPropagationProvider) Timeout() (time.Duration, time.Duration) {
	return time.Hour, time.Hour
}

func TestTenantDNSPropagationStopsAfterCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		provider := dnsChallengeProvider{Provider: slowPropagationProvider{}, ctx: ctx}
		timeout, interval := provider.Timeout()
		checked := make(chan struct{}, 1)
		finished := make(chan error, 1)
		go func() {

			<-time.After(interval)
			finished <- wait.For("propagation", timeout, interval, func() (bool, error) {
				return provider.checkPropagation("tenant.example.com", "_acme-challenge.tenant.example.com.", "value", func(string, string) (bool, error) {
					checked <- struct{}{}
					return false, nil
				})
			})
		}()
		<-checked
		synctest.Wait()
		canceledAt := time.Now()
		cancel()
		if err := <-finished; !errors.Is(err, context.Canceled) {
			t.Fatalf("propagation error = %v, want cancellation", err)
		}
		if elapsed := time.Since(canceledAt); elapsed > 5*time.Second {
			t.Fatalf("canceled propagation took %s, want at most one bounded poll", elapsed)
		}
	})
}

func TestTenantDNSPropagationPreservesCancellationDuringCheck(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	provider := dnsChallengeProvider{ctx: ctx}
	stop, err := provider.checkPropagation("tenant.example.com", "_acme-challenge.tenant.example.com.", "value", func(string, string) (bool, error) {
		cancel()
		return false, context.DeadlineExceeded
	})
	if !stop || !errors.Is(err, context.Canceled) {
		t.Fatalf("propagation = %v, %v, want terminal cancellation", stop, err)
	}
}

func TestTenantCanceledOrderReleasesIssuer(t *testing.T) {
	manager := &Manager{}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := manager.ObtainTenantCertificate(ctx, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("ObtainTenantCertificate() error = %v, want cancellation", err)
	}
	if !manager.issuanceMu.TryLock() {
		t.Fatal("canceled order retained the issuance lock")
	}
	manager.issuanceMu.Unlock()
}
func TestTenantBudgetSurvivesRestartAndIdentityRotation(t *testing.T) {
	cfg := Config{TenantIssuanceStateDir: t.TempDir(), CADirURL: "https://ca.example/directory"}
	now := time.Now()
	for i := range 20 {

		manager := &Manager{cfg: cfg}
		reservation, err := manager.reserveTenantOrder(fmt.Sprintf("tenant%d.zone.example.com", i), now)
		if err != nil {
			t.Fatal(err)
		}
		reservation.file.Close()
	}
	manager := &Manager{cfg: cfg}
	if _, err := manager.reserveTenantOrder("rotated.other.example.com", now); !errors.Is(err, ErrTenantOrderLimited) {
		t.Fatalf("registered domain budget bypassed: %v", err)
	}
	if _, err := manager.reserveTenantOrder("rotated.other.example.com", now.Add(tenantBudgetWindow-time.Second)); !errors.Is(err, ErrTenantOrderLimited) {
		t.Fatalf("budget expired early: %v", err)
	}
	reservation, err := manager.reserveTenantOrder("rotated.other.example.com", now.Add(tenantBudgetWindow))
	if err != nil {
		t.Fatal(err)
	}
	reservation.file.Close()
}

func TestTenantBudgetSerializesManagersAndFailsClosed(t *testing.T) {
	cfg := Config{TenantIssuanceStateDir: t.TempDir(), CADirURL: "https://ca.example/directory"}
	first, second := &Manager{cfg: cfg}, &Manager{cfg: cfg}
	now := time.Now()
	reservation, err := first.reserveTenantOrder("a.example.com", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := second.reserveTenantOrder("b.example.com", now); !errors.Is(err, ErrTenantIssuerBusy) {
		t.Fatalf("concurrent manager admitted: %v", err)
	}
	reservation.file.Close()
	next, err := second.reserveTenantOrder("b.example.com", now)
	if err != nil {
		t.Fatal(err)
	}
	next.file.Close()
	f, err := os.OpenFile(filepath.Join(cfg.TenantIssuanceStateDir, "tenant-orders.jsonl"), os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("{\"id\":")
	f.Close()
	if _, err := second.reserveTenantOrder("c.example.com", now); err == nil {
		t.Fatal("incomplete journal admitted order")
	}
	if _, err := (&Manager{}).reserveTenantOrder("a.example.com", now); err == nil {
		t.Fatal("missing shared state admitted order")
	}
}

func TestTenantBudgetReservesSeparateBoundedRenewalCapacity(t *testing.T) {
	cfg := Config{TenantIssuanceStateDir: t.TempDir(), CADirURL: "https://ca.example/directory"}
	manager := &Manager{cfg: cfg}
	now := time.Now()
	// Seed successful issuance history older than the accounting window. A fresh
	// CSR alone is not enough: only a recorded certificate near expiry qualifies.
	var history []byte
	for i := range 12 {
		entry := tenantOrderEntry{ID: fmt.Sprint(i), CA: cfg.CADirURL, Domain: "example.com", Host: fmt.Sprintf("renew%d.example.com", i), At: now.Add(-60 * 24 * time.Hour)}
		encoded, _ := json.Marshal(entry)
		history = append(history, append(encoded, '\n')...)
		entry.NotBefore = entry.At
		entry.NotAfter = now.Add(10 * 24 * time.Hour)
		if i == 11 {
			entry.NotAfter = now.Add(90 * 24 * time.Hour)
		}
		encoded, _ = json.Marshal(entry)
		history = append(history, append(encoded, '\n')...)
	}
	if err := os.WriteFile(filepath.Join(cfg.TenantIssuanceStateDir, "tenant-orders.jsonl"), history, 0600); err != nil {
		t.Fatal(err)
	}
	for i := range 20 {
		r, err := manager.reserveTenantOrder(fmt.Sprintf("new%d.example.com", i), now)
		if err != nil {
			t.Fatal(err)
		}
		r.file.Close()
	}
	if _, err := manager.reserveTenantOrder("renew11.example.com", now); !errors.Is(err, ErrTenantOrderLimited) {
		t.Fatalf("premature renewal bypassed new order cap: %v", err)
	}
	for i := range 10 {
		r, err := manager.reserveTenantOrder(fmt.Sprintf("renew%d.example.com", i), now)
		if err != nil {
			t.Fatal(err)
		}
		if !r.entry.Renewal {
			t.Fatal("eligible renewal consumed new order capacity")
		}
		r.file.Close()
	}
	if _, err := manager.reserveTenantOrder("renew10.example.com", now); !errors.Is(err, ErrTenantOrderLimited) {
		t.Fatalf("renewal cap bypassed: %v", err)
	}
}

func TestTenantBudgetLimitsCAAcrossRegisteredDomains(t *testing.T) {
	cfg := Config{TenantIssuanceStateDir: t.TempDir(), CADirURL: "https://ca.example/directory"}
	manager := &Manager{cfg: cfg}
	now := time.Now()
	for i := range 40 {
		r, err := manager.reserveTenantOrder(fmt.Sprintf("tenant.example%d.com", i), now)
		if err != nil {
			t.Fatal(err)
		}
		r.file.Close()
	}
	if _, err := manager.reserveTenantOrder("tenant.another.com", now); !errors.Is(err, ErrTenantOrderLimited) {
		t.Fatalf("CA cap bypassed: %v", err)
	}
}

func TestTenantBudgetReconcilesOnlyMatchingSuccess(t *testing.T) {
	local, err := NewManager(Config{BaseDomain: "localhost", KeyDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if err := local.EnsureTLSMaterial(t.Context()); err != nil {
		t.Fatal(err)
	}
	encoded, _ := tenantCSR(t, &x509.CertificateRequest{DNSNames: []string{"tenant.example.com"}})
	csr, err := ParseTenantCSR(encoded, []string{"tenant.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	chain, err := local.ObtainTenantCertificate(t.Context(), csr)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{TenantIssuanceStateDir: t.TempDir(), CADirURL: "https://ca.example/directory"}
	manager := &Manager{cfg: cfg}
	now := time.Now()
	reservation, err := manager.reserveTenantOrder("tenant.example.com", now)
	if err != nil {
		t.Fatal(err)
	}
	wrongEncoded, _ := tenantCSR(t, &x509.CertificateRequest{DNSNames: []string{"tenant.example.com"}})
	wrong, _ := ParseTenantCSR(wrongEncoded, []string{"tenant.example.com"})
	if err := reservation.reconcile(chain, wrong); err == nil {
		t.Fatal("mismatched public key reconciled")
	}
	if err := reservation.reconcile(chain, csr); err != nil {
		t.Fatal(err)
	}
	reservation.file.Close()
	restarted := &Manager{cfg: cfg}
	next, err := restarted.reserveTenantOrder("tenant.example.com", now.Add(17*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if !next.entry.Renewal {
		t.Fatal("durable success did not establish renewal eligibility")
	}
	next.file.Close()
	expired, err := restarted.reserveTenantOrder("tenant.example.com", now.Add(25*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if expired.entry.Renewal {
		t.Fatal("expired certificate used reserved renewal capacity")
	}
	expired.file.Close()
	if _, err := restarted.reserveTenantOrder("tenant.example.com", now.Add(27*time.Hour)); !errors.Is(err, ErrTenantOrderLimited) {
		t.Fatalf("hostname cap bypassed: %v", err)
	}
}

func TestTenantBudgetRejectsMalformedJournalSuffix(t *testing.T) {
	cfg := Config{TenantIssuanceStateDir: t.TempDir(), CADirURL: "https://ca.example/directory"}
	if err := os.WriteFile(filepath.Join(cfg.TenantIssuanceStateDir, "tenant-orders.jsonl"), []byte("}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := (&Manager{cfg: cfg}).reserveTenantOrder("tenant.example.com", time.Now()); err == nil {
		t.Fatal("malformed journal admitted order")
	}
}
