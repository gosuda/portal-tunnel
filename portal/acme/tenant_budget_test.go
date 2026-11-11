package acme

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestTenantBudgetSurvivesRestartAndIdentityRotation(t *testing.T) {
	cfg := Config{TenantIssuanceStateDir: t.TempDir(), CADirURL: "https://ca.example/directory"}
	now := time.Now()
	for i := range 20 {
		// Separate managers represent process restarts and unrelated new identities.
		manager := &Manager{cfg: cfg}
		reservation, err := manager.reserveTenantOrder(fmt.Sprintf("tenant%d.zone.example.com", i), now)
		if err != nil {
			t.Fatal(err)
		}
		reservation.file.Close() // No result: failed and ambiguous orders stay charged.
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
