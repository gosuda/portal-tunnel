package acme

import (
	"crypto/x509"
	"math/big"
	"testing"
	"time"
)

func TestCertificateCoversDomains(t *testing.T) {
	t.Parallel()

	domains := []string{"relay.example", "*.relay.example"}
	for _, tc := range []struct {
		name string
		sans []string
		want bool
	}{
		{"apex and wildcard", []string{"relay.example", "*.relay.example"}, true},
		{"wildcard without apex", []string{"*.relay.example"}, false},
		{"apex without wildcard", []string{"relay.example"}, false},
		{"single probe name without wildcard", []string{"relay.example", "probe.relay.example"}, false},
		{"different domain", []string{"other.example", "*.other.example"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cert := &x509.Certificate{DNSNames: tc.sans}
			if got := certificateCoversDomains(cert, domains); got != tc.want {
				t.Fatalf("certificateCoversDomains(%v, %v) = %v, want %v", tc.sans, domains, got, tc.want)
			}
		})
	}
}

func TestEvaluateRenewalDecision(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	domains := []string{"relay.example", "*.relay.example"}
	cert := &x509.Certificate{
		SerialNumber:   big.NewInt(12345),
		AuthorityKeyId: []byte{1, 2, 3, 4, 5, 6, 7, 8},
		DNSNames:       domains,
		NotAfter:       now.Add(60 * 24 * time.Hour),
	}
	dueTime := now.Add(-time.Minute)

	// 1. ARI window says renew now even when >30 days remain; returns ReplacesCertID.
	shouldRenew, replacesCertID := evaluateRenewalDecision(cert, domains, true, &dueTime, now)
	if !shouldRenew || replacesCertID == "" {
		t.Fatalf("ARI due renewal = (%v, %q); want (true, non-empty certID)", shouldRenew, replacesCertID)
	}

	// 2. ARI window defers renewal (nil renewAt) even when <30 days remain.
	shortCert := *cert
	shortCert.NotAfter = now.Add(10 * 24 * time.Hour)
	shouldRenew, replacesCertID = evaluateRenewalDecision(&shortCert, domains, true, nil, now)
	if shouldRenew || replacesCertID != "" {
		t.Fatalf("ARI deferred renewal = (%v, %q); want (false, \"\")", shouldRenew, replacesCertID)
	}

	// 3. Fallback without ARI uses the 30-day threshold.
	shouldRenew, _ = evaluateRenewalDecision(cert, domains, false, nil, now)
	if shouldRenew {
		t.Fatal("fallback renewed certificate with 60 days remaining")
	}
	shouldRenew, replacesCertID = evaluateRenewalDecision(&shortCert, domains, false, nil, now)
	if !shouldRenew || replacesCertID != "" {
		t.Fatalf("fallback <30d renewal = (%v, %q); want (true, \"\")", shouldRenew, replacesCertID)
	}

	// 4. Domain mismatch always triggers immediate re-provisioning without ReplacesCertID.
	shouldRenew, replacesCertID = evaluateRenewalDecision(cert, []string{"other.example", "*.other.example"}, true, nil, now)
	if !shouldRenew || replacesCertID != "" {
		t.Fatalf("domain mismatch renewal = (%v, %q); want (true, \"\")", shouldRenew, replacesCertID)
	}
}
