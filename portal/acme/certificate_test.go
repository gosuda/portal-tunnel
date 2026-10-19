package acme

import (
	"crypto/x509"
	"math/big"
	"testing"
	"time"

	legoacme "github.com/go-acme/lego/v4/acme"
	"github.com/go-acme/lego/v4/certificate"
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

func TestEvaluateRenewal(t *testing.T) {
	t.Parallel()

	const (
		day      = 24 * time.Hour
		lifetime = 90 * day
	)
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	domains := []string{"relay.example", "*.relay.example"}
	newCert := func(remaining, validity time.Duration) *x509.Certificate {
		return &x509.Certificate{
			SerialNumber:   big.NewInt(12345),
			AuthorityKeyId: []byte{1, 2, 3, 4, 5, 6, 7, 8},
			DNSNames:       domains,
			NotBefore:      now.Add(remaining - validity),
			NotAfter:       now.Add(remaining),
		}
	}
	// Windows lie entirely in the past or entirely beyond the next check, so
	// the random time ShouldRenewAt picks inside them cannot change the result.
	pastWindow := &legoacme.Window{Start: now.Add(-2 * time.Hour), End: now.Add(-time.Hour)}
	farWindow := &legoacme.Window{Start: now.Add(72 * time.Hour), End: now.Add(73 * time.Hour)}
	soonWindow := &legoacme.Window{Start: now.Add(2 * time.Hour), End: now.Add(3 * time.Hour)}
	ariFor := func(window *legoacme.Window, retryAfter time.Duration) *certificate.RenewalInfoResponse {
		return &certificate.RenewalInfoResponse{
			RenewalInfoResponse: legoacme.RenewalInfoResponse{SuggestedWindow: *window},
			RetryAfter:          retryAfter,
		}
	}

	for _, tc := range []struct {
		name        string
		cert        *x509.Certificate
		domains     []string
		ari         *certificate.RenewalInfoResponse
		wantRenew   bool
		wantReplace bool
		wantRecheck time.Duration
	}{
		{"due window renews early and replaces the certificate", newCert(60*day, lifetime), domains, ariFor(pastWindow, 0), true, true, 24 * time.Hour},
		{"future window defers", newCert(60*day, lifetime), domains, ariFor(farWindow, 0), false, false, 24 * time.Hour},
		{"future window defers even below the fallback threshold", newCert(20*day, lifetime), domains, ariFor(farWindow, 0), false, false, 24 * time.Hour},
		{"retry after below one hour is raised to one hour", newCert(60*day, lifetime), domains, ariFor(soonWindow, 5*time.Minute), false, false, time.Hour},
		{"retry after above one day is capped at one day", newCert(60*day, lifetime), domains, ariFor(farWindow, 72*time.Hour), false, false, 24 * time.Hour},
		{"window before the next check renews now", newCert(60*day, lifetime), domains, ariFor(soonWindow, 6*time.Hour), true, true, 6 * time.Hour},
		{"expiry floor overrides a deferring window", newCert(3*day, lifetime), domains, ariFor(farWindow, 0), true, true, 24 * time.Hour},
		{"next check is no later than the expiry floor", newCert(7*day+2*time.Hour, lifetime), domains, ariFor(farWindow, 0), false, false, 2 * time.Hour},
		{"floor is a tenth of a short lifetime", newCert(3*day, 6*day), domains, ariFor(farWindow, 0), false, false, 24 * time.Hour},
		{"short lifetime below its floor renews", newCert(10*time.Hour, 6*day), domains, ariFor(farWindow, 0), true, true, 24 * time.Hour},
		{"expired certificate renews without ReplacesCertID", newCert(-time.Hour, lifetime), domains, ariFor(farWindow, 0), true, false, 24 * time.Hour},
		{"domain mismatch renews without ReplacesCertID", newCert(60*day, lifetime), []string{"other.example", "*.other.example"}, ariFor(farWindow, 0), true, false, 24 * time.Hour},
		{"zero window falls back to the threshold", newCert(60*day, lifetime), domains, ariFor(&legoacme.Window{}, 0), false, false, 24 * time.Hour},
		{"zero window renews below the threshold", newCert(10*day, lifetime), domains, ariFor(&legoacme.Window{}, 0), true, false, 24 * time.Hour},
		{"inverted window falls back to the threshold", newCert(60*day, lifetime), domains, ariFor(&legoacme.Window{Start: farWindow.End, End: farWindow.Start}, 0), false, false, 24 * time.Hour},
		{"inverted window renews below the threshold", newCert(10*day, lifetime), domains, ariFor(&legoacme.Window{Start: pastWindow.End, End: pastWindow.Start}, 0), true, false, 24 * time.Hour},
		{"missing ARI falls back to the threshold", newCert(60*day, lifetime), domains, nil, false, false, 24 * time.Hour},
		{"missing ARI renews below the threshold", newCert(10*day, lifetime), domains, nil, true, false, 24 * time.Hour},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			renew, replacesCertID, recheck := evaluateRenewal(tc.cert, tc.domains, tc.ari, now)
			if renew != tc.wantRenew || (replacesCertID != "") != tc.wantReplace || recheck != tc.wantRecheck {
				t.Fatalf("evaluateRenewal = (%v, %q, %v); want (%v, replaces=%v, %v)", renew, replacesCertID, recheck, tc.wantRenew, tc.wantReplace, tc.wantRecheck)
			}
		})
	}
}
