package gcloud

import (
	"testing"

	gdns "google.golang.org/api/dns/v1"
)

// TestDNSKeyDSRecordPrefersSHA256 protects the invariant that when a DNSSEC key has
// multiple DS digest types, the DS record uses SHA-256 (the minimum mandatory algorithm
// per RFC 8624), preferring it over weaker SHA-1.
func TestDNSKeyDSRecordPrefersSHA256(t *testing.T) {
	t.Parallel()

	record, ok := dnsKeyDSRecord(&gdns.DnsKey{
		Algorithm: "ecdsap256sha256",
		KeyTag:    12345,
		Type:      "keySigning",
		IsActive:  true,
		Digests: []*gdns.DnsKeyDigest{
			{Type: "sha1", Digest: "AAAA"},
			{Type: "sha256", Digest: "BBBB"},
		},
	})
	if !ok {
		t.Fatal("dnsKeyDSRecord() = !ok, want ok")
	}
	if record != "12345 13 2 BBBB" {
		t.Fatalf("dnsKeyDSRecord() = %q, want %q", record, "12345 13 2 BBBB")
	}
}

// TestDNSSECStatusFromZoneUsesActiveKeySigningKey protects the invariant that only
// an active key-signing key (KSK) with a valid SHA-256 digest contributes to the
// DS record, so that the parent chain is anchored only to keys that are in use.
func TestDNSSECStatusFromZoneUsesActiveKeySigningKey(t *testing.T) {
	t.Parallel()

	state, dsRecord, _, err := dnssecStatusFromZone(&gdns.ManagedZone{
		DnssecConfig: &gdns.ManagedZoneDnsSecConfig{State: "on"},
	}, []*gdns.DnsKey{
		{
			Algorithm: "rsasha256",
			KeyTag:    100,
			Type:      "zoneSigning",
			IsActive:  true,
			Digests: []*gdns.DnsKeyDigest{
				{Type: "sha256", Digest: "IGNORE"},
			},
		},
		{
			Algorithm: "rsasha256",
			KeyTag:    200,
			Type:      "keySigning",
			IsActive:  true,
			Digests: []*gdns.DnsKeyDigest{
				{Type: "sha256", Digest: "USEME"},
			},
		},
	})
	if err != nil {
		t.Fatalf("dnssecStatusFromZone() error = %v, want nil", err)
	}

	if state != "on" {
		t.Fatalf("dnssecStatusFromZone().state = %q, want %q", state, "on")
	}
	if dsRecord != "200 8 2 USEME" {
		t.Fatalf("dnssecStatusFromZone().dsRecord = %q, want %q", dsRecord, "200 8 2 USEME")
	}
}
