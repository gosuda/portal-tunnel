package gcloud

import (
	"testing"

	"google.golang.org/api/dns/v1"
)

func TestDNSKeyDSRecordPrefersSHA256(t *testing.T) {
	t.Parallel()

	record, ok := dnsKeyDSRecord(&dns.DnsKey{
		Algorithm: "ecdsap256sha256",
		KeyTag:    12345,
		Type:      "keySigning",
		IsActive:  true,
		Digests: []*dns.DnsKeyDigest{
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

func TestDNSSECStatusFromZoneUsesActiveKeySigningKey(t *testing.T) {
	t.Parallel()

	state, dsRecord, _, err := dnssecStatusFromZone(&dns.ManagedZone{
		DnssecConfig: &dns.ManagedZoneDnsSecConfig{State: "on"},
	}, []*dns.DnsKey{
		{
			Algorithm: "rsasha256",
			KeyTag:    100,
			Type:      "zoneSigning",
			IsActive:  true,
			Digests: []*dns.DnsKeyDigest{
				{Type: "sha256", Digest: "IGNORE"},
			},
		},
		{
			Algorithm: "rsasha256",
			KeyTag:    200,
			Type:      "keySigning",
			IsActive:  true,
			Digests: []*dns.DnsKeyDigest{
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
