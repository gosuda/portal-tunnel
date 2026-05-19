package hetzner

import (
	"context"
	"testing"

	"github.com/hetznercloud/hcloud-go/v2/hcloud"
)

func TestChallengeProviderRequiresAPIToken(t *testing.T) {
	t.Parallel()

	provider := New("")
	challengeProvider, err := provider.ChallengeProvider(context.Background())
	if challengeProvider != nil {
		t.Fatalf("ChallengeProvider() provider = %T, want nil", challengeProvider)
	}
	if err == nil || err.Error() != "hetzner api token is required" {
		t.Fatalf("ChallengeProvider() error = %v, want local api token error", err)
	}
}

func TestRelativeRecordName(t *testing.T) {
	t.Parallel()

	zone := &hcloud.Zone{Name: "example.com"}
	testCases := []struct {
		name string
		fqdn string
		want string
	}{
		{name: "apex", fqdn: "example.com", want: "@"},
		{name: "subdomain", fqdn: "portal.example.com", want: "portal"},
		{name: "wildcard", fqdn: "*.example.com", want: "*"},
		{name: "nested", fqdn: "_ens.portal.example.com", want: "_ens.portal"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := relativeRecordName(tc.fqdn, zone)
			if err != nil {
				t.Fatalf("relativeRecordName() error = %v", err)
			}
			if got != tc.want {
				t.Fatalf("relativeRecordName() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestTXTContent(t *testing.T) {
	t.Parallel()

	got := txtContent(`"ENS1 0x238A8F792dFA6033814B18618aD4100654aeef01" " 0xabc"`)
	if got != "ENS1 0x238A8F792dFA6033814B18618aD4100654aeef01 0xabc" {
		t.Fatalf("txtContent() = %q", got)
	}
}

func TestSameRecordsIgnoresOrder(t *testing.T) {
	t.Parallel()

	a := []hcloud.ZoneRRSetRecord{{Value: "b"}, {Value: "a", Comment: "one"}}
	b := []hcloud.ZoneRRSetRecord{{Value: "a", Comment: "one"}, {Value: "b"}}
	if !sameRecords(a, b) {
		t.Fatal("sameRecords() = false, want true")
	}
}
