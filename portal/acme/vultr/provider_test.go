package vultr

import (
	"context"
	"testing"
)

func TestChallengeProviderRequiresAPIKey(t *testing.T) {
	t.Parallel()

	provider := New("")
	challengeProvider, err := provider.ChallengeProvider(context.Background())
	if challengeProvider != nil {
		t.Fatalf("ChallengeProvider() provider = %T, want nil", challengeProvider)
	}
	if err == nil || err.Error() != "vultr api key is required" {
		t.Fatalf("ChallengeProvider() error = %v, want local api key error", err)
	}
}

func TestRelativeRecordName(t *testing.T) {
	t.Parallel()

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

			got, err := relativeRecordName(tc.fqdn, "example.com")
			if err != nil {
				t.Fatalf("relativeRecordName() error = %v", err)
			}
			if got != tc.want {
				t.Fatalf("relativeRecordName() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestPreferredDSRecordPrefersSHA256(t *testing.T) {
	t.Parallel()

	got := preferredDSRecord([]string{
		"example.com IN DNSKEY 257 3 13 abc",
		"example.com IN DS 27933 13 1 2d9ac457e5c11a104e25d971d0a6254562bddde7",
		"example.com IN DS 27933 13 2 8858e7b0dfb881280ce2ca1e0eafcd93d5b53687c21da284d4f8799ba82208a9",
	})
	if got != "27933 13 2 8858e7b0dfb881280ce2ca1e0eafcd93d5b53687c21da284d4f8799ba82208a9" {
		t.Fatalf("preferredDSRecord() = %q", got)
	}
}
