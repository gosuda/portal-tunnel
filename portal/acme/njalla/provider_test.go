package njalla

import (
	"context"
	"testing"
)

func TestChallengeProviderRequiresToken(t *testing.T) {
	t.Parallel()

	provider := New("")
	challengeProvider, err := provider.ChallengeProvider(context.Background())
	if challengeProvider != nil {
		t.Fatalf("ChallengeProvider() provider = %T, want nil", challengeProvider)
	}
	if err == nil || err.Error() != "njalla token is required" {
		t.Fatalf("ChallengeProvider() error = %v, want local token error", err)
	}
}

func TestRelativeRecordName(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		fqdn string
		want string
	}{
		{name: "apex", fqdn: "example.com", want: ""},
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

func TestSameRecordName(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name       string
		recordName string
		expected   string
		fqdn       string
		want       bool
	}{
		{name: "apex-empty", recordName: "", expected: "", fqdn: "example.com", want: true},
		{name: "apex-at", recordName: "@", expected: "", fqdn: "example.com", want: true},
		{name: "apex-fqdn", recordName: "example.com", expected: "", fqdn: "example.com", want: true},
		{name: "relative", recordName: "portal", expected: "portal", fqdn: "portal.example.com", want: true},
		{name: "fqdn", recordName: "portal.example.com", expected: "portal", fqdn: "portal.example.com", want: true},
		{name: "other", recordName: "www", expected: "portal", fqdn: "portal.example.com", want: false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := sameRecordName(tc.recordName, tc.expected, tc.fqdn, "example.com")
			if got != tc.want {
				t.Fatalf("sameRecordName() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestTXTContent(t *testing.T) {
	t.Parallel()

	got := txtContent(`"ENS1 0x238A8F792dFA6033814B18618aD4100654aeef01"`)
	if got != "ENS1 0x238A8F792dFA6033814B18618aD4100654aeef01" {
		t.Fatalf("txtContent() = %q", got)
	}
}
