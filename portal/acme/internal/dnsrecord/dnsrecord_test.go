package dnsrecord

import "testing"

func TestRelativeName(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		provider string
		fqdn     string
		zone     string
		want     string
		wantErr  string
	}{
		{name: "apex", provider: "njalla", fqdn: "example.com", zone: "example.com", want: "@"},
		{name: "normalized subdomain", provider: "vultr", fqdn: "Portal.Example.COM.", zone: "EXAMPLE.COM.", want: "portal"},
		{name: "wildcard", provider: "njalla", fqdn: "*.example.com", zone: "example.com", want: "*"},
		{name: "nested", provider: "vultr", fqdn: "_ens.portal.example.com", zone: "example.com", want: "_ens.portal"},
		{name: "missing record name", provider: "njalla", zone: "example.com", wantErr: "record name is required"},
		{name: "missing zone", provider: "vultr", fqdn: "portal.example.com", wantErr: "vultr zone is required"},
		{
			name:     "outside zone",
			provider: "njalla",
			fqdn:     "portal.other.com",
			zone:     "example.com",
			wantErr:  `hostname "portal.other.com" is outside njalla zone "example.com"`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := RelativeName(tc.provider, tc.fqdn, tc.zone)
			if tc.wantErr != "" {
				if err == nil || err.Error() != tc.wantErr {
					t.Fatalf("RelativeName() error = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("RelativeName() error = %v", err)
			}
			if got != tc.want {
				t.Fatalf("RelativeName() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestNameMatches(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name       string
		recordName string
		expected   string
		fqdn       string
		zone       string
		want       bool
	}{
		{name: "relative", recordName: "portal", expected: "portal", fqdn: "portal.example.com", zone: "example.com", want: true},
		{name: "empty apex", recordName: "", expected: "@", fqdn: "example.com", zone: "example.com", want: true},
		{name: "zone apex", recordName: "example.com.", expected: "@", fqdn: "example.com", zone: "example.com", want: true},
		{name: "fully qualified", recordName: "PORTAL.EXAMPLE.COM.", expected: "portal", fqdn: "portal.example.com", zone: "example.com", want: true},
		{name: "different record", recordName: "other", expected: "portal", fqdn: "portal.example.com", zone: "example.com", want: false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := NameMatches(tc.recordName, tc.expected, tc.fqdn, tc.zone); got != tc.want {
				t.Fatalf("NameMatches() = %t, want %t", got, tc.want)
			}
		})
	}
}

func TestTXTContent(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		raw  string
		want string
	}{
		{name: "quoted", raw: `"portal"`, want: "portal"},
		{name: "unquoted", raw: "portal", want: "portal"},
		{name: "trimmed", raw: `  "portal"  `, want: "portal"},
		{name: "escaped", raw: `"portal\nrelay"`, want: "portal\nrelay"},
		{name: "malformed quote", raw: `"portal`, want: "portal"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := TXTContent(tc.raw); got != tc.want {
				t.Fatalf("TXTContent() = %q, want %q", got, tc.want)
			}
		})
	}
}
