package dnsrecord

import "testing"

// TestHTTPSRecordContent protects the invariant that HTTPSRecord normalization
// produces a dot-terminated target and a default priority of 1, and that the
// wire-format Content() output matches the RFC 9460 SvcParams syntax.
func TestHTTPSRecordContent(t *testing.T) {
	record, err := (HTTPSRecord{Target: "public.example.com", SvcParams: `ech="config" port=8443`}).Normalized()
	if err != nil {
		t.Fatalf("Normalized() error = %v", err)
	}
	if record.Priority != 1 || record.Target != "public.example.com." {
		t.Fatalf("Normalized() = %#v", record)
	}
	content, err := record.Content()
	if err != nil {
		t.Fatalf("Content() error = %v", err)
	}
	if content != `1 public.example.com. ech="config" port=8443` {
		t.Fatalf("Content() = %q", content)
	}
}

// TestRelativeName protects the invariant that RelativeName converts fully-qualified
// domain names to the provider-specific relative form, handles the apex as "@",
// and rejects names outside the zone with a descriptive error.
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

// TestNameMatches protects the invariant that NameMatches accepts the relative,
// apex, and fully-qualified record-name forms as equivalent, so that provider
// API responses round-trip correctly regardless of which form they return.
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

// TestTXTContent protects the invariant that TXTContent unquotes and trims TXT
// record values returned by DNS provider APIs, so that assertion comparisons are
// stable regardless of whether the provider includes surrounding quotes.
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
