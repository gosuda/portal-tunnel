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

func TestRecordName(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		raw     string
		want    string
		wantErr string
	}{
		{name: "normalized", raw: "Portal.Example.COM.", want: "portal.example.com"},
		{name: "empty", raw: "", wantErr: "record name is required"},
		{name: "blank", raw: "   ", wantErr: "record name is required"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := RecordName(tc.raw)
			if tc.wantErr != "" {
				if err == nil || err.Error() != tc.wantErr {
					t.Fatalf("RecordName() error = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("RecordName() error = %v", err)
			}
			if got != tc.want {
				t.Fatalf("RecordName() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestBaseDomain(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		raw     string
		want    string
		wantErr string
	}{
		{name: "normalized", raw: "Example.COM.", want: "example.com"},
		{name: "empty", raw: "", wantErr: "base domain is required"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := BaseDomain(tc.raw)
			if tc.wantErr != "" {
				if err == nil || err.Error() != tc.wantErr {
					t.Fatalf("BaseDomain() error = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("BaseDomain() error = %v", err)
			}
			if got != tc.want {
				t.Fatalf("BaseDomain() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestARecordInputs(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name       string
		recordName string
		publicIPv4 string
		want       string
		wantErr    string
	}{
		{name: "valid", recordName: "example.com", publicIPv4: "203.0.113.10", want: "example.com"},
		{name: "empty name", recordName: "", publicIPv4: "203.0.113.10", wantErr: "record name is required"},
		{name: "invalid ip", recordName: "example.com", publicIPv4: "not-an-ip", wantErr: `invalid ipv4 address: "not-an-ip"`},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := ARecordInputs(tc.recordName, tc.publicIPv4)
			if tc.wantErr != "" {
				if err == nil || err.Error() != tc.wantErr {
					t.Fatalf("ARecordInputs() error = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ARecordInputs() error = %v", err)
			}
			if got != tc.want {
				t.Fatalf("ARecordInputs() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestARecordsInputs(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name       string
		baseDomain string
		publicIPv4 string
		want       string
		wantErr    string
	}{
		{name: "valid", baseDomain: "example.com", publicIPv4: "203.0.113.10", want: "example.com"},
		{name: "empty domain", baseDomain: "", publicIPv4: "203.0.113.10", wantErr: "base domain is required"},
		{name: "invalid ip", baseDomain: "example.com", publicIPv4: "not-an-ip", wantErr: `invalid ipv4 address: "not-an-ip"`},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := ARecordsInputs(tc.baseDomain, tc.publicIPv4)
			if tc.wantErr != "" {
				if err == nil || err.Error() != tc.wantErr {
					t.Fatalf("ARecordsInputs() error = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ARecordsInputs() error = %v", err)
			}
			if got != tc.want {
				t.Fatalf("ARecordsInputs() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestTXTInputs(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name       string
		recordName string
		value      string
		wantName   string
		wantValue  string
		wantErr    string
	}{
		{name: "valid", recordName: "_ens.example.com", value: " portal ", wantName: "_ens.example.com", wantValue: "portal"},
		{name: "empty name", recordName: "", value: "portal", wantErr: "record name is required"},
		{name: "empty value", recordName: "_ens.example.com", value: "  ", wantErr: "txt record value is required"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			gotName, gotValue, err := TXTInputs(tc.recordName, tc.value)
			if tc.wantErr != "" {
				if err == nil || err.Error() != tc.wantErr {
					t.Fatalf("TXTInputs() error = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("TXTInputs() error = %v", err)
			}
			if gotName != tc.wantName || gotValue != tc.wantValue {
				t.Fatalf("TXTInputs() = %q, %q, want %q, %q", gotName, gotValue, tc.wantName, tc.wantValue)
			}
		})
	}
}

func TestTXTPrefixInputs(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		recordName  string
		matchPrefix string
		wantName    string
		wantPrefix  string
		wantErr     string
	}{
		{name: "valid", recordName: "_ens.example.com", matchPrefix: " portal", wantName: "_ens.example.com", wantPrefix: "portal"},
		{name: "empty name", recordName: "", matchPrefix: "portal", wantErr: "record name is required"},
		{name: "empty prefix", recordName: "_ens.example.com", matchPrefix: "", wantErr: "txt record match prefix is required"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			gotName, gotPrefix, err := TXTPrefixInputs(tc.recordName, tc.matchPrefix)
			if tc.wantErr != "" {
				if err == nil || err.Error() != tc.wantErr {
					t.Fatalf("TXTPrefixInputs() error = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("TXTPrefixInputs() error = %v", err)
			}
			if gotName != tc.wantName || gotPrefix != tc.wantPrefix {
				t.Fatalf("TXTPrefixInputs() = %q, %q, want %q, %q", gotName, gotPrefix, tc.wantName, tc.wantPrefix)
			}
		})
	}
}

func TestApexWildcard(t *testing.T) {
	t.Parallel()

	got := ApexWildcard("example.com")
	if len(got) != 2 || got[0] != "example.com" || got[1] != "*.example.com" {
		t.Fatalf("ApexWildcard() = %v", got)
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
