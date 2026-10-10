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

func TestAddressRecordInputs(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name       string
		recordName string
		publicIP   string
		wantName   string
		wantType   string
		wantIP     string
		wantErr    string
	}{
		{name: "ipv4", recordName: "Portal.Example.COM.", publicIP: "203.0.113.10", wantName: "portal.example.com", wantType: "A", wantIP: "203.0.113.10"},
		{name: "ipv6", recordName: "Portal.Example.COM.", publicIP: " 2001:0DB8:0000:0000:0000:0000:0000:0010 ", wantName: "portal.example.com", wantType: "AAAA", wantIP: "2001:db8::10"},
		{name: "mapped ipv4", recordName: "portal.example.com", publicIP: "::ffff:203.0.113.10", wantName: "portal.example.com", wantType: "A", wantIP: "203.0.113.10"},
		{name: "trimmed ipv4", recordName: "portal.example.com", publicIP: " 203.0.113.10 ", wantName: "portal.example.com", wantType: "A", wantIP: "203.0.113.10"},
		{name: "empty name", recordName: "", publicIP: "2001:db8::10", wantErr: "record name is required"},
		{name: "invalid ip", recordName: "portal.example.com", publicIP: "not-an-ip", wantErr: `invalid ip address: "not-an-ip"`},
		{name: "ip with port", recordName: "portal.example.com", publicIP: "[2001:db8::10]:443", wantErr: `invalid ip address: "[2001:db8::10]:443"`},
		{name: "scoped ip", recordName: "portal.example.com", publicIP: "fe80::1%eth0", wantErr: `invalid ip address: "fe80::1%eth0"`},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			name, recordType, ip, err := AddressRecordInputs(tc.recordName, tc.publicIP)
			if tc.wantErr != "" {
				if err == nil || err.Error() != tc.wantErr {
					t.Fatalf("AddressRecordInputs() error = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("AddressRecordInputs() error = %v", err)
			}
			if name != tc.wantName || recordType != tc.wantType || ip != tc.wantIP {
				t.Fatalf("AddressRecordInputs() = (%q, %q, %q), want (%q, %q, %q)", name, recordType, ip, tc.wantName, tc.wantType, tc.wantIP)
			}
		})
	}
}

func TestAddressRecordsInputs(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name       string
		baseDomain string
		publicIP   string
		wantDomain string
		wantType   string
		wantIP     string
		wantErr    string
	}{
		{name: "ipv4", baseDomain: "*.Example.COM.", publicIP: "203.0.113.10", wantDomain: "example.com", wantType: "A", wantIP: "203.0.113.10"},
		{name: "ipv6", baseDomain: "Example.COM.", publicIP: " 2001:0DB8::0010 ", wantDomain: "example.com", wantType: "AAAA", wantIP: "2001:db8::10"},
		{name: "mapped ipv4", baseDomain: "example.com", publicIP: "::ffff:203.0.113.10", wantDomain: "example.com", wantType: "A", wantIP: "203.0.113.10"},
		{name: "empty domain", baseDomain: "", publicIP: "2001:db8::10", wantErr: "base domain is required"},
		{name: "invalid ip", baseDomain: "example.com", publicIP: "not-an-ip", wantErr: `invalid ip address: "not-an-ip"`},
		{name: "scoped ip", baseDomain: "example.com", publicIP: "fe80::1%eth0", wantErr: `invalid ip address: "fe80::1%eth0"`},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			domain, recordType, ip, err := AddressRecordsInputs(tc.baseDomain, tc.publicIP)
			if tc.wantErr != "" {
				if err == nil || err.Error() != tc.wantErr {
					t.Fatalf("AddressRecordsInputs() error = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("AddressRecordsInputs() error = %v", err)
			}
			if domain != tc.wantDomain || recordType != tc.wantType || ip != tc.wantIP {
				t.Fatalf("AddressRecordsInputs() = (%q, %q, %q), want (%q, %q, %q)", domain, recordType, ip, tc.wantDomain, tc.wantType, tc.wantIP)
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
