package utils

import "testing"

func TestSanitizeReportedIP(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  string
		want string
	}{
		{name: "empty", raw: "", want: ""},
		{name: "whitespace", raw: "   ", want: ""},
		{name: "ipv4", raw: " 203.0.113.10 ", want: "203.0.113.10"},
		{name: "ipv6", raw: " 2001:db8::1 ", want: "2001:db8::1"},
		{name: "invalid", raw: "not-an-ip", want: ""},
		{name: "host port", raw: "203.0.113.10:443", want: ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := SanitizeReportedIP(tc.raw); got != tc.want {
				t.Fatalf("SanitizeReportedIP(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

func TestSanitizeReportedPublicIPs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		reportedIP   string
		reportedIPv4 string
		reportedIPv6 string
		wantIPv4     string
		wantIPv6     string
	}{
		{
			name:       "legacy ipv4 fills ipv4 slot",
			reportedIP: "203.0.113.10",
			wantIPv4:   "203.0.113.10",
		},
		{
			name:       "legacy ipv6 fills ipv6 slot",
			reportedIP: "2001:db8::10",
			wantIPv6:   "2001:db8::10",
		},
		{
			name:         "explicit fields win",
			reportedIP:   "2001:db8::10",
			reportedIPv4: "203.0.113.10",
			reportedIPv6: "2001:db8::11",
			wantIPv4:     "203.0.113.10",
			wantIPv6:     "2001:db8::11",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := SanitizeReportedPublicIPs(tc.reportedIP, tc.reportedIPv4, tc.reportedIPv6)
			if got.IPv4 != tc.wantIPv4 || got.IPv6 != tc.wantIPv6 {
				t.Fatalf("SanitizeReportedPublicIPs() = %#v, want IPv4=%q IPv6=%q", got, tc.wantIPv4, tc.wantIPv6)
			}
		})
	}
}

func TestNormalizePublicIPs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		publicIPs PublicIPs
		want      PublicIPs
		wantErr   bool
	}{
		{
			name:      "dual stack",
			publicIPs: PublicIPs{IPv4: " 203.0.113.10 ", IPv6: " 2001:db8::10 "},
			want:      PublicIPs{IPv4: "203.0.113.10", IPv6: "2001:db8::10"},
		},
		{
			name:      "ipv6 only",
			publicIPs: PublicIPs{IPv6: "2001:db8::10"},
			want:      PublicIPs{IPv6: "2001:db8::10"},
		},
		{
			name:      "reject empty",
			publicIPs: PublicIPs{},
			wantErr:   true,
		},
		{
			name:      "reject invalid ipv4",
			publicIPs: PublicIPs{IPv4: "not-an-ip"},
			wantErr:   true,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := NormalizePublicIPs(tc.publicIPs)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("NormalizePublicIPs(%#v) error = nil, want error", tc.publicIPs)
				}
				return
			}
			if err != nil {
				t.Fatalf("NormalizePublicIPs(%#v) error = %v", tc.publicIPs, err)
			}
			if got != tc.want {
				t.Fatalf("NormalizePublicIPs(%#v) = %#v, want %#v", tc.publicIPs, got, tc.want)
			}
		})
	}
}

func TestResolveHostIPFamiliesLiteralIP(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		host     string
		wantIPv4 bool
		wantIPv6 bool
	}{
		{name: "ipv4 literal", host: "203.0.113.10", wantIPv4: true},
		{name: "ipv6 literal", host: "2001:db8::10", wantIPv6: true},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			gotIPv4, gotIPv6, err := ResolveHostIPFamilies(t.Context(), tc.host)
			if err != nil {
				t.Fatalf("ResolveHostIPFamilies(%q) error = %v", tc.host, err)
			}
			if gotIPv4 != tc.wantIPv4 || gotIPv6 != tc.wantIPv6 {
				t.Fatalf("ResolveHostIPFamilies(%q) = (%t, %t), want (%t, %t)", tc.host, gotIPv4, gotIPv6, tc.wantIPv4, tc.wantIPv6)
			}
		})
	}
}
