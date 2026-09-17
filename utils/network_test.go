package utils

import "testing"

// TestSanitizeReportedIP verifies that SanitizeReportedIP strips whitespace from
// valid IP literals, passes through bare addresses, and returns empty string for
// anything that is not a clean IP address.
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
