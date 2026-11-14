package utils

import (
	"testing"
)

func TestEnsurePortHandlesBracketedIPv6(t *testing.T) {
	for _, tc := range []struct {
		name string
		host string
		want string
	}{
		{name: "loopback", host: "[::1]", want: "[::1]:443"},
		{name: "zone id", host: "[fe80::1%eth0]", want: "[fe80::1%eth0]:443"},
		{name: "existing port", host: "[::1]:8443", want: "[::1]:8443"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := EnsurePort(tc.host); got != tc.want {
				t.Fatalf("EnsurePort(%q) = %q, want %q", tc.host, got, tc.want)
			}
		})
	}
}

func TestNormalizeTargetAddrIPv6(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  string
	}{
		{input: "::1", want: "[::1]:80"},
		{input: "[::1]", want: "[::1]:80"},
		{input: "[::1]:8080", want: "[::1]:8080"},
		{input: "http://[::1]", want: "[::1]:80"},
		{input: "http://[::1]:8080", want: "[::1]:8080"},
		{input: "fe80::1%eth0", want: "[fe80::1%eth0]:80"},
		{input: "[fe80::1%eth0]", want: "[fe80::1%eth0]:80"},
		{input: "http://[fe80::1%25eth0]", want: "[fe80::1%eth0]:80"},
	} {
		t.Run(tc.input, func(t *testing.T) {
			got, err := NormalizeTargetAddr(tc.input)
			if err != nil {
				t.Fatalf("NormalizeTargetAddr(%q): %v", tc.input, err)
			}
			if got != tc.want {
				t.Fatalf("NormalizeTargetAddr(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
	for _, input := range []string{"[::1", "::1]", "[not-an-ip]", "http://[not-an-ip]"} {
		t.Run(input, func(t *testing.T) {
			if got, err := NormalizeTargetAddr(input); err == nil {
				t.Fatalf("NormalizeTargetAddr(%q) = %q, want invalid address", input, got)
			}
		})
	}
}

func TestNormalizeURLPathCollapsesBackslashLedPaths(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{`/\example`, `/\`, `/\/`} {
		if got := NormalizeURLPath(raw); got != "/" {
			t.Fatalf("NormalizeURLPath(%q) = %q, want %q", raw, got, "/")
		}
	}
}
