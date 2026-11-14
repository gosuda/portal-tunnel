package utils

import (
	"errors"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

func TestNormalizeRelayURLPreservesParseErrors(t *testing.T) {
	_, err := NormalizeRelayURL("https://relay.example/%zz")
	var parseErr *url.Error
	if !errors.As(err, &parseErr) {
		t.Fatalf("NormalizeRelayURL() error = %v, want wrapped URL error", err)
	}
	var escapeErr url.EscapeError
	if !errors.As(err, &escapeErr) {
		t.Fatalf("NormalizeRelayURL() error = %v, want wrapped escape error", err)
	}

	_, err = NormalizeRelayURL("https://relay.example:" + strings.Repeat("9", 30))
	var numErr *strconv.NumError
	if !errors.As(err, &numErr) || !errors.Is(err, strconv.ErrRange) {
		t.Fatalf("NormalizeRelayURL() error = %v, want wrapped port overflow", err)
	}
}

func TestHostnameMatchesPattern(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		pattern string
		host    string
		want    bool
	}{
		{name: "exact match", pattern: "foo.example.com", host: "foo.example.com", want: true},
		{name: "wildcard matches one level", pattern: "*.example.com", host: "foo.example.com", want: true},
		{name: "wildcard rejects multi-level", pattern: "*.example.com", host: "a.b.example.com", want: false},
		{name: "wildcard rejects apex", pattern: "*.example.com", host: "example.com", want: false},
		{name: "wildcard requires dotted suffix", pattern: "*.com", host: "foo.com", want: false},
		{name: "bare star matches nothing", pattern: "*", host: "foo.example.com", want: false},
		{name: "mismatch", pattern: "bar.example.com", host: "foo.example.com", want: false},
		{name: "empty pattern", pattern: "", host: "foo.example.com", want: false},
		{name: "empty hostname", pattern: "*.example.com", host: "", want: false},
		{name: "normalizes case and trailing dot", pattern: "*.Example.COM.", host: "FOO.example.com", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := HostnameMatchesPattern(tt.pattern, tt.host); got != tt.want {
				t.Fatalf("HostnameMatchesPattern(%q, %q) = %v, want %v", tt.pattern, tt.host, got, tt.want)
			}
		})
	}
}

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

func TestRelayHostTrustBoundaries(t *testing.T) {
	for _, tc := range []struct {
		host      string
		localTLS  bool
		localOnly bool
	}{
		{"", true, true},
		{"localhost", true, true},
		{"LOCALHOST", true, true},
		{"sub.localhost", true, true},
		{"my.app.localhost.", true, true},
		{"relay.local", false, true},
		{"app.relay.LOCAL.", false, true},
		{"fe80::1%eth0", false, true},
		{"2001:4860:4860::8888%eth0", false, true},
		{"127.0.0.1", true, true},
		{"127.0.0.2", true, true},
		{"::1", true, true},
		{"relay.example.com", false, false},
		{"192.0.2.1", false, false},
		{"203.0.113.1", false, false},
	} {
		t.Run(tc.host, func(t *testing.T) {
			if got := IsLocalRelayHost(tc.host); got != tc.localTLS {
				t.Fatalf("IsLocalRelayHost(%q) = %v, want %v", tc.host, got, tc.localTLS)
			}
			if got := IsLocalOnlyRelayHost(tc.host); got != tc.localOnly {
				t.Fatalf("IsLocalOnlyRelayHost(%q) = %v, want %v", tc.host, got, tc.localOnly)
			}
		})
	}
}

func TestNormalizeHostWithoutPort(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct{ in, want string }{
		{"app.example", "app.example"},
		{"  App.Example. ", "app.example"},
		{"app.example:443", "app.example"},
		{"App.Example.:443", "app.example"},
		{"[::1]:8443", "::1"},
		{"", ""},
	} {
		if got := NormalizeHostWithoutPort(tc.in); got != tc.want {
			t.Errorf("NormalizeHostWithoutPort(%q) = %q, want %q", tc.in, got, tc.want)
		}
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
