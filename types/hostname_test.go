package types

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
