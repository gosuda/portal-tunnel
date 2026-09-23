package utils

import (
	"strings"
	"testing"
)

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

func TestLeaseHostname(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		raw     string
		root    string
		want    string
		wantErr bool
	}{
		{name: "composes child hostname", raw: "demo", root: "example.com", want: "demo.example.com"},
		{name: "normalizes name and root", raw: "My App", root: "Example.COM.", want: "my-app.example.com"},
		{name: "rejects empty name", raw: "", root: "example.com", wantErr: true},
		{name: "rejects punctuation-only name", raw: "!!!", root: "example.com", wantErr: true},
		{name: "rejects over-long name", raw: strings.Repeat("a", 64), root: "example.com", wantErr: true},
		{name: "rejects empty root host", raw: "demo", root: "", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := LeaseHostname(tt.raw, tt.root)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("LeaseHostname(%q, %q) error = nil, want invalid label error", tt.raw, tt.root)
				}
				return
			}
			if err != nil {
				t.Fatalf("LeaseHostname(%q, %q) error = %v", tt.raw, tt.root, err)
			}
			if got != tt.want {
				t.Fatalf("LeaseHostname(%q, %q) = %q, want %q", tt.raw, tt.root, got, tt.want)
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
