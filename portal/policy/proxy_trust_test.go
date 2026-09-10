package policy

import (
	"net"
	"net/http/httptest"
	"testing"
)

func TestExtractClientIPDoesNotTrustImplicitProxies(t *testing.T) {
	runtime, err := NewRuntime(false, false, true, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, peer := range []string{
		"127.0.0.1", "10.0.0.9", "172.16.0.9", "192.168.0.9",
		"169.254.0.9", "100.64.0.9", "::1", "fd00::9", "fe80::9",
		"203.0.113.9",
	} {
		t.Run(peer, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/connect", nil)
			req.RemoteAddr = net.JoinHostPort(peer, "12345")
			for _, claimed := range []string{"198.51.100.1", "198.51.100.2"} {
				req.Header.Set("X-Forwarded-For", claimed)
				req.Header.Set("X-Real-IP", claimed)
				if got := runtime.ExtractClientIP(req); got != peer {
					t.Fatalf("claimed IP %q changed source key to %q, want socket peer %q", claimed, got, peer)
				}
			}
		})
	}
}

func TestExtractClientIPHonorsConfiguredProxyBoundary(t *testing.T) {
	for _, tc := range []struct {
		name    string
		enabled bool
		cidrs   string
		peer    string
		xff     string
		xri     string
		want    string
	}{
		{name: "explicit IPv4 proxy", enabled: true, cidrs: "172.31.240.2/32", peer: "172.31.240.2", xff: "198.51.100.1", want: "198.51.100.1"},
		{name: "private sibling", enabled: true, cidrs: "172.31.240.2/32", peer: "172.31.240.3", xff: "198.51.100.1", xri: "198.51.100.2", want: "172.31.240.3"},
		{name: "headers disabled", cidrs: "172.31.240.2/32", peer: "172.31.240.2", xff: "198.51.100.1", xri: "198.51.100.2", want: "172.31.240.2"},
		{name: "explicit IPv6 proxy", enabled: true, cidrs: "172.31.240.2/32,fd00::2/128", peer: "fd00::2", xff: "2001:db8::1", want: "2001:db8::1"},
		{name: "IPv6 sibling", enabled: true, cidrs: "fd00::2/128", peer: "fd00::3", xff: "2001:db8::1", xri: "2001:db8::2", want: "fd00::3"},
		{name: "real IP fallback", enabled: true, cidrs: "172.31.240.2/32", peer: "172.31.240.2", xff: "invalid", xri: "198.51.100.2", want: "198.51.100.2"},
		{name: "invalid headers", enabled: true, cidrs: "172.31.240.2/32", peer: "172.31.240.2", xff: "invalid", xri: "invalid", want: "172.31.240.2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runtime, err := NewRuntime(false, false, tc.enabled, tc.cidrs)
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest("GET", "/api/connect", nil)
			req.RemoteAddr = net.JoinHostPort(tc.peer, "12345")
			req.Header.Set("X-Forwarded-For", tc.xff)
			req.Header.Set("X-Real-IP", tc.xri)
			if got := runtime.ExtractClientIP(req); got != tc.want {
				t.Fatalf("client IP = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestExtractClientIPRevokesRemovedProxy(t *testing.T) {
	runtime, err := NewRuntime(false, false, true, "172.31.240.2/32")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "/api/connect", nil)
	req.RemoteAddr = "172.31.240.2:12345"
	req.Header.Set("X-Forwarded-For", "198.51.100.1")
	if got := runtime.ExtractClientIP(req); got != "198.51.100.1" {
		t.Fatalf("client IP before removing proxy = %q, want forwarded address", got)
	}
	if err := runtime.SetProxyTrust(true, ""); err != nil {
		t.Fatal(err)
	}
	if got := runtime.ExtractClientIP(req); got != "172.31.240.2" {
		t.Fatalf("client IP after removing proxy = %q, want socket peer", got)
	}
}
