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

func TestNormalizeLoopbackTargetPortRange(t *testing.T) {
	for input, want := range map[string]string{
		"3000":            "127.0.0.1:3000",
		":3000":           "127.0.0.1:3000",
		"abc":             "abc:80",
		"localhost:65535": "localhost:65535",
	} {
		if got, err := NormalizeLoopbackTarget(input); err != nil || got != want {
			t.Errorf("NormalizeLoopbackTarget(%q) = %q, %v, want %q", input, got, err, want)
		}
	}
	for _, input := range []string{"65536", ":65536", "localhost:65536", "localhost:0", "localhost:", "http://127.0.0.1:70000"} {
		if got, err := NormalizeLoopbackTarget(input); err == nil {
			t.Errorf("NormalizeLoopbackTarget(%q) = %q, want a port range error", input, got)
		}
	}
}

func TestNormalizeHTTPUpstream(t *testing.T) {
	for input, want := range map[string]string{
		"3000":            "http://127.0.0.1:3000/",
		"localhost:65535": "http://localhost:65535/",
		"http://localhost:3000/api/?tenant=a#top": "http://localhost:3000/api?tenant=a",
		"https://backend.example.com":             "https://backend.example.com/",
	} {
		if got, err := NormalizeHTTPUpstream(input); err != nil || got.String() != want {
			t.Errorf("NormalizeHTTPUpstream(%q) = %v, %v, want %q", input, got, err, want)
		}
	}
	for _, input := range []string{"65536", "http://localhost:65536/api", "http://localhost:0", "ftp://localhost:21", "http:///api"} {
		if got, err := NormalizeHTTPUpstream(input); err == nil {
			t.Errorf("NormalizeHTTPUpstream(%q) = %v, want an error", input, got)
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
