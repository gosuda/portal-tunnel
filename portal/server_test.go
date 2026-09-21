package portal

import (
	"strings"
	"testing"

	"github.com/gosuda/portal-tunnel/v2/types"
)

// The runtime rejects an unparseable proxy CIDR allowlist inside
// policy.NewRuntime; validation must parse it the same way so `relay-server
// config` cannot call a list valid that startup rejects.
func TestValidateServerConfigRejectsInvalidTrustedProxyCIDRs(t *testing.T) {
	cfg := ServerConfig{
		PortalURL:         "https://localhost:4017",
		StateDir:          t.TempDir(),
		TrustedProxyCIDRs: "192.0.2.0/24,not-a-cidr",
	}
	if _, err := ValidateServerConfig(cfg); err == nil {
		t.Fatal("ValidateServerConfig() error = nil, want error for invalid trusted proxy CIDR")
	}
	cfg.TrustedProxyCIDRs = "192.0.2.0/24,2001:db8::/32"
	if _, err := ValidateServerConfig(cfg); err != nil {
		t.Fatalf("ValidateServerConfig() error = %v, want nil for valid CIDR list", err)
	}
	cfg.TrustedProxyCIDRs = ""
	if _, err := ValidateServerConfig(cfg); err != nil {
		t.Fatalf("ValidateServerConfig() error = %v, want nil for empty CIDR list", err)
	}
}

func TestNewServerRejectsPortalURLCredentialsWithoutEchoingThem(t *testing.T) {
	_, err := NewServer(ServerConfig{
		PortalURL: "https://user:secret@localhost",
		StateDir:  t.TempDir(),
	})
	if err == nil {
		t.Fatal("NewServer() error = nil, want credential rejection")
	}
	if strings.Contains(err.Error(), "user") || strings.Contains(err.Error(), "secret") {
		t.Fatalf("NewServer() error exposes PORTAL_URL credentials: %q", err)
	}
}

func TestHTTPRedirectTargetValidation(t *testing.T) {
	for _, target := range []string{"http://localhost:4017", "http://relay.example", "//relay.example", "https://user:pass@relay.example", "https://relay.example:0", "https://relay.example:65536", "https://relay.example:bad", "https://relay.example:", "https:///missing-host", "https://./"} {
		t.Run(target, func(t *testing.T) {
			if _, err := NormalizeHTTPRedirectConfig(types.HTTPRedirectConfig{Enabled: true}, target); err == nil {
				t.Fatal("NormalizeHTTPRedirectConfig() error = nil, want invalid redirect target rejection")
			}
		})
	}

	// net/url accepts HTTPS schemes regardless of their spelling.
	for _, hsts := range []bool{false, true} {
		scheme := "HTTPS"
		if hsts {
			scheme = "hTtPs"
		}
		t.Run(scheme, func(t *testing.T) {
			cfg, err := NormalizeHTTPRedirectConfig(types.HTTPRedirectConfig{
				Enabled: true,
				HSTS:    hsts,
			}, scheme+"://localhost:4017/base/?configured=discarded#fragment")
			if err != nil {
				t.Fatalf("NormalizeHTTPRedirectConfig() error = %v, want %q scheme accepted", err, scheme)
			}
			if !cfg.Enabled || cfg.Addr != types.DefaultHTTPRedirectAddr || cfg.HSTS != hsts {
				t.Fatalf("NormalizeHTTPRedirectConfig() cfg = %+v, want enabled config with default redirect address and hsts=%v", cfg, hsts)
			}
		})
	}
}

func TestNewServerSeparatesPublicAndLocalSNIPorts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		portalURL      string
		localSNIPort   int
		wantLocalPort  int
		wantPublicPort int
	}{
		{"default ports", "https://relay.example.com", 0, 443, 443},
		{"local bind override", "https://relay.example.com", 8443, 8443, 443},
		{"explicit public port", "https://relay.example.com:9443", 443, 443, 9443},
		{"unoverridden listener follows public port", "https://relay.example.com:9443", 0, 9443, 9443},
		{"explicit override keeps mapped listener", "https://localhost:8443", 443, 443, 8443},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg, err := ValidateServerConfig(ServerConfig{
				PortalURL: tc.portalURL,
				StateDir:  t.TempDir(),
				SNIPort:   tc.localSNIPort,
			})
			if err != nil {
				t.Fatalf("ValidateServerConfig() error = %v", err)
			}
			if got := cfg.SNIPort; got != tc.wantLocalPort {
				t.Fatalf("ServerConfig.SNIPort = %d, want local port %d", got, tc.wantLocalPort)
			}
			// DefaultSNIPort is the shared derivation: the public port is the
			// PORTAL_URL port, and an unoverridden local listener follows it.
			if got := DefaultSNIPort(cfg.PortalURL); got != tc.wantPublicPort {
				t.Fatalf("DefaultSNIPort(%q) = %d, want public port %d", cfg.PortalURL, got, tc.wantPublicPort)
			}
		})
	}
}

func TestRegisterLeaseWithUDPAndRawTCP(t *testing.T) {
	t.Parallel()

	registry := newTestRegistry(t, true, true)
	_, resp, err := registry.Register(types.RegisterChallengeRequest{
		Identity:   newTestLeaseIdentity(t, "demo"),
		UDPEnabled: true,
		TCPEnabled: true,
	}, "203.0.113.10", "", types.RelayDescriptor{}, nil)
	if err != nil {
		t.Fatalf("registry.Register() error = %v", err)
	}
	if resp.SNIPort != 443 {
		t.Fatalf("RegisterResponse.SNIPort = %d, want registry public port 443", resp.SNIPort)
	}
	if !resp.UDPEnabled || !resp.TCPEnabled || resp.UDPAddr == "" || resp.TCPAddr == "" {
		t.Fatalf("RegisterResponse transports = %+v, want UDP and raw TCP endpoints", resp)
	}
	if _, ok := registry.Lookup("demo.example.com"); !ok {
		t.Fatal("Lookup(derived public hostname) = false, want registered lease")
	}
}
