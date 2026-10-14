package portal

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/gosuda/portal-tunnel/v2/types"
)

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
		name          string
		portalURL     string
		localSNIPort  int
		wantLocalPort int
	}{
		{"default ports", "https://relay.example.com", 0, 443},
		{"local bind override", "https://relay.example.com", 8443, 8443},
		{"explicit public port", "https://relay.example.com:9443", 443, 443},
		{"unoverridden listener follows public port", "https://relay.example.com:9443", 0, 9443},
		{"explicit override keeps mapped listener", "https://localhost:8443", 443, 443},
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
		})
	}
}

func TestRegisterLeaseWithUDPAndRawTCP(t *testing.T) {
	registry := newTestRegistry(t, true, true)
	_, resp, err := registry.Register(types.RegisterChallengeRequest{
		Identity:   newTestLeaseIdentity(t, "demo"),
		UDPEnabled: true,
		TCPEnabled: true,
	}, netip.MustParseAddr("203.0.113.10"), "", types.RelayDescriptor{}, nil)
	if err != nil {
		t.Fatalf("registry.Register() error = %v", err)
	}
	if !resp.UDPEnabled || !resp.TCPEnabled || resp.UDPAddr == "" || resp.TCPAddr == "" {
		t.Fatalf("RegisterResponse transports = %+v, want UDP and raw TCP endpoints", resp)
	}
	if _, ok := registry.Lookup("demo.example.com"); !ok {
		t.Fatal("Lookup(derived public hostname) = false, want registered lease")
	}
}

func TestRawPortsAreAllocatedPerIdentity(t *testing.T) {
	registry := newTestRegistry(t, true, true)
	register := func(clientIP string) types.RegisterResponse {
		t.Helper()
		_, resp, err := registry.Register(types.RegisterChallengeRequest{
			AllowCanonicalFallback: true,
			Identity:               newTestLeaseIdentity(t, "shared"),
			UDPEnabled:             true,
			TCPEnabled:             true,
		}, netip.MustParseAddr(clientIP), "", types.RelayDescriptor{}, nil)
		if err != nil {
			t.Fatalf("registry.Register() error = %v", err)
		}
		return resp
	}

	first := register("203.0.113.10")
	second := register("203.0.113.11")
	if first.UDPAddr == second.UDPAddr || first.TCPAddr == second.TCPAddr {
		t.Fatalf("different identities shared raw endpoints: first=%+v second=%+v", first, second)
	}
}
