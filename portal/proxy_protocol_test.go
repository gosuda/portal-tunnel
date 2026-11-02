package portal

import "testing"

func TestProxyProtocolTrustedIPs(t *testing.T) {
	for _, raw := range []string{"10.0.0.0/8", "0.0.0.0", "::", "ff02::1", "fe80::1%eth0", "proxy.example.com", ""} {
		t.Run(raw, func(t *testing.T) {
			if _, err := ValidateServerConfig(ServerConfig{PortalURL: "https://localhost", StateDir: t.TempDir(), ProxyProtocolTrustedIPs: []string{raw}}); err == nil {
				t.Fatal("accepted a non-concrete trusted proxy IP")
			}
		})
	}
	cfg, err := ValidateServerConfig(ServerConfig{
		PortalURL: "https://localhost", StateDir: t.TempDir(),
		ProxyProtocolTrustedIPs: []string{" 127.0.0.1 ", "::ffff:127.0.0.1", "2001:db8::1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.ProxyProtocolTrustedIPs) != 2 || cfg.ProxyProtocolTrustedIPs[0] != "127.0.0.1" || cfg.ProxyProtocolTrustedIPs[1] != "2001:db8::1" {
		t.Fatalf("trusted IPs = %v", cfg.ProxyProtocolTrustedIPs)
	}
}
