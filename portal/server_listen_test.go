package portal

import (
	"testing"
)

func TestNormalizeServerConfigLoopbackListenAddrs(t *testing.T) {
	t.Parallel()

	cfg, err := normalizeServerConfig(ServerConfig{
		PortalURL:    "https://127.0.0.1:14017",
		IdentityPath: t.TempDir(),
		APIPort:      14017,
		SNIPort:      14443,
	})
	if err != nil {
		t.Fatalf("normalizeServerConfig() error = %v", err)
	}
	if cfg.APIListenAddr != "127.0.0.1:14017" {
		t.Fatalf("APIListenAddr = %q, want 127.0.0.1:14017", cfg.APIListenAddr)
	}
	if cfg.SNIListenAddr != "127.0.0.1:14443" {
		t.Fatalf("SNIListenAddr = %q, want 127.0.0.1:14443", cfg.SNIListenAddr)
	}
}

func TestNormalizeServerConfigPublicListenAddrs(t *testing.T) {
	t.Parallel()

	cfg, err := normalizeServerConfig(ServerConfig{
		PortalURL:    "https://relay.example:4017",
		IdentityPath: t.TempDir(),
		APIPort:      4017,
		SNIPort:      443,
	})
	if err != nil {
		t.Fatalf("normalizeServerConfig() error = %v", err)
	}
	if cfg.APIListenAddr != ":4017" {
		t.Fatalf("APIListenAddr = %q, want :4017", cfg.APIListenAddr)
	}
	if cfg.SNIListenAddr != ":443" {
		t.Fatalf("SNIListenAddr = %q, want :443", cfg.SNIListenAddr)
	}
}
