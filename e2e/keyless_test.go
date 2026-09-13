package e2e_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gosuda/portal-tunnel/v2/portal"
	"github.com/gosuda/portal-tunnel/v2/portal/acme"
)

func TestCertificateSignerMismatchRejectsStartup(t *testing.T) {
	certPEM, _ := localTLSMaterial(t, t.TempDir())
	_, otherKeyPEM := localTLSMaterial(t, t.TempDir())

	stateDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(stateDir, "fullchain.pem"), certPEM, 0o600); err != nil {
		t.Fatalf("write certificate: %v", err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "privatekey.pem"), otherKeyPEM, 0o600); err != nil {
		t.Fatalf("write private key: %v", err)
	}

	relay, err := portal.NewServer(portal.ServerConfig{
		PortalURL:     "https://localhost",
		StateDir:      stateDir,
		APIListenAddr: "127.0.0.1:0",
		SNIListenAddr: "127.0.0.1:0",
	})
	if err != nil {
		t.Fatalf("create relay: %v", err)
	}
	err = relay.Start(context.Background(), nil)
	if err == nil {
		_ = relay.Shutdown(context.Background())
		t.Fatal("start relay with mismatched certificate and signer succeeded")
	}
	if !strings.Contains(err.Error(), "private key does not match public key") {
		t.Fatalf("start error = %q, want key mismatch", err)
	}
}

func localTLSMaterial(t *testing.T, keyDir string) ([]byte, []byte) {
	t.Helper()
	manager, err := acme.NewManager(acme.Config{BaseDomain: "localhost", KeyDir: keyDir})
	if err != nil {
		t.Fatalf("create local certificate manager: %v", err)
	}
	certPEM, keyPEM, err := manager.EnsureTLSMaterial(context.Background())
	if err != nil {
		t.Fatalf("create local certificate: %v", err)
	}
	return certPEM, keyPEM
}
