package e2e_test

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal"
	"github.com/gosuda/portal-tunnel/v2/portal/identity"
)

// A relay restart that rotates its lease signing authority while keeping
// its TLS identity drops the in-memory lease registry, so the listener's
// stored access token and reverse capability now answer "unauthorized"
// instead of "lease not found". The SDK must classify that answer as a
// lost lease and re-register on its own; restarting the application must
// never be required (issue #471). ServerConfig.LeaseAuthorityPath models
// the rotation without reaching into relay internals; the same-authority
// restart variant lives in restart_recovery_test.go.
func TestExposureReRegistersAfterAuthorityRotation(t *testing.T) {
	h := newHarness(t)
	publicURL := h.waitForPublicURL()
	if got := h.get(publicURL); got != marker {
		t.Fatalf("tenant response before rotation = %q, want %q", got, marker)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := h.server.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("shutdown relay: %v", err)
	}
	if err := h.server.Wait(); err != nil {
		t.Fatalf("wait for relay shutdown: %v", err)
	}

	// The same state dir keeps the relay identity and TLS materials, so
	// the restarted relay keeps the identity the exposure pinned. Only
	// the lease signing authority rotates: the fresh registry is empty,
	// and its authority no longer verifies the listener's stored
	// credentials.
	rotatedPath := filepath.Join(t.TempDir(), "rotated-lease-authority.json")
	rotated, err := identity.Generate("rotated")
	if err != nil {
		t.Fatalf("generate rotated authority identity: %v", err)
	}
	raw, err := identity.Marshal(rotated)
	if err != nil {
		t.Fatalf("marshal rotated authority identity: %v", err)
	}
	if err := os.WriteFile(rotatedPath, raw, 0o600); err != nil {
		t.Fatalf("write rotated authority identity: %v", err)
	}
	restarted, err := portal.NewServer(portal.ServerConfig{
		PortalURL:          "https://127.0.0.1:" + strconv.Itoa(h.sniPort),
		StateDir:           h.stateDir,
		APIListenAddr:      "127.0.0.1:" + strconv.Itoa(h.apiPort),
		SNIListenAddr:      "127.0.0.1:" + strconv.Itoa(h.sniPort),
		SNIPort:            h.sniPort,
		LeaseAuthorityPath: rotatedPath,
	})
	if err != nil {
		t.Fatalf("create restarted relay: %v", err)
	}
	serverCtx, serverCancel := context.WithCancel(context.Background())
	t.Cleanup(serverCancel)
	if err := restarted.Start(serverCtx, nil); err != nil {
		t.Fatalf("start restarted relay: %v", err)
	}
	h.server = restarted

	// The exposure must recover without being recreated: a complete new
	// registration, fresh reverse sessions, and the public hostname
	// routing again.
	deadline := time.Now().Add(45 * time.Second)
	for {
		if got, ok := h.tryGet(publicURL); ok && got == marker {
			return
		}
		if !time.Now().Before(deadline) {
			break
		}
		<-time.After(250 * time.Millisecond)
	}
	t.Fatal("exposure did not route again after relay restart with rotated authority")
}
