package e2e_test

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal"
)

// A relay restart drops the in-memory lease registry and kills the live
// reverse sessions. When the relay restarts with the same signing
// identity, the listener's stored credentials answer "lease not found"
// once it is back, and the SDK re-registers on its own. This test pins
// that recovery so a relay restart never requires restarting the SDK
// application (issue #471); the rotated-authority variant lives in
// authority_rotation_test.go.
func TestExposureReRegistersAfterRelayRestart(t *testing.T) {
	h := newHarness(t)
	publicURL := h.waitForPublicURL()
	if got := h.get(publicURL); got != marker {
		t.Fatalf("tenant response before restart = %q, want %q", got, marker)
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
	// the restarted relay re-verifies nothing the SDK pinned.
	restarted, err := portal.NewServer(portal.ServerConfig{
		PortalURL:     "https://127.0.0.1:" + strconv.Itoa(h.sniPort),
		StateDir:      h.stateDir,
		SNIListenAddr: "127.0.0.1:" + strconv.Itoa(h.sniPort),
		SNIPort:       h.sniPort,
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
	t.Fatal("exposure did not route again after relay restart")
}
