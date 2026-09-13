package e2e_test

import (
	"strconv"
	"strings"
	"testing"

	"github.com/gosuda/portal-tunnel/v2/portal"
)

func TestLocalSNIPortWithoutPublicPortFailsFast(t *testing.T) {
	_, err := portal.NewServer(portal.ServerConfig{
		PortalURL: "https://localhost",
		StateDir:  t.TempDir(),
		SNIPort:   8443,
	})
	if err == nil {
		t.Fatal("NewServer() error = nil, want validation error for portless local URL with non-default SNI port")
	}
	if !strings.Contains(err.Error(), "PORTAL_URL") {
		t.Fatalf("error %q does not mention PORTAL_URL", err.Error())
	}
	if !strings.Contains(err.Error(), "SNI_PORT") {
		t.Fatalf("error %q does not mention SNI_PORT", err.Error())
	}
}

func TestCanonicalTunnelThroughLocalSNIOrigin(t *testing.T) {
	apiPort := harnessPort(t)
	sniPort := harnessPort(t)
	relayURL := "https://localhost:" + strconv.Itoa(sniPort)
	h := newHarnessWithRelayURL(t, relayURL, portal.ServerConfig{
		PortalURL:     relayURL,
		StateDir:      t.TempDir(),
		APIListenAddr: "127.0.0.1:" + strconv.Itoa(apiPort),
		SNIListenAddr: "127.0.0.1:" + strconv.Itoa(sniPort),
		SNIPort:       sniPort,
	})
	publicURL := h.waitForPublicURL()
	if got := h.get(publicURL); got != marker {
		t.Fatalf("tenant response = %q, want %q", got, marker)
	}
}
