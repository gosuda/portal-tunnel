package e2e_test

import (
	"net/url"
	"testing"
)

// TestCanonicalTunnel verifies that a registered tunnel receives a public URL on the
// same port as the relay's PORTAL_URL and that the public URL serves tenant traffic.
func TestCanonicalTunnel(t *testing.T) {
	h := newHarness(t)
	publicURL := h.waitForPublicURL()
	publicOrigin, err := url.Parse(publicURL)
	if err != nil {
		t.Fatalf("parse public URL: %v", err)
	}
	portalOrigin, err := url.Parse(h.server.PortalURL())
	if err != nil {
		t.Fatalf("parse portal URL: %v", err)
	}
	if publicOrigin.Port() != portalOrigin.Port() {
		t.Fatalf("public URL port = %q, want canonical PORTAL_URL port %q", publicOrigin.Port(), portalOrigin.Port())
	}
	if got := h.get(publicURL); got != marker {
		t.Fatalf("tenant response = %q, want %q", got, marker)
	}
}
