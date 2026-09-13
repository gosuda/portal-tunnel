package e2e_test

import "testing"

func TestCanonicalTunnel(t *testing.T) {
	h := newHarness(t)
	publicURL := h.waitForPublicURL()
	if got := h.get(publicURL); got != marker {
		t.Fatalf("tenant response = %q, want %q", got, marker)
	}
}
