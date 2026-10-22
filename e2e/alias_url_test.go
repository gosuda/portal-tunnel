package e2e_test

import (
	"context"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/sdk"
)

// A second identity registering a taken name falls back to its canonical
// hostname and must not report the other identity's friendly alias.
func TestAliasURLOnlyForAliasOwner(t *testing.T) {
	h := newHarnessWithName(t, "e2e", "127.0.0.1", "")
	h.waitForPublicURL()
	owner := h.exposure.Relays()
	if len(owner) != 1 || owner[0].AliasURL == "" {
		t.Fatalf("alias owner status = %+v, want AliasURL", owner)
	}

	other, err := identity.Generate("e2e")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	exposure, err := sdk.Expose(ctx, other, []string{"https://" + h.sniAddr})
	if err != nil {
		t.Fatalf("expose second identity: %v", err)
	}
	defer exposure.Close()
	ready, err := exposure.WaitReady(ctx)
	if err != nil {
		t.Fatalf("second identity did not become ready: %v", err)
	}
	if len(ready) != 1 || ready[0].PublicURL == "" || ready[0].PublicURL == owner[0].PublicURL {
		t.Fatalf("second identity status = %+v, want its own canonical PublicURL", ready)
	}
	if ready[0].AliasURL != "" {
		t.Fatalf("second identity AliasURL = %q, want empty after canonical fallback", ready[0].AliasURL)
	}
	if got := h.exposure.Relays(); len(got) != 1 || got[0].AliasURL != owner[0].AliasURL {
		t.Fatalf("alias owner status after fallback = %+v, want AliasURL %q", got, owner[0].AliasURL)
	}
}
