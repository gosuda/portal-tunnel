// Package selectortest provides a parameterized contract test harness for
// implementations of discovery.Selector. Import this package only from
// _test.go files — it is a test-helper package and is not intended to be
// compiled into production binaries.
//
// Usage:
//
//	selectortest.Contract(t, "mols", func() discovery.Selector { return mols.New() })
//	selectortest.Contract(t, "weighted", func() discovery.Selector {
//	    return weighted.New(mols.New())
//	})
package selectortest

import (
	"context"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/auth"
	"github.com/gosuda/portal-tunnel/v2/portal/discovery"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

// Contract runs the parameterized invariant suite against the Selector returned
// by factory. Each sub-test calls factory() to obtain a fresh Selector instance,
// so stateful selectors do not leak state across cases.
func Contract(t *testing.T, name string, factory func() discovery.Selector) {
	t.Helper()

	t.Run(name+"/explicit_relay_precedence", func(t *testing.T) {
		sel := factory()
		explicitURL := "https://contract-explicit.example"
		autoURL1 := "https://contract-auto-1.example"
		autoURL2 := "https://contract-auto-2.example"

		pool := []discovery.RelayState{
			mustConfirmedRelayState(t, explicitURL),
			mustConfirmedRelayState(t, autoURL1),
			mustConfirmedRelayState(t, autoURL2),
		}
		client := discovery.ClientState{
			ExplicitRelayURLs: []string{explicitURL},
			MaxActiveRelays:   1, // cap at 1 auto relay, explicit must still appear
		}
		urls, _ := sel.SelectPriority(context.Background(), pool, client)
		if !slices.Contains(urls, explicitURL) {
			t.Fatalf("explicit relay %q missing from SelectPriority output %v; explicit relays must bypass MaxActiveRelays cap", explicitURL, urls)
		}
	})

	t.Run(name+"/max_active_relays_cap", func(t *testing.T) {
		sel := factory()
		const cap = 3
		const poolSize = 7
		pool := make([]discovery.RelayState, poolSize)
		for i := range pool {
			pool[i] = mustConfirmedRelayState(t, relayURL(i))
		}
		client := discovery.ClientState{MaxActiveRelays: cap}
		urls, _ := sel.SelectPriority(context.Background(), pool, client)
		// Only non-explicit (auto) relays count against the cap; client has no explicit relays.
		if len(urls) > cap {
			t.Fatalf("SelectPriority returned %d URLs with MaxActiveRelays=%d pool=%d; want <= %d", len(urls), cap, poolSize, cap)
		}
	})

	t.Run(name+"/banned_excluded", func(t *testing.T) {
		sel := factory()
		bannedURL := "https://contract-banned.example"
		okURL := "https://contract-ok.example"

		banned := mustConfirmedRelayState(t, bannedURL)
		banned.Banned = true

		pool := []discovery.RelayState{
			banned,
			mustConfirmedRelayState(t, okURL),
		}
		urls, _ := sel.SelectPriority(context.Background(), pool, discovery.ClientState{})
		if slices.Contains(urls, bannedURL) {
			t.Fatalf("banned relay %q appeared in SelectPriority output %v; banned relays must be excluded", bannedURL, urls)
		}
	})

	t.Run(name+"/suppression_respected", func(t *testing.T) {
		sel := factory()
		suppressedURL := "https://contract-suppressed.example"
		okURL := "https://contract-ok-supp.example"

		// Drive relay into active suppression via Lifecycle.OnActiveFailure.
		lc := discovery.NewLifecycle()
		base := mustConfirmedRelayState(t, suppressedURL)
		const budget = 3
		for i := 0; i <= budget; i++ {
			base, _, _ = lc.OnActiveFailure(base, nil, budget)
		}
		if !base.IsSuppressedActive(time.Now()) {
			t.Fatalf("test setup: relay is not suppressed after driving through Lifecycle.OnActiveFailure; cannot run invariant")
		}

		pool := []discovery.RelayState{
			base,
			mustConfirmedRelayState(t, okURL),
		}
		urls, _ := sel.SelectPriority(context.Background(), pool, discovery.ClientState{})
		if slices.Contains(urls, suppressedURL) {
			t.Fatalf("suppressed relay %q appeared in SelectPriority output %v; suppressed relays must be excluded", suppressedURL, urls)
		}
	})

	t.Run(name+"/bootstrap_pin_survives_aggregate", func(t *testing.T) {
		sel := factory()
		// An unobserved bootstrap relay (LastSeenAt zero, no ExpiresAt) must
		// appear in SelectPriority output when pool is small enough that the
		// cap does not truncate it. This tests the bootstrap-pin invariant:
		// bootstrap stays in pool regardless of lack of confirmation.
		bootstrapURL := "https://contract-bootstrap.example"
		pool := []discovery.RelayState{
			mustBootstrapRelayState(bootstrapURL),
		}
		urls, _ := sel.SelectPriority(context.Background(), pool, discovery.ClientState{})
		if !slices.Contains(urls, bootstrapURL) {
			t.Fatalf("bootstrap relay %q missing from SelectPriority output %v; unobserved bootstrap must survive in output for small pool", bootstrapURL, urls)
		}
	})

	t.Run(name+"/freshness_gate_skips_expired", func(t *testing.T) {
		sel := factory()
		expiredURL := "https://contract-expired.example"
		freshURL := "https://contract-fresh.example"

		// expired: HasObservedDescriptor()==true (LastSeenAt set), ExpiresAt in past.
		expired := mustConfirmedRelayState(t, expiredURL)
		expired.Descriptor.ExpiresAt = time.Now().UTC().Add(-time.Minute)

		pool := []discovery.RelayState{
			expired,
			mustConfirmedRelayState(t, freshURL),
		}
		urls, _ := sel.SelectPriority(context.Background(), pool, discovery.ClientState{})
		if slices.Contains(urls, expiredURL) {
			t.Fatalf("expired relay %q appeared in SelectPriority output %v; expired auto relays must be excluded", expiredURL, urls)
		}
	})

	t.Run(name+"/determinism_fixed_input", func(t *testing.T) {
		sel := factory()
		// All load fields are zero so no external state can vary between calls.
		pool := []discovery.RelayState{
			mustConfirmedRelayState(t, "https://contract-det-a.example"),
			mustConfirmedRelayState(t, "https://contract-det-b.example"),
			mustConfirmedRelayState(t, "https://contract-det-c.example"),
		}
		client := discovery.ClientState{LocalAddress: "determinism-test-addr"}

		first, _ := sel.SelectPriority(context.Background(), pool, client)
		for range 5 {
			got, _ := sel.SelectPriority(context.Background(), pool, client)
			if len(got) != len(first) {
				t.Fatalf("non-deterministic length: first=%d subsequent=%d", len(first), len(got))
			}
			for i := range got {
				if got[i] != first[i] {
					t.Fatalf("non-deterministic result at index %d: first=%q subsequent=%q", i, first[i], got[i])
				}
			}
		}
	})

	t.Run(name+"/empty_pool_returns_nil", func(t *testing.T) {
		sel := factory()
		client := discovery.ClientState{}

		urls, _ := sel.SelectPriority(context.Background(), nil, client)
		if len(urls) != 0 {
			t.Fatalf("SelectPriority(ctx, nil, client) = %v, want nil/empty", urls)
		}

		urls, _ = sel.SelectPriority(context.Background(), []discovery.RelayState{}, client)
		if len(urls) != 0 {
			t.Fatalf("SelectPriority(ctx, []RelayState{}, client) = %v, want nil/empty", urls)
		}
	})

	t.Run(name+"/multihop_depth_zero_returns_nil", func(t *testing.T) {
		sel := factory()
		pool := []discovery.RelayState{
			mustOverlayRelayState(t, "https://contract-mh-a.example"),
			mustOverlayRelayState(t, "https://contract-mh-b.example"),
		}
		urls, _ := sel.SelectMultiHop(context.Background(), pool, discovery.ClientState{MultiHopDepth: 0})
		if len(urls) != 0 {
			t.Fatalf("SelectMultiHop(depth=0) = %v, want nil/empty", urls)
		}
	})

	t.Run(name+"/multihop_depth_one_returns_nil", func(t *testing.T) {
		sel := factory()
		pool := []discovery.RelayState{
			mustOverlayRelayState(t, "https://contract-mh-a.example"),
			mustOverlayRelayState(t, "https://contract-mh-b.example"),
		}
		urls, _ := sel.SelectMultiHop(context.Background(), pool, discovery.ClientState{MultiHopDepth: 1})
		if len(urls) != 0 {
			t.Fatalf("SelectMultiHop(depth=1) = %v, want nil/empty", urls)
		}
	})

	t.Run(name+"/trace_pool_total_matches_input", func(t *testing.T) {
		sel := factory()
		pool := []discovery.RelayState{
			mustConfirmedRelayState(t, "https://contract-trace-a.example"),
			mustConfirmedRelayState(t, "https://contract-trace-b.example"),
			mustConfirmedRelayState(t, "https://contract-trace-c.example"),
		}
		_, trace := sel.SelectPriority(context.Background(), pool, discovery.ClientState{})
		if trace.PoolTotal != len(pool) {
			t.Fatalf("SelectionTrace.PoolTotal = %d, want %d (== len(pool))", trace.PoolTotal, len(pool))
		}
	})

	t.Run(name+"/every_excluded_has_reason", func(t *testing.T) {
		sel := factory()
		bannedURL := "https://contract-excl-banned.example"
		expiredURL := "https://contract-excl-expired.example"
		freshURL := "https://contract-excl-fresh.example"

		banned := mustConfirmedRelayState(t, bannedURL)
		banned.Banned = true

		expired := mustConfirmedRelayState(t, expiredURL)
		expired.Descriptor.ExpiresAt = time.Now().UTC().Add(-time.Minute)

		pool := []discovery.RelayState{
			banned,
			expired,
			mustConfirmedRelayState(t, freshURL),
		}
		_, trace := sel.SelectPriority(context.Background(), pool, discovery.ClientState{})
		for _, url := range trace.Suppressed {
			if _, ok := trace.Reasons[url]; !ok {
				t.Errorf("suppressed relay %q has no corresponding entry in trace.Reasons; every Suppressed URL must have a Reason", url)
			}
		}
	})
}

// ---------------------------------------------------------------------------
// internal helpers — not exported; used only by Contract above.
// ---------------------------------------------------------------------------

// mustRelayDescriptor builds and signs a RelayDescriptor valid for one hour.
func mustRelayDescriptor(t *testing.T, relayURL string) types.RelayDescriptor {
	t.Helper()
	signing, err := utils.ResolveSecp256k1Identity("")
	if err != nil {
		t.Fatalf("ResolveSecp256k1Identity() error = %v", err)
	}
	now := time.Now().UTC()
	signed, err := auth.SignRelayDescriptor(types.RelayDescriptor{
		Address:      signing.Address,
		Version:      types.DiscoveryVersion,
		IssuedAt:     now,
		ExpiresAt:    now.Add(time.Hour),
		APIHTTPSAddr: relayURL,
	}, signing.PrivateKey)
	if err != nil {
		t.Fatalf("SignRelayDescriptor() error = %v", err)
	}
	return signed
}

// mustConfirmedRelayState returns a confirmed, observed RelayState with a
// freshly signed descriptor. It mirrors confirmedPolicyRelayState from mols_test.go.
func mustConfirmedRelayState(t *testing.T, relayURL string) discovery.RelayState {
	t.Helper()
	return discovery.RelayState{
		Descriptor: mustRelayDescriptor(t, relayURL),
		Confirmed:  true,
		LastSeenAt: time.Now().UTC(),
	}
}

// mustBootstrapRelayState returns an unobserved bootstrap relay (no descriptor
// freshness, LastSeenAt zero). This matches the "seed" pattern: Bootstrap=true,
// no signed descriptor, no ExpiresAt — MOLS keeps it in the pool unconditionally.
func mustBootstrapRelayState(relayURL string) discovery.RelayState {
	return discovery.RelayState{
		Descriptor: types.RelayDescriptor{
			APIHTTPSAddr: relayURL,
		},
		Bootstrap: true,
	}
}

// mustOverlayRelayState returns a confirmed RelayState with overlay support
// enabled, suitable for SelectMultiHop eligibility.
func mustOverlayRelayState(t *testing.T, relayURL string) discovery.RelayState {
	t.Helper()
	state := mustConfirmedRelayState(t, relayURL)
	state.Descriptor.SupportsOverlay = true
	state.Descriptor.WireGuardPublicKey = "dGVzdGtleXRlc3RrZXl0ZXN0a2V5dGVzdGtleTA=" // non-empty placeholder
	state.Descriptor.WireGuardPort = 51820
	return state
}

// relayURL generates a URL for relay index i (helper for table-driven pool construction).
func relayURL(i int) string {
	return "https://contract-relay-" + strconv.Itoa(i) + ".example"
}
