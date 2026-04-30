package voucher_test

import (
	"context"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/discovery"
	"github.com/gosuda/portal-tunnel/v2/portal/discovery/selectors/mols"
	"github.com/gosuda/portal-tunnel/v2/portal/discovery/selectortest"
	"github.com/gosuda/portal-tunnel/v2/portal/discovery/voucher"
	"github.com/gosuda/portal-tunnel/v2/types"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// relayState returns a simple RelayState for priority-mode use (no overlay
// fields needed). SupportsReservation is configurable.
func relayState(url string, supportsRes bool) discovery.RelayState {
	now := time.Now().UTC()
	return discovery.RelayState{
		Descriptor: types.RelayDescriptor{
			APIHTTPSAddr:        url,
			IssuedAt:            now,
			ExpiresAt:           now.Add(time.Hour),
			SupportsReservation: supportsRes,
		},
		Bootstrap: true,
	}
}

// freshVoucherFor returns a non-expired voucher for the given relay URL.
func freshVoucherFor(relayURL string) types.ReservationVoucher {
	now := time.Now().UTC()
	return types.ReservationVoucher{
		ClientAddress: "test-client",
		RelayURL:      relayURL,
		IssuedAt:      now,
		ExpiresAt:     now.Add(time.Hour),
	}
}

// urlsOf extracts APIHTTPSAddr from a pool slice, in order.
func urlsOf(pool []discovery.RelayState) []string {
	out := make([]string, len(pool))
	for i, rs := range pool {
		out[i] = rs.Descriptor.APIHTTPSAddr
	}
	return out
}

// ---------------------------------------------------------------------------
// Contract harness
// ---------------------------------------------------------------------------

func TestVoucherContract(t *testing.T) {
	selectortest.Contract(t, "voucher_mols", func() discovery.Selector {
		return voucher.New(mols.New(), voucher.NewCache())
	})
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

// TestVoucherName returns "<inner>+voucher".
func TestVoucherName(t *testing.T) {
	sel := voucher.New(mols.New(), voucher.NewCache())
	if got, want := sel.Name(), "mols+voucher"; got != want {
		t.Fatalf("Name() = %q, want %q", got, want)
	}
}

// TestVoucherLegacyBypass — all relays have SupportsReservation=false.
// The selector must return exactly the same URL set as the inner selector
// (all land in bucket A).
func TestVoucherLegacyBypass(t *testing.T) {
	inner := mols.New()
	cache := voucher.NewCache()
	sel := voucher.New(inner, cache)
	ctx := context.Background()

	pool := []discovery.RelayState{
		relayState("https://legacy-1.example", false),
		relayState("https://legacy-2.example", false),
		relayState("https://legacy-3.example", false),
	}
	client := discovery.ClientState{
		LocalAddress:    "legacy-bypass-test",
		MaxActiveRelays: len(pool),
	}

	innerURLs, _ := inner.SelectPriority(ctx, pool, client)
	gotURLs, _ := sel.SelectPriority(ctx, pool, client)

	if len(innerURLs) != len(gotURLs) {
		t.Fatalf("legacy bypass: len mismatch inner=%d voucher=%d", len(innerURLs), len(gotURLs))
	}
	for i := range innerURLs {
		if innerURLs[i] != gotURLs[i] {
			t.Fatalf("legacy bypass: output[%d] inner=%q voucher=%q; want identical order", i, innerURLs[i], gotURLs[i])
		}
	}
}

// TestVoucherEmptyCacheDemotes — all relays SupportsReservation=true, empty
// cache. All candidates land in bucket C. The selector must still return all
// of them (none discarded), but they may all be in the demoted section.
// Because all are in the same bucket, inner's relative order is preserved.
func TestVoucherEmptyCacheDemotes(t *testing.T) {
	cache := voucher.NewCache()
	sel := voucher.New(mols.New(), cache)
	ctx := context.Background()

	pool := []discovery.RelayState{
		relayState("https://res-1.example", true),
		relayState("https://res-2.example", true),
		relayState("https://res-3.example", true),
	}
	client := discovery.ClientState{
		LocalAddress:    "empty-cache-demotes-test",
		MaxActiveRelays: len(pool),
	}

	gotURLs, _ := sel.SelectPriority(ctx, pool, client)

	// All three pool URLs must be present in the output (none dropped, none duplicated).
	if len(gotURLs) != len(pool) {
		t.Fatalf("empty-cache demote: want %d URLs, got %d: %v", len(pool), len(gotURLs), gotURLs)
	}
	got := make(map[string]struct{}, len(gotURLs))
	for _, u := range gotURLs {
		if _, dup := got[u]; dup {
			t.Fatalf("empty-cache demote: duplicate URL %q in output %v", u, gotURLs)
		}
		got[u] = struct{}{}
	}
	for _, u := range urlsOf(pool) {
		if _, ok := got[u]; !ok {
			t.Fatalf("empty-cache demote: URL %q missing from output %v; all candidates must still be returned", u, gotURLs)
		}
	}
}

// TestVoucherCachedPreferred — mixed pool: some relays support reservation,
// some don't. The cached voucher holders must appear before uncached
// reservation-supporting relays.
//
// Pool (in fixed URL alphabetical order for determinism in a bootstrap pool):
//
//	r1: SupportsReservation=true,  no voucher in cache  → bucket C
//	r2: SupportsReservation=false,                      → bucket A
//	r3: SupportsReservation=true,  cached voucher       → bucket B
//
// Expected output order: r2 (A), r3 (B), then r1 (C).
func TestVoucherCachedPreferred(t *testing.T) {
	cache := voucher.NewCache()

	const urlR1 = "https://r1-uncached.example"
	const urlR2 = "https://r2-legacy.example"
	const urlR3 = "https://r3-cached.example"

	// Pre-seed cache only for r3.
	cache.Put(freshVoucherFor(urlR3))

	pool := []discovery.RelayState{
		relayState(urlR1, true),
		relayState(urlR2, false),
		relayState(urlR3, true),
	}

	sel := voucher.New(mols.New(), cache)
	ctx := context.Background()

	client := discovery.ClientState{
		LocalAddress:    "cached-preferred-test",
		MaxActiveRelays: len(pool),
	}

	gotURLs, _ := sel.SelectPriority(ctx, pool, client)

	// All three must appear.
	if len(gotURLs) != 3 {
		t.Fatalf("cached-preferred: want 3 URLs, got %d: %v", len(gotURLs), gotURLs)
	}

	// Find positions of each URL in the output.
	posOf := func(url string) int {
		for i, u := range gotURLs {
			if u == url {
				return i
			}
		}
		return -1
	}

	posR1 := posOf(urlR1)
	posR2 := posOf(urlR2)
	posR3 := posOf(urlR3)

	if posR1 < 0 || posR2 < 0 || posR3 < 0 {
		t.Fatalf("cached-preferred: one or more URLs missing from output %v", gotURLs)
	}

	// r2 (bucket A) and r3 (bucket B) must both appear before r1 (bucket C).
	if posR1 <= posR2 {
		t.Errorf("cached-preferred: r1(C) pos=%d should be > r2(A) pos=%d", posR1, posR2)
	}
	if posR1 <= posR3 {
		t.Errorf("cached-preferred: r1(C) pos=%d should be > r3(B) pos=%d", posR1, posR3)
	}
}
