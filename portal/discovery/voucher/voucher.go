package voucher

import (
	"context"

	"github.com/gosuda/portal-tunnel/v2/portal/discovery"
)

// Voucher wraps an inner discovery.Selector and re-orders its output using a
// three-bucket partition based on each relay's SupportsReservation flag and
// whether the client holds a valid cached voucher for that relay.
//
// Bucket A — relay.SupportsReservation == false (legacy; bypasses voucher logic)
// Bucket B — SupportsReservation && cache.Has(url)  (cached; preferred)
// Bucket C — SupportsReservation && !cache.Has(url) (uncached; demoted to back)
//
// A and B preserve the inner selector's ordering relative to each other.
// C is appended after A+B in the order they appeared in the inner output.
//
// WARNING: EXPERIMENTAL — see package documentation.
type Voucher struct {
	inner discovery.Selector
	cache *Cache
}

// Compile-time assertion: *Voucher must satisfy discovery.Selector.
var _ discovery.Selector = (*Voucher)(nil)

// New returns a new Voucher selector wrapping inner and using cache to test
// for cached vouchers.
func New(inner discovery.Selector, cache *Cache) *Voucher {
	return &Voucher{inner: inner, cache: cache}
}

// Name returns the inner selector's name with "+voucher" appended.
func (v *Voucher) Name() string { return v.inner.Name() + "+voucher" }

// SelectPriority delegates to the inner selector and applies three-bucket
// partitioning to the returned URLs.
func (v *Voucher) SelectPriority(ctx context.Context, pool []discovery.RelayState, client discovery.ClientState) ([]string, discovery.SelectionTrace) {
	urls, trace := v.inner.SelectPriority(ctx, pool, client)
	out := v.partition(urls, pool)
	trace.OutputURLs = out
	return out, trace
}

// SelectMultiHop delegates to the inner selector and applies three-bucket
// partitioning to the returned URLs.
func (v *Voucher) SelectMultiHop(ctx context.Context, pool []discovery.RelayState, client discovery.ClientState) ([]string, discovery.SelectionTrace) {
	urls, trace := v.inner.SelectMultiHop(ctx, pool, client)
	out := v.partition(urls, pool)
	trace.OutputURLs = out
	return out, trace
}

// partition applies the three-bucket ordering to urls, using pool to look up
// each relay's SupportsReservation flag. Relays whose URL is not found in the
// pool are treated as legacy (bucket A) for safety.
func (v *Voucher) partition(urls []string, pool []discovery.RelayState) []string {
	if len(urls) == 0 {
		return urls
	}

	// Build URL → SupportsReservation lookup from pool.
	supportsRes := make(map[string]bool, len(pool))
	for _, rs := range pool {
		supportsRes[rs.Descriptor.APIHTTPSAddr] = rs.Descriptor.SupportsReservation
	}

	front := make([]string, 0, len(urls)) // A + B (in inner order)
	back := make([]string, 0, len(urls))  // C (in inner order)

	for _, url := range urls {
		if !supportsRes[url] {
			// Bucket A: legacy relay — keep at front.
			front = append(front, url)
		} else if v.cache.Has(url) {
			// Bucket B: voucher cached — keep at front.
			front = append(front, url)
		} else {
			// Bucket C: reservation required but no voucher — demote to back.
			back = append(back, url)
		}
	}

	return append(front, back...)
}
