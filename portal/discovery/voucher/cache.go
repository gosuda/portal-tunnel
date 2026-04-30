// Package voucher provides an in-memory cache for ReservationVoucher values
// and a discovery.Selector wrapper that uses the cache to partition relay
// candidates into three priority buckets.
//
// WARNING: EXPERIMENTAL — the voucher mechanism ships ahead of production
// telemetry. Do not enable in production until oversubscription data justifies
// it. Phase 4 delivers the negotiation surface only; dataplane enforcement is
// NOT wired and is deferred to a future phase.
package voucher

import (
	"sync"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
)

// Cache is a thread-safe in-memory store of ReservationVoucher values keyed
// by relay URL. Get and Has automatically evict any entry whose ExpiresAt is
// in the past at the time of the read.
//
// WARNING: EXPERIMENTAL — see package documentation.
type Cache struct {
	mu    sync.RWMutex
	store map[string]types.ReservationVoucher
}

// NewCache returns an initialised, empty Cache.
func NewCache() *Cache {
	return &Cache{
		store: make(map[string]types.ReservationVoucher),
	}
}

// Put stores v under the key v.RelayURL, replacing any prior entry.
func (c *Cache) Put(v types.ReservationVoucher) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.store[v.RelayURL] = v
}

// Get returns the cached voucher for relayURL and true when a non-expired entry
// exists. If the stored entry has expired it is deleted and (zero, false) is
// returned. A write lock is taken whenever an eviction is needed.
func (c *Cache) Get(relayURL string) (types.ReservationVoucher, bool) {
	// Fast path: read lock, check existence and freshness.
	c.mu.RLock()
	v, ok := c.store[relayURL]
	c.mu.RUnlock()

	if !ok {
		return types.ReservationVoucher{}, false
	}
	if time.Now().After(v.ExpiresAt) {
		// Entry has expired — evict under write lock, then re-verify (another
		// goroutine may have replaced it with a fresh voucher since we dropped
		// the read lock).
		c.mu.Lock()
		if stored, still := c.store[relayURL]; still && time.Now().After(stored.ExpiresAt) {
			delete(c.store, relayURL)
		}
		c.mu.Unlock()
		return types.ReservationVoucher{}, false
	}
	return v, true
}

// Has returns true when a non-expired voucher exists for relayURL. Expired
// entries are evicted on read (same policy as Get).
func (c *Cache) Has(relayURL string) bool {
	_, ok := c.Get(relayURL)
	return ok
}

// Evict unconditionally removes the entry for relayURL, if any.
func (c *Cache) Evict(relayURL string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.store, relayURL)
}
