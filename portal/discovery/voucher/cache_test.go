package voucher_test

import (
	"sync"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/discovery/voucher"
	"github.com/gosuda/portal-tunnel/v2/types"
)

func makeVoucher(relayURL string, expiresIn time.Duration) types.ReservationVoucher {
	now := time.Now().UTC()
	return types.ReservationVoucher{
		ClientAddress: "test-client",
		RelayURL:      relayURL,
		IssuedAt:      now,
		ExpiresAt:     now.Add(expiresIn),
	}
}

// TestCachePutGet stores a fresh voucher and retrieves it.
func TestCachePutGet(t *testing.T) {
	c := voucher.NewCache()
	url := "https://relay-a.example"
	v := makeVoucher(url, time.Hour)
	c.Put(v)

	got, ok := c.Get(url)
	if !ok {
		t.Fatal("Get() returned false; want true for recently Put voucher")
	}
	if got.RelayURL != url {
		t.Fatalf("Get() RelayURL = %q, want %q", got.RelayURL, url)
	}
}

// TestCacheGetEvictsExpired verifies that an already-expired voucher is evicted
// on read: Get returns false and Has returns false.
func TestCacheGetEvictsExpired(t *testing.T) {
	c := voucher.NewCache()
	url := "https://relay-expired.example"

	// Put a voucher whose ExpiresAt is already in the past.
	v := makeVoucher(url, -time.Second)
	c.Put(v)

	if _, ok := c.Get(url); ok {
		t.Fatal("Get() returned true for expired voucher; want false")
	}
	if c.Has(url) {
		t.Fatal("Has() returned true for expired voucher; want false")
	}

	// A second Get after eviction must also return false (no panic, no stale entry).
	if _, ok := c.Get(url); ok {
		t.Fatal("Get() returned true on second call after eviction; want false")
	}
}

// TestCacheEvict unconditionally removes a live entry.
func TestCacheEvict(t *testing.T) {
	c := voucher.NewCache()
	url := "https://relay-evict.example"
	c.Put(makeVoucher(url, time.Hour))

	c.Evict(url)

	if _, ok := c.Get(url); ok {
		t.Fatal("Get() returned true after explicit Evict; want false")
	}
	if c.Has(url) {
		t.Fatal("Has() returned true after explicit Evict; want false")
	}
}

// TestCacheConcurrent runs N goroutines doing Put/Get on the same key to
// exercise the RWMutex paths. Run with -race to catch data races.
func TestCacheConcurrent(t *testing.T) {
	const goroutines = 50
	c := voucher.NewCache()
	url := "https://relay-concurrent.example"

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := range goroutines {
		go func(i int) {
			defer wg.Done()
			// Alternate between Put (fresh) and Get.
			if i%2 == 0 {
				c.Put(makeVoucher(url, time.Hour))
			} else {
				_, _ = c.Get(url) // return values intentionally discarded
			}
		}(i)
	}
	wg.Wait()

	// Cache must be in a consistent state: entry is either present or absent,
	// but no panic or data race.
}
