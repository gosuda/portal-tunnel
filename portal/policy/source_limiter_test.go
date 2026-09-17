package policy

import (
	"testing"
	"time"
)

// TestSourceLimiterIsolatesSourcesAndRefills protects the per-source token-bucket
// rate-limiting invariant: each source IP has its own bucket, the burst budget
// is shared across requests from the same source, and tokens refill at a fixed rate.
func TestSourceLimiterIsolatesSourcesAndRefills(t *testing.T) {
	limiter := NewSourceLimiter(60, 5)
	now := time.Now()
	limiter.clock = func() time.Time { return now }
	for i := range 5 {
		if !limiter.Allow("10.0.0.1") {
			t.Fatalf("burst[%d] should be allowed", i)
		}
	}
	if limiter.Allow("10.0.0.1") {
		t.Fatal("burst budget should be exhausted")
	}
	if !limiter.Allow("10.0.0.2") {
		t.Fatal("different IP should have its own bucket")
	}
	now = now.Add(time.Second)
	if !limiter.Allow("10.0.0.1") || limiter.Allow("10.0.0.1") {
		t.Fatal("one second should refill exactly one token")
	}
}

// TestSourceLimiterBoundsStorageAndExpiresIdleSources protects the memory-bounds
// invariant that the limiter caps the number of tracked sources and evicts sources
// that have been idle beyond the TTL to release that storage.
func TestSourceLimiterBoundsStorageAndExpiresIdleSources(t *testing.T) {
	limiter := NewSourceLimiter(60, 1)
	limiter.maxBucketCount = 1
	now := time.Now()
	limiter.clock = func() time.Time { return now }
	if !limiter.Allow("10.0.0.1") || limiter.Allow("10.0.0.2") {
		t.Fatal("new sources must be rejected when bucket storage is full")
	}
	now = now.Add(sourceLimiterIdleTTL + time.Second)
	if !limiter.Allow("10.0.0.2") {
		t.Fatal("idle source should expire and release bucket storage")
	}
}
