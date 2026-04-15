package discovery

import (
	"strings"
	"sync"
	"time"
)

// Default per-source-IP rate-limit parameters for the announce endpoint.
// Honest relays announce roughly once per discovery TTL (every five minutes
// at most), so a sustained rate of one request per minute with a small
// burst is generous yet defends against memory-exhaustion injection spam.
const (
	DefaultAnnounceRatePerMinute = 5
	DefaultAnnounceBurst         = 10
	announceLimiterPruneInterval = 10 * time.Minute
	announceLimiterIdleTTL       = 30 * time.Minute
)

// AnnounceLimiter is a fixed-window-with-token-refill rate limiter keyed
// by source IP. Buckets that have not been touched for announceLimiterIdleTTL
// are garbage-collected on demand to keep memory bounded under a churning
// IP address space.
//
// AnnounceLimiter is safe for concurrent use. All state lives behind a
// single sync.Mutex; the limiter is on the announce hot path but each
// permit decision is O(1) (bucket lookup + arithmetic), and pruning is
// amortized over normal traffic so the worst-case latency is bounded.
type AnnounceLimiter struct {
	mu             sync.Mutex
	buckets        map[string]*announceBucket
	ratePerMinute  float64
	burst          float64
	lastPrune      time.Time
	pruneInterval  time.Duration
	bucketIdleTTL  time.Duration
	clock          func() time.Time // overridable for tests
	maxBucketCount int
}

type announceBucket struct {
	tokens     float64
	updatedAt  time.Time
	lastUsedAt time.Time
}

// NewAnnounceLimiter constructs a limiter with the supplied sustained rate
// (requests per minute) and burst capacity. Non-positive values fall back
// to the defaults so the zero-config path is safe.
func NewAnnounceLimiter(ratePerMinute, burst int) *AnnounceLimiter {
	if ratePerMinute <= 0 {
		ratePerMinute = DefaultAnnounceRatePerMinute
	}
	if burst <= 0 {
		burst = DefaultAnnounceBurst
	}
	return &AnnounceLimiter{
		buckets:        make(map[string]*announceBucket),
		ratePerMinute:  float64(ratePerMinute),
		burst:          float64(burst),
		pruneInterval:  announceLimiterPruneInterval,
		bucketIdleTTL:  announceLimiterIdleTTL,
		clock:          func() time.Time { return time.Now() },
		maxBucketCount: 65536,
	}
}

// Allow returns true if the supplied source IP has remaining capacity in
// its bucket and atomically deducts one token. Empty source IPs share a
// single anonymized bucket so a misconfigured proxy cannot bypass the
// limiter by suppressing client identification.
func (l *AnnounceLimiter) Allow(srcIP string) bool {
	if l == nil {
		return true
	}
	key := normalizeAnnounceLimiterKey(srcIP)

	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.clock()
	l.maybePruneLocked(now)

	bucket, ok := l.buckets[key]
	if !ok {
		// New buckets start full so a single legitimate announce isn't
		// gated by warm-up latency.
		bucket = &announceBucket{
			tokens:     l.burst,
			updatedAt:  now,
			lastUsedAt: now,
		}
		// Hard ceiling: if the table is saturated, refuse new IPs rather
		// than allow unbounded growth from random source addresses.
		if len(l.buckets) >= l.maxBucketCount {
			return false
		}
		l.buckets[key] = bucket
	} else {
		elapsed := now.Sub(bucket.updatedAt)
		if elapsed > 0 {
			bucket.tokens += (l.ratePerMinute * float64(elapsed)) / float64(time.Minute)
			if bucket.tokens > l.burst {
				bucket.tokens = l.burst
			}
			bucket.updatedAt = now
		}
	}

	bucket.lastUsedAt = now
	if bucket.tokens < 1 {
		return false
	}
	bucket.tokens--
	return true
}

// maybePruneLocked drops idle buckets so the limiter's memory footprint
// stays proportional to the number of recently-active source IPs. The
// caller MUST already hold l.mu.
func (l *AnnounceLimiter) maybePruneLocked(now time.Time) {
	if l.lastPrune.IsZero() {
		l.lastPrune = now
		return
	}
	if now.Sub(l.lastPrune) < l.pruneInterval {
		return
	}
	l.lastPrune = now
	threshold := now.Add(-l.bucketIdleTTL)
	for key, bucket := range l.buckets {
		if bucket.lastUsedAt.Before(threshold) {
			delete(l.buckets, key)
		}
	}
}

func normalizeAnnounceLimiterKey(raw string) string {
	key := strings.TrimSpace(raw)
	if key == "" {
		return "<unknown>"
	}
	return strings.ToLower(key)
}
