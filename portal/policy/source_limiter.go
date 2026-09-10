package policy

import (
	"cmp"
	"strings"
	"sync"
	"time"
)

const (
	sourceLimiterPruneInterval = 10 * time.Minute
	sourceLimiterIdleTTL       = 30 * time.Minute
)

// SourceLimiter bounds requests per source IP with a token bucket. Each endpoint
// owns its budget; bucket storage is bounded and idle entries expire on demand.
// It is safe for concurrent use.
type SourceLimiter struct {
	mu             sync.Mutex
	buckets        map[string]*sourceBucket
	ratePerMinute  float64
	burst          float64
	lastPrune      time.Time
	pruneInterval  time.Duration
	bucketIdleTTL  time.Duration
	clock          func() time.Time // overridable for tests
	maxBucketCount int
}

type sourceBucket struct {
	tokens     float64
	updatedAt  time.Time
	lastUsedAt time.Time
}

// NewSourceLimiter constructs an endpoint's budget. Both limits must be positive.
func NewSourceLimiter(ratePerMinute, burst int) *SourceLimiter {
	return &SourceLimiter{
		buckets:        make(map[string]*sourceBucket),
		ratePerMinute:  float64(ratePerMinute),
		burst:          float64(burst),
		pruneInterval:  sourceLimiterPruneInterval,
		bucketIdleTTL:  sourceLimiterIdleTTL,
		clock:          func() time.Time { return time.Now() },
		maxBucketCount: 65536,
	}
}

// Allow returns true if the supplied source IP has remaining capacity in
// its bucket and atomically deducts one token. Empty source IPs share a
// single anonymized bucket so a misconfigured proxy cannot bypass the
// limiter by suppressing client identification.
func (l *SourceLimiter) Allow(srcIP string) bool {
	if l == nil {
		return true
	}
	key := strings.ToLower(strings.TrimSpace(srcIP))
	key = cmp.Or(key, "<unknown>")

	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.clock()
	l.maybePruneLocked(now)

	bucket, ok := l.buckets[key]
	if !ok {
		// New buckets start full so a single legitimate request isn't
		// gated by warm-up latency.
		bucket = &sourceBucket{
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
func (l *SourceLimiter) maybePruneLocked(now time.Time) {
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
