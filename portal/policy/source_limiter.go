package policy

import (
	"cmp"
	"math"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	sourceLimiterPruneInterval = time.Minute
	sourceLimiterIdleTTL       = 30 * time.Minute
)

// SourceLimiter owns weighted source and global admission budgets. State is
// bounded, expires on demand, and never becomes durable authorization policy.
type SourceLimiter struct {
	mu                      sync.Mutex
	buckets                 map[string]*sourceBucket
	ratePerMinute, burst    float64
	globalRate, globalBurst float64
	global                  sourceBucket
	lastPrune               time.Time
	clock                   func() time.Time
	maxBucketCount          int
}

type sourceBucket struct {
	tokens     float64
	updatedAt  time.Time
	lastUsedAt time.Time
}

// NewSourceLimiter requires positive source limits. A zero global rate disables
// the global bucket for callers that already have a separate capacity boundary.
func NewSourceLimiter(ratePerMinute, burst, globalRate, globalBurst int) *SourceLimiter {
	return &SourceLimiter{
		buckets: make(map[string]*sourceBucket), ratePerMinute: float64(ratePerMinute), burst: float64(burst),
		globalRate: float64(globalRate), globalBurst: float64(globalBurst),
		global: sourceBucket{tokens: float64(globalBurst)}, clock: time.Now, maxBucketCount: 65536,
	}
}

// Allow deducts cost only if both budgets admit the request. Rejections return
// retry guidance and a bounded layer label; no IP history is persisted.
func (l *SourceLimiter) Allow(srcIP string, cost int) (time.Duration, string) {
	key := strings.TrimSpace(srcIP)
	if ip := net.ParseIP(key); ip != nil {
		key = ip.String()
	}
	key = cmp.Or(key, "<unknown>")
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clock()
	if l.lastPrune.IsZero() || now.Sub(l.lastPrune) >= sourceLimiterPruneInterval {
		l.lastPrune = now
		for key, bucket := range l.buckets {
			if now.Sub(bucket.lastUsedAt) >= sourceLimiterIdleTTL {
				delete(l.buckets, key)
			}
		}
	}
	// Check global capacity before allocating memory for a new source.
	if l.globalRate > 0 {
		if retry := l.global.retry(now, l.globalRate, l.globalBurst, cost); retry > 0 {
			return retry, "global"
		}
	}
	bucket := l.buckets[key]
	if bucket == nil {
		if len(l.buckets) >= l.maxBucketCount {
			return sourceLimiterPruneInterval, "source"
		}
		bucket = &sourceBucket{tokens: l.burst, updatedAt: now}
		l.buckets[key] = bucket
	}
	bucket.lastUsedAt = now
	if retry := bucket.retry(now, l.ratePerMinute, l.burst, cost); retry > 0 {
		return retry, "source"
	}
	bucket.tokens -= float64(cost)
	if l.globalRate > 0 {
		l.global.tokens -= float64(cost)
	}
	return 0, ""
}

func (b *sourceBucket) retry(now time.Time, rate, burst float64, cost int) time.Duration {
	if !b.updatedAt.IsZero() && now.After(b.updatedAt) {
		b.tokens = math.Min(burst, b.tokens+rate*now.Sub(b.updatedAt).Minutes())
	}
	b.updatedAt = now
	if b.tokens >= float64(cost) {
		return 0
	}
	return time.Duration(math.Ceil((float64(cost) - b.tokens) / rate * float64(time.Minute)))
}
