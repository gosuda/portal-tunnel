package overlay

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
	maxSourceBuckets           = 65536
)

// sourceLimiter owns the overlay-local per-source request budget. It protects
// overlay resources only: the resolved source value is supplied by the relay
// ingress, and no IP history is persisted or promoted to authorization policy.
type sourceLimiter struct {
	mu                   sync.Mutex
	buckets              map[string]*sourceBucket
	ratePerMinute, burst float64
	lastPrune            time.Time
}

type sourceBucket struct {
	tokens     float64
	updatedAt  time.Time
	lastUsedAt time.Time
}

func newSourceLimiter(ratePerMinute, burst int) *sourceLimiter {
	return &sourceLimiter{
		buckets:       make(map[string]*sourceBucket),
		ratePerMinute: float64(ratePerMinute),
		burst:         float64(burst),
	}
}

// Allow deducts cost only when the source budget admits the request and
// returns the retry guidance otherwise.
func (l *sourceLimiter) Allow(srcIP string, cost int) time.Duration {
	key := strings.TrimSpace(srcIP)
	if ip := net.ParseIP(key); ip != nil {
		key = ip.String()
	}
	key = cmp.Or(key, "<unknown>")
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if l.lastPrune.IsZero() || now.Sub(l.lastPrune) >= sourceLimiterPruneInterval {
		l.lastPrune = now
		for key, bucket := range l.buckets {
			if now.Sub(bucket.lastUsedAt) >= sourceLimiterIdleTTL {
				delete(l.buckets, key)
			}
		}
	}
	bucket := l.buckets[key]
	if bucket == nil {
		if len(l.buckets) >= maxSourceBuckets {
			return sourceLimiterPruneInterval
		}
		bucket = &sourceBucket{tokens: l.burst, updatedAt: now}
		l.buckets[key] = bucket
	}
	bucket.lastUsedAt = now
	if retry := bucket.retry(now, l.ratePerMinute, l.burst, cost); retry > 0 {
		return retry
	}
	bucket.tokens -= float64(cost)
	return 0
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
