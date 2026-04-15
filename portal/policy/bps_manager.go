package policy

import (
	"maps"
	"sync"
	"time"
)

type BPSManager struct {
	identityBPS      map[string]int64
	identityLimiters map[string]*bpsLimiter
	mu               sync.RWMutex
}

func NewBPSManager() *BPSManager {
	return &BPSManager{
		identityBPS:      make(map[string]int64),
		identityLimiters: make(map[string]*bpsLimiter),
	}
}

func (m *BPSManager) IdentityBPS(key string) int64 {
	if m == nil || key == "" {
		return 0
	}

	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.identityBPS[key]
}

func (m *BPSManager) SetIdentityBPS(key string, bps int64) {
	if m == nil || key == "" {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if bps <= 0 {
		delete(m.identityBPS, key)
		delete(m.identityLimiters, key)
		return
	}
	m.identityBPS[key] = bps
}

func (m *BPSManager) DeleteIdentityBPS(key string) {
	if m == nil || key == "" {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.identityBPS, key)
	delete(m.identityLimiters, key)
}

func (m *BPSManager) IdentityBPSLimits() map[string]int64 {
	if m == nil {
		return nil
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	out := make(map[string]int64, len(m.identityBPS))
	maps.Copy(out, m.identityBPS)
	return out
}

func (m *BPSManager) SetIdentityBPSLimits(limits map[string]int64) {
	if m == nil {
		return
	}

	next := make(map[string]int64, len(limits))
	for key, bps := range limits {
		if key == "" || bps <= 0 {
			continue
		}
		next[key] = bps
	}

	m.mu.Lock()
	m.identityBPS = next
	m.identityLimiters = make(map[string]*bpsLimiter)
	m.mu.Unlock()
}

func (m *BPSManager) ThrottleIdentityBPS(key string, maxBytes int) int {
	if m == nil || key == "" || maxBytes <= 0 {
		return maxBytes
	}

	for {
		bps, limiter := m.identityLimiter(key)
		if bps <= 0 || limiter == nil {
			return maxBytes
		}
		chunkSize := bpsChunkSize(maxBytes, bps)
		if wait := limiter.reserve(float64(chunkSize), float64(bps)); wait > 0 {
			time.Sleep(wait)
			continue
		}
		return chunkSize
	}
}

func (m *BPSManager) identityLimiter(key string) (int64, *bpsLimiter) {
	m.mu.RLock()
	bps := m.identityBPS[key]
	limiter := m.identityLimiters[key]
	m.mu.RUnlock()
	if bps <= 0 || limiter != nil {
		return bps, limiter
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	bps = m.identityBPS[key]
	if bps <= 0 {
		return 0, nil
	}
	if m.identityLimiters == nil {
		m.identityLimiters = make(map[string]*bpsLimiter)
	}
	limiter = m.identityLimiters[key]
	if limiter == nil {
		limiter = &bpsLimiter{}
		m.identityLimiters[key] = limiter
	}
	return bps, limiter
}

func bpsChunkSize(length int, bps int64) int {
	if bps <= 0 {
		return length
	}
	chunk := bps / 10
	if chunk < 1 {
		chunk = 1
	}
	if chunk > int64(length) {
		chunk = int64(length)
	}
	return int(chunk)
}

type bpsLimiter struct {
	mu        sync.Mutex
	tokens    float64
	updatedAt time.Time
}

func (l *bpsLimiter) reserve(bytes, bps float64) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	if l.updatedAt.IsZero() {
		l.updatedAt = now
	} else if elapsed := now.Sub(l.updatedAt).Seconds(); elapsed > 0 {
		l.tokens += elapsed * bps
		l.updatedAt = now
	}
	if l.tokens > bps {
		l.tokens = bps
	}

	if l.tokens >= bytes {
		l.tokens -= bytes
		return 0
	}

	missing := bytes - l.tokens
	l.tokens = 0
	l.updatedAt = now
	return time.Duration(missing / bps * float64(time.Second))
}
