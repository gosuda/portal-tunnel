package pepper

import (
	"errors"
	"sync"
	"time"
)

type ReplayCache struct {
	window        time.Duration
	epochDuration time.Duration
	maxItems      int

	mu      sync.Mutex
	entries map[string]int64
	buckets map[int64]map[string]struct{}
}

func NewReplayCache(window, epochDuration time.Duration, maxItems int) (*ReplayCache, error) {
	switch {
	case window <= 0:
		return nil, errors.New("replay window must be greater than zero")
	case epochDuration <= 0:
		return nil, errors.New("epoch duration must be greater than zero")
	case maxItems <= 0:
		return nil, errors.New("replay max items must be greater than zero")
	}
	return &ReplayCache{
		window:        window,
		epochDuration: epochDuration,
		maxItems:      maxItems,
		entries:       make(map[string]int64, maxItems),
		buckets:       make(map[int64]map[string]struct{}),
	}, nil
}

func (c *ReplayCache) SeenOrAdd(identity []byte, now time.Time) bool {
	if len(identity) == 0 {
		return true
	}
	epoch := now.UTC().UnixNano() / c.epochDuration.Nanoseconds()

	c.mu.Lock()
	defer c.mu.Unlock()

	c.evictLocked(epoch)
	key := string(identity)
	if _, ok := c.entries[key]; ok {
		return true
	}
	if len(c.entries) >= c.maxItems {
		c.evictOneLocked()
	}
	if c.buckets[epoch] == nil {
		c.buckets[epoch] = make(map[string]struct{})
	}
	c.entries[key] = epoch
	c.buckets[epoch][key] = struct{}{}
	return false
}

func (c *ReplayCache) evictLocked(nowEpoch int64) {
	maxAge := c.window.Nanoseconds() / c.epochDuration.Nanoseconds()
	cutoff := nowEpoch - maxAge
	for epoch, keys := range c.buckets {
		if epoch > cutoff {
			continue
		}
		for key := range keys {
			delete(c.entries, key)
		}
		delete(c.buckets, epoch)
	}
}

func (c *ReplayCache) evictOneLocked() {
	var oldestEpoch int64
	hasOldest := false
	for epoch := range c.buckets {
		if !hasOldest || epoch < oldestEpoch {
			oldestEpoch = epoch
			hasOldest = true
		}
	}
	if !hasOldest {
		return
	}
	for key := range c.buckets[oldestEpoch] {
		delete(c.entries, key)
		delete(c.buckets[oldestEpoch], key)
		break
	}
	if len(c.buckets[oldestEpoch]) == 0 {
		delete(c.buckets, oldestEpoch)
	}
}
