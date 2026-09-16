package portal

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
)

// staticCache owns both staging and published bytes. Registry operations only
// mutate metadata; disk work never holds the registry's lock.
type staticCache struct {
	mu         sync.Mutex
	cfg        types.RelayCacheConfig
	entries    map[string]*cachedSite
	retired    []*cachedSite
	used       int64
	snapshots  int
	population chan struct{}
}

type cachedSite struct {
	host, owner, leaseID, clientIP string
	digest, dir, index             string
	files                          map[string]types.StaticCacheFile
	bytes                          int64
	ttl                            time.Duration
	expiresAt, usedAt              time.Time
	readers                        int
}

func newStaticCache(cfg types.RelayCacheConfig) (*staticCache, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	if err := os.MkdirAll(cfg.Dir, 0o700); err != nil {
		return nil, err
	}
	// This operator-selected directory must be exclusive to this relay. Only
	// our generated snapshot directories are disposable across restarts.
	children, err := os.ReadDir(cfg.Dir)
	if err != nil {
		return nil, err
	}
	for _, child := range children {
		if child.IsDir() && strings.HasPrefix(child.Name(), "portal-cache-") {
			if err := os.RemoveAll(filepath.Join(cfg.Dir, child.Name())); err != nil {
				return nil, err
			}
		}
	}
	return &staticCache{cfg: cfg, entries: make(map[string]*cachedSite), population: make(chan struct{}, cfg.PopulationConcurrency)}, nil
}

// retireLocked removes routing immediately, while readers and failed disk
// cleanup keep their bytes charged until the directory is actually removed.
func (c *staticCache) retireLocked(site *cachedSite) {
	delete(c.entries, site.host)
	c.retired = append(c.retired, site)
}

func (c *staticCache) invalidate(record *leaseRecord) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, site := range c.entries {
		if record.routesOverlap(&leaseRecord{Hostname: site.host}) || record.Key() == site.owner {
			c.retireLocked(site)
		}
	}
}

func (c *staticCache) renew(record *leaseRecord) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if site := c.entries[record.Hostname]; site != nil && site.leaseID == record.id {
		if !time.Now().Before(site.expiresAt) {
			c.retireLocked(site)
			return
		}
		site.expiresAt = record.cacheExpiresAt()
		site.clientIP = record.ClientIP
	}
}

func (c *staticCache) detach(record *leaseRecord) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if site := c.entries[record.Hostname]; site != nil && site.leaseID == record.id {
		disconnected := time.Now()
		if !disconnected.Before(site.expiresAt) {
			c.retireLocked(site)
			return
		}
		if record.ExpiresAt.Before(disconnected) {
			disconnected = record.ExpiresAt
		}
		// Disconnecting may shorten retention, never extend the last observed
		// liveness bound (which may precede a long-lived lease's expiry).
		if expiresAt := disconnected.Add(site.ttl); expiresAt.Before(site.expiresAt) {
			site.expiresAt = expiresAt
		}
	}
}

func (c *staticCache) collect(now time.Time) {
	if c == nil {
		return
	}
	c.mu.Lock()
	for _, site := range c.entries {
		if !now.Before(site.expiresAt) {
			c.retireLocked(site)
		}
	}
	var ready []*cachedSite
	previous := c.retired
	kept := previous[:0]
	for _, site := range c.retired {
		if site.readers == 0 {
			ready = append(ready, site)
		} else {
			kept = append(kept, site)
		}
	}
	clear(previous[len(kept):])
	c.retired = kept
	c.mu.Unlock()
	for _, site := range ready {
		err := os.RemoveAll(site.dir)
		c.mu.Lock()
		if err == nil {
			c.used -= site.bytes
			c.snapshots--
		} else {
			c.retired = append(c.retired, site)
		}
		c.mu.Unlock()
	}
}

func (c *staticCache) reserve(size int64) error {
	c.collect(time.Now())
	for {
		c.mu.Lock()
		if size <= int64(c.cfg.MaxBytes)-c.used && c.snapshots < types.StaticCacheMaxEntries {
			c.used += size
			c.snapshots++
			c.mu.Unlock()
			return nil
		}
		var oldest *cachedSite
		for _, site := range c.entries {
			if site.readers != 0 {
				continue
			}
			if oldest == nil {
				oldest = site
				continue
			}
			earlier := site.usedAt.Before(oldest.usedAt)
			tie := site.usedAt.Equal(oldest.usedAt) && site.host < oldest.host
			if earlier || tie {
				oldest = site
			}
		}
		if oldest == nil {
			c.mu.Unlock()
			return errors.New("relay cache is full")
		}
		c.retireLocked(oldest)
		c.mu.Unlock()
		c.collect(time.Now())
	}
}

// acquire pins disk files across concurrent eviction. Admission and policy
// checks use the same registry -> cache lock order as lease replacement.
func (r *leaseRegistry) acquireCachedSite(host string) *cachedSite {
	c := r.cache
	if c == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	c.mu.Lock()
	defer c.mu.Unlock()
	site := c.entries[host]
	if site == nil || !time.Now().Before(site.expiresAt) || !r.policy.IsIdentityRoutable(site.owner) || r.policy.IPFilter().IsIPBanned(site.clientIP) {
		return nil
	}
	site.readers++
	site.usedAt = time.Now()
	return site
}

func (c *staticCache) release(site *cachedSite) {
	c.mu.Lock()
	site.readers--
	c.mu.Unlock()
}
