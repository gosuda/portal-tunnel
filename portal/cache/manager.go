package cache

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/policy"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

// Manager owns both staging and published bytes. Registry operations only
// mutate metadata; disk work never holds the registry's lock.
type Manager struct {
	mu         sync.Mutex
	cfg        Config
	dir        string
	limits     types.StaticCacheLimits
	policy     *policy.Runtime
	leases     map[string]leaseState
	entries    map[string]*cachedSite
	retired    []*cachedSite
	used       int64
	snapshots  int
	population chan struct{}
	checks     chan struct{}
}

type cachedSite struct {
	host, owner, leaseID string
	digest, dir, index   string
	files                map[string]types.StaticCacheFile
	bytes                int64
	ttl                  time.Duration
	expiresAt, usedAt    time.Time
	readers              int
}

// New requires an explicit storage directory from the host application.
// It never infers a cleanup location from the process working directory.
func New(cfg Config, dir string, policy *policy.Runtime) (*Manager, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	if strings.TrimSpace(dir) == "" {
		return nil, errors.New("cache directory is required")
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	dir, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	if policy == nil {
		return nil, errors.New("cache policy runtime is required")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	// This host-provided directory must be exclusive to this relay. Only
	// our generated snapshot directories are disposable across restarts.
	children, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, child := range children {
		if child.IsDir() && strings.HasPrefix(child.Name(), "portal-cache-") {
			if err := os.RemoveAll(filepath.Join(dir, child.Name())); err != nil {
				return nil, err
			}
		}
	}
	// A tenant may use at most a quarter of the total budget, capped at
	// 64 MiB, with a one-byte minimum for tiny budgets.
	exposureBytes := min(64<<20, max(1, cfg.MaxBytes/4))
	return &Manager{
		cfg: cfg, dir: dir, policy: policy,
		limits: types.StaticCacheLimits{MaxExposureBytes: int64(exposureBytes), MaxObjectSize: int64(min(10<<20, exposureBytes))},
		leases: make(map[string]leaseState), entries: make(map[string]*cachedSite),
		population: make(chan struct{}, 2),
		checks:     make(chan struct{}, 2),
	}, nil
}

// retireLocked removes routing immediately, while readers and failed disk
// cleanup keep their bytes charged until the directory is actually removed.
func (c *Manager) retireLocked(site *cachedSite) {
	delete(c.entries, site.host)
	c.retired = append(c.retired, site)
}

// Lease is an immutable observation supplied by the lease registry. Cache
// policy and effective retention are owned only by Manager.
type Lease struct {
	ID, Owner, Hostname, HostnameHash string
	ExpiresAt, LastSeenAt             time.Time
}

type leaseState struct {
	Lease
	ttl time.Duration
}

const observationWindow = 2 * time.Minute
const maxSnapshots = 128

func (l leaseState) cacheExpiry() time.Time {
	until := l.LastSeenAt.Add(observationWindow)
	if l.ExpiresAt.Before(until) {
		until = l.ExpiresAt
	}
	return until.Add(l.ttl)
}

func (l Lease) replaces(owner, host string) bool {
	if l.Owner == owner || l.Hostname == host {
		return true
	}
	return l.HostnameHash != "" && utils.HostnameHash(host) == l.HostnameHash
}

func (c *Manager) Register(lease Lease, req types.RegisterChallengeRequest) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	// A new lease revokes overlapping cached content, including offline sites
	// and registrations that do not opt in or switch to hidden hostnames.
	for _, site := range c.entries {
		if lease.replaces(site.owner, site.host) {
			c.retireLocked(site)
		}
	}
	for id, previous := range c.leases {
		if lease.replaces(previous.Owner, previous.Hostname) {
			delete(c.leases, id)
		}
	}
	if !req.Cache || req.UDPEnabled || req.TCPEnabled {
		return
	}
	if lease.HostnameHash != "" || strings.Contains(lease.Hostname, "*") {
		return
	}
	ttl := c.cfg.MaxTTL
	if req.CacheTTL > 0 && int64(req.CacheTTL) < int64(ttl/time.Second) {
		ttl = time.Duration(req.CacheTTL) * time.Second
	}
	c.leases[lease.ID] = leaseState{Lease: lease, ttl: ttl}
}

func (c *Manager) Renew(lease Lease) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	state, ok := c.leases[lease.ID]
	if !ok {
		return
	}
	state.Lease = lease
	c.leases[lease.ID] = state
	if site := c.entries[lease.Hostname]; site != nil && site.leaseID == lease.ID {
		if !time.Now().Before(site.expiresAt) {
			c.retireLocked(site)
			return
		}
		site.expiresAt = state.cacheExpiry()
	}
}

func (c *Manager) Detach(lease Lease) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.leases, lease.ID)
	if site := c.entries[lease.Hostname]; site != nil && site.leaseID == lease.ID {
		disconnected := time.Now()
		if !disconnected.Before(site.expiresAt) {
			c.retireLocked(site)
			return
		}
		if lease.ExpiresAt.Before(disconnected) {
			disconnected = lease.ExpiresAt
		}
		if expiry := disconnected.Add(site.ttl); expiry.Before(site.expiresAt) {
			site.expiresAt = expiry
		}
	}
}

func (c *Manager) Run(ctx context.Context) error {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case now := <-ticker.C:
			c.collect(now)
		}
	}
}

func (c *Manager) Limits() *types.StaticCacheLimits {
	if c == nil {
		return nil
	}
	limits := c.limits
	return &limits
}

// Eligible checks the current lease event and the live policy owner. It is
// also used immediately before publishing to reject late/revoked uploads.
func (c *Manager) Eligible(id string) bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.eligibleLocked(id)
}

func (c *Manager) eligibleLocked(id string) bool {
	lease, ok := c.leases[id]
	return ok && time.Now().Before(lease.ExpiresAt) && c.policy.IsIdentityRoutable(lease.Owner)
}

func (c *Manager) collect(now time.Time) {
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

func (c *Manager) reserve(size int64) error {
	c.collect(time.Now())
	for {
		c.mu.Lock()
		if size <= int64(c.cfg.MaxBytes)-c.used && c.snapshots < maxSnapshots {
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

// Has is an ingress routing hint; it does not pin disk content.
func (c *Manager) Has(host string) bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lookupLocked(host) != nil
}

func (c *Manager) lookupLocked(host string) *cachedSite {
	site := c.entries[host]
	if site == nil || !time.Now().Before(site.expiresAt) || !c.policy.IsIdentityRoutable(site.owner) {
		return nil
	}
	return site
}

func (c *Manager) acquire(host string) *cachedSite {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	site := c.lookupLocked(host)
	if site != nil {
		site.readers++
		site.usedAt = time.Now()
	}
	return site
}

func (c *Manager) release(site *cachedSite) {
	c.mu.Lock()
	site.readers--
	c.mu.Unlock()
}
