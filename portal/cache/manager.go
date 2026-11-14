package cache

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

var (
	errCacheDirectoryIsRequired     = errors.New("cache directory is required")
	errRelayCacheIsFull             = errors.New("relay cache is full")
	errCacheTotalBytesMustPositive  = errors.New("cache total bytes must be positive")
	errCacheOfflineTTLMustBetween1s = errors.New("cache offline TTL must be between 1s and 8760h")
)

// Config is operator policy. Tenant fairness and request admission are internal
// cache responsibilities; origins can only request a shorter offline TTL.
type Config struct {
	Enabled  bool
	MaxBytes int
	MaxTTL   time.Duration
}

func (cfg Config) Validate() error {
	if !cfg.Enabled {
		return nil
	}
	if cfg.MaxBytes <= 0 {
		return errCacheTotalBytesMustPositive
	}
	if cfg.MaxTTL < time.Second || cfg.MaxTTL > 365*24*time.Hour {
		return errCacheOfflineTTLMustBetween1s
	}
	return nil
}

// Manager owns both staging and published bytes. Registry operations only
// mutate metadata; disk work never holds the registry's lock.
type Manager struct {
	mu         sync.Mutex
	cfg        Config
	dir        string
	limits     types.StaticCacheLimits
	leases     map[string]leaseState
	entries    map[string]*cachedSite
	retired    []*cachedSite
	used       int64
	snapshots  int
	uploads    map[types.ServiceIdentityKey]struct{}
	checks     chan struct{}
	generation uint64
}

type cachedSite struct {
	host, leaseID      string
	owner              types.ServiceIdentityKey
	digest, dir, index string
	files              map[string]types.StaticCacheFile
	bytes              int64
	ttl                time.Duration
	expiresAt, usedAt  time.Time
	readers            int
}

// New requires an explicit storage directory from the host application.
// It never infers a cleanup location from the process working directory.
func New(cfg Config, dir string) (*Manager, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	if strings.TrimSpace(dir) == "" {
		return nil, errCacheDirectoryIsRequired
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	dir, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := clearStaleCacheDirs(dir); err != nil {
		return nil, err
	}
	exposureBytes := min(64<<20, max(1, cfg.MaxBytes/4))
	return &Manager{
		cfg: cfg, dir: dir,
		limits: types.StaticCacheLimits{MaxExposureBytes: int64(exposureBytes), MaxObjectSize: int64(min(10<<20, exposureBytes))},
		leases: make(map[string]leaseState), entries: make(map[string]*cachedSite),
		uploads: make(map[types.ServiceIdentityKey]struct{}),
		checks:  make(chan struct{}, 2),
	}, nil
}

func clearStaleCacheDirs(dir string) error {
	children, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, child := range children {
		if child.IsDir() && strings.HasPrefix(child.Name(), "portal-cache-") {
			if err := os.RemoveAll(filepath.Join(dir, child.Name())); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *Manager) retireLocked(site *cachedSite) {
	if site == nil || c.entries[site.host] != site {
		return
	}
	delete(c.entries, site.host)
	c.retired = append(c.retired, site)
}

// Lease is an immutable observation supplied by the lease registry. Cache
// policy and effective retention are owned only by Manager.
type Lease struct {
	ID, Hostname          string
	Owner                 types.ServiceIdentityKey
	ExpiresAt, LastSeenAt time.Time
}

type leaseState struct {
	Lease
	ttl        time.Duration
	generation uint64
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

func (c *Manager) Register(lease Lease, req types.RegisterChallengeRequest) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if site := c.entries[lease.Hostname]; site != nil {
		c.retireLocked(site)
	}
	for id, previous := range c.leases {
		if lease.Owner == previous.Owner || lease.Hostname == previous.Hostname {
			delete(c.leases, id)
		}
	}
	if !req.Cache || req.UDPEnabled || req.TCPEnabled {
		return
	}
	if lease.Hostname == "" || strings.Contains(lease.Hostname, "*") {
		return
	}
	ttl := c.cfg.MaxTTL
	if req.CacheTTL > 0 && int64(req.CacheTTL) < int64(ttl/time.Second) {
		ttl = time.Duration(req.CacheTTL) * time.Second
	}
	c.generation++
	c.leases[lease.ID] = leaseState{Lease: lease, ttl: ttl, generation: c.generation}
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

// Owners returns identities with a retained published snapshot. The relay uses
// this observation to project access changes after the live lease is gone.
func (c *Manager) Owners() []types.ServiceIdentityKey {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	owners := make(map[types.ServiceIdentityKey]struct{})
	for _, site := range c.entries {
		owners[site.owner] = struct{}{}
	}
	out := make([]types.ServiceIdentityKey, 0, len(owners))
	for owner := range owners {
		out = append(out, owner)
	}
	return out
}

// Eligible reports whether the live lease supports cache operations.
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
	return ok && time.Now().Before(lease.ExpiresAt)
}

// Generation identifies this lease's current cache admission. Capture it before
// checking external access; Handle rejects the request if revocation intervenes.
func (c *Manager) Generation(id string) uint64 {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.leases[id].generation
}

// DetachOwner immediately revokes cached content owned by one identity while
// retaining its live cache lease. If the relay routes the identity again, the
// same lease may publish fresh content without re-registering.
func (c *Manager) DetachOwner(owner types.ServiceIdentityKey) {
	if c == nil || !owner.Valid() {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.generation++
	for id, lease := range c.leases {
		if lease.Owner == owner {
			lease.generation = c.generation
			c.leases[id] = lease
		}
	}
	for _, site := range c.entries {
		if site.owner == owner {
			c.retireLocked(site)
		}
	}
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
		oldest := c.oldestEvictableLocked()
		if oldest == nil {
			c.mu.Unlock()
			return errRelayCacheIsFull
		}
		c.retireLocked(oldest)
		c.mu.Unlock()
		c.collect(time.Now())
	}
}

func (c *Manager) oldestEvictableLocked() *cachedSite {
	var oldest *cachedSite
	for _, site := range c.entries {
		if site.readers != 0 {
			continue
		}
		if oldest == nil {
			oldest = site
			continue
		}
		if site.usedAt.Before(oldest.usedAt) || (site.usedAt.Equal(oldest.usedAt) && site.host < oldest.host) {
			oldest = site
		}
	}
	return oldest
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
	if site == nil || !time.Now().Before(site.expiresAt) {
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

// Serve returns false for origin fallback. Disk pins are confined to this
// method, so the caller never retains cached bytes while contacting an origin.
func (c *Manager) Serve(w http.ResponseWriter, req *http.Request, host string) bool {
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		return false
	}
	site := c.acquire(host)
	if site == nil {
		return false
	}
	defer c.release(site)
	rel, valid := utils.StaticSiteRequestPath("/", req.URL.Path)
	if !valid {
		http.NotFound(w, req)
		return true
	}
	file, found := site.files[strings.TrimPrefix(rel, "/")]
	if !found {
		file = site.files[site.index]
	}
	input, err := os.OpenInRoot(site.dir, file.SHA256)
	if err != nil {
		c.discard(site)
		return false
	}
	defer input.Close()
	info, err := input.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != file.Size {
		c.discard(site)
		return false
	}
	w.Header().Set("ETag", `"`+file.SHA256+`"`)
	w.Header().Set("Cache-Control", "no-cache")
	reader := &siteReader{File: input, size: info.Size()}
	http.ServeContent(w, req, file.Path, time.Time{}, reader)
	if reader.failed {
		c.discard(site)
	}
	return true
}

func (c *Manager) discard(site *cachedSite) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries[site.host] == site {
		c.retireLocked(site)
	}
}

type siteReader struct {
	*os.File
	failed         bool
	position, size int64
}

func (r *siteReader) Read(p []byte) (int, error) {
	n, err := r.File.Read(p)
	r.position += int64(n)
	short := err == io.EOF && r.position < r.size
	if short || (err != nil && err != io.EOF) {
		r.failed = true
	}
	return n, err
}

func (r *siteReader) Seek(offset int64, whence int) (int64, error) {
	n, err := r.File.Seek(offset, whence)
	if err != nil {
		r.failed = true
	} else {
		r.position = n
	}
	return n, err
}
