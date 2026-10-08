package cache

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

// SourceConfig identifies the static site and its requested offline lifetime.
// A zero TTL accepts the relay's maximum lifetime.
type SourceConfig struct {
	Path string
	TTL  time.Duration
}

// Source belongs to one exposure. Its producer publishes immutable
// manifests to every relay; subscribers own only transport and relay limits.
type Source struct {
	root, index string
	ttl         time.Duration
	mu          sync.Mutex
	limits      map[string]types.StaticCacheLimits
	snapshot    *sourceSnapshot
	changed     chan struct{}
	wake        chan struct{}
	done        chan struct{}
}

type sourceSnapshot struct {
	root     string
	manifest types.StaticCacheManifest
	err      error
}

// NewSource resolves and validates a static site without starting background work.
func NewSource(cfg SourceConfig) (*Source, error) {
	if cfg.TTL != 0 && (cfg.TTL < time.Second || cfg.TTL > 365*24*time.Hour) {
		return nil, errors.New("relay cache TTL must be zero or between 1s and 8760h")
	}
	root, index, err := utils.ResolveStaticSite(cfg.Path)
	if err != nil {
		return nil, fmt.Errorf("relay cache source: %w", err)
	}
	return &Source{root: root, index: index, ttl: cfg.TTL, limits: make(map[string]types.StaticCacheLimits), changed: make(chan struct{}), wake: make(chan struct{}, 1), done: make(chan struct{})}, nil
}

// ConfigureRegistration applies this source's cache permission and requested TTL.
// A nil source leaves ordinary exposure registration unchanged.
func (s *Source) ConfigureRegistration(req *types.RegisterChallengeRequest) {
	if s == nil {
		return
	}
	req.Cache = true
	req.CacheTTL = int(s.ttl / time.Second)
}

func (s *Source) current() (*sourceSnapshot, <-chan struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.snapshot, s.changed
}

// Run produces shared snapshot generations until cancellation. The exposure
// starts it exactly once and calls Wait after canceling its context.
func (s *Source) Run(ctx context.Context) {
	defer close(s.done)
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.wake:
		case <-ticker.C:
		}
		s.mu.Lock()
		var limits types.StaticCacheLimits
		for _, relay := range s.limits {
			limits.MaxExposureBytes = max(limits.MaxExposureBytes, relay.MaxExposureBytes)
			limits.MaxObjectSize = max(limits.MaxObjectSize, relay.MaxObjectSize)
		}
		s.mu.Unlock()
		if limits.MaxExposureBytes == 0 {
			continue
		}
		snapshot := s.scan(ctx, limits)
		if ctx.Err() != nil {
			return
		}
		s.mu.Lock()
		s.snapshot = snapshot
		close(s.changed)
		s.changed = make(chan struct{})
		s.mu.Unlock()
	}
}

// Wait waits for the producer started by Run to stop.
func (s *Source) Wait() {
	<-s.done
}

func (s *Source) scan(ctx context.Context, limits types.StaticCacheLimits) *sourceSnapshot {
	snapshot := &sourceSnapshot{root: s.root, manifest: types.StaticCacheManifest{Index: s.index}}
	root, err := os.OpenRoot(s.root)
	if err != nil {
		snapshot.err = err
		return snapshot
	}
	defer root.Close()
	var total int64
	snapshot.err = fs.WalkDir(root.FS(), ".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("cache source %q is not a regular file", path)
		}
		if len(snapshot.manifest.Files) >= types.StaticCacheMaxFiles {
			return errors.New("too many static cache files")
		}
		file, err := root.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()
		info, err := file.Stat()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Size() > limits.MaxObjectSize || info.Size() > limits.MaxExposureBytes-total {
			return fmt.Errorf("cache source %q exceeds relay limits or is not a regular file", path)
		}
		hash := sha256.New()
		if _, err := io.CopyN(hash, file, info.Size()); err != nil {
			return err
		}
		snapshot.manifest.Files = append(snapshot.manifest.Files, types.StaticCacheFile{Path: path, Size: info.Size(), SHA256: hex.EncodeToString(hash.Sum(nil))})
		total += info.Size()
		return nil
	})
	if snapshot.err != nil {
		return snapshot
	}
	slices.SortFunc(snapshot.manifest.Files, func(a, b types.StaticCacheFile) int { return cmp.Compare(a.Path, b.Path) })
	_, _, snapshot.err = manifestDigest(snapshot.manifest, limits.MaxObjectSize, limits.MaxExposureBytes)
	return snapshot
}
