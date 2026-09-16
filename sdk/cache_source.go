package sdk

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

	"github.com/gosuda/portal-tunnel/v2/internal/cachemanifest"
	"github.com/gosuda/portal-tunnel/v2/types"
)

type staticCacheConfig struct {
	root, index string
	ttl         time.Duration
}

// staticCacheSource belongs to one exposure. Its producer publishes immutable
// manifests to every relay; subscribers own only transport and relay limits.
type staticCacheSource struct {
	cfg      staticCacheConfig
	mu       sync.Mutex
	limits   map[string]types.StaticCacheLimits
	snapshot *staticSnapshot
	changed  chan struct{}
	wake     chan struct{}
	done     chan struct{}
}

type staticSnapshot struct {
	root     string
	manifest types.StaticCacheManifest
	err      error
}

func newStaticCacheSource(cfg staticCacheConfig) *staticCacheSource {
	return &staticCacheSource{cfg: cfg, limits: make(map[string]types.StaticCacheLimits), changed: make(chan struct{}), wake: make(chan struct{}, 1), done: make(chan struct{})}
}

func (s *staticCacheSource) subscribe(relay string, limits *types.StaticCacheLimits) {
	s.mu.Lock()
	if limits == nil {
		delete(s.limits, relay)
	} else {
		s.limits[relay] = *limits
	}
	// A newly connected relay consumes the current generation. Only a missing
	// or failed snapshot needs an immediate rebuild (possibly with larger limits).
	wake := limits != nil && (s.snapshot == nil || s.snapshot.err != nil)
	s.mu.Unlock()
	if wake {
		select {
		case s.wake <- struct{}{}:
		default:
		}
	}
}

func (s *staticCacheSource) current() (*staticSnapshot, <-chan struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.snapshot, s.changed
}

func (s *staticCacheSource) run(ctx context.Context) {
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

func (s *staticCacheSource) scan(ctx context.Context, limits types.StaticCacheLimits) *staticSnapshot {
	snapshot := &staticSnapshot{root: s.cfg.root, manifest: types.StaticCacheManifest{Index: s.cfg.index}}
	root, err := os.OpenRoot(s.cfg.root)
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
	_, _, snapshot.err = cachemanifest.Digest(snapshot.manifest, limits.MaxObjectSize, limits.MaxExposureBytes)
	return snapshot
}
