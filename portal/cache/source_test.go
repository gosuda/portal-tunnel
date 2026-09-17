package cache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func TestSourceSharesGenerationAcrossRelays(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "index.html")
	if err := os.WriteFile(path, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := NewSource(SourceConfig{Path: root})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	go source.Run(ctx)
	t.Cleanup(func() { cancel(); source.Wait() })
	want := sha256.Sum256([]byte("first"))
	for _, name := range []string{"first", "second", "smaller"} {
		t.Run(name, func(t *testing.T) {
			var probes, invalidations atomic.Int32
			relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get(types.HeaderAccessToken) != "lease-token" {
					t.Error("cache request lost its lease token")
				}
				switch r.Method {
				case http.MethodDelete:
					invalidations.Add(1)
					utils.WriteAPIData(w, http.StatusOK, types.StaticCacheStatus{})
					return
				case http.MethodPost:
					probes.Add(1)
				default:
					t.Errorf("unexpected method %s", r.Method)
					http.Error(w, "bad method", 400)
					return
				}
				var manifest types.StaticCacheManifest
				if err := json.NewDecoder(r.Body).Decode(&manifest); err != nil {
					t.Error(err)
					http.Error(w, "bad manifest", 400)
					return
				}
				if len(manifest.Files) != 1 || manifest.Files[0].SHA256 != hex.EncodeToString(want[:]) {
					t.Error("relay did not receive shared immutable manifest")
				}
				utils.WriteAPIData(w, http.StatusOK, types.StaticCacheStatus{Present: true})
			}))
			defer relay.Close()
			relayURL, _ := url.Parse(relay.URL)
			limits := types.StaticCacheLimits{MaxExposureBytes: 1024, MaxObjectSize: 512}
			if name == "smaller" {
				limits = types.StaticCacheLimits{MaxExposureBytes: 4, MaxObjectSize: 4}
			}
			syncer := source.Subscribe(*relayURL, limits)
			defer syncer.Close()
			if !syncer.Next(ctx) {
				t.Fatal("source did not publish a shared generation")
			}
			err := syncer.Sync(ctx, relay.Client(), "lease-token")
			if name == "smaller" {
				if err == nil || probes.Load() != 0 || invalidations.Load() != 1 {
					t.Fatalf("relay limit bypassed: err=%v probes=%d invalidations=%d", err, probes.Load(), invalidations.Load())
				}
				return
			}
			if err != nil || probes.Load() != 1 || invalidations.Load() != 0 {
				t.Fatalf("shared generation: err=%v probes=%d invalidations=%d", err, probes.Load(), invalidations.Load())
			}
			if name == "first" {
				// Joining relays must consume the existing generation without
				// rediscovering the source, even if the static tree changed.
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
	current, _ := source.current()
	failed := source.scan(ctx, types.StaticCacheLimits{MaxExposureBytes: 1024, MaxObjectSize: 512})
	if failed.err == nil || current == nil || current.err != nil || len(current.manifest.Files) != 1 {
		t.Fatal("source rebuild lost generation isolation")
	}
	// Ending the source also releases subscribers waiting for another generation,
	// even if their individual relay context has not yet been canceled.
	relayURL, _ := url.Parse("https://waiting.example")
	waiting := source.Subscribe(*relayURL, types.StaticCacheLimits{MaxExposureBytes: 1024, MaxObjectSize: 512})
	defer waiting.Close()
	if !waiting.Next(ctx) {
		t.Fatal("subscriber did not receive the current generation")
	}
	cancel()
	source.Wait()
	waitCtx, waitCancel := context.WithTimeout(context.Background(), time.Second)
	defer waitCancel()
	if waiting.Next(waitCtx) || waitCtx.Err() != nil {
		t.Fatal("subscriber did not stop with its source")
	}
}
