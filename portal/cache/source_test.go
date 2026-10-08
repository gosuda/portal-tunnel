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

// startTestSource runs the real producer for the tree and stops it when the
// test ends.
func startTestSource(t *testing.T, root string) (*Source, context.CancelFunc) {
	t.Helper()
	source, err := NewSource(SourceConfig{Path: root})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go source.Run(ctx)
	t.Cleanup(func() { cancel(); source.Wait() })
	return source, cancel
}

// newCountingRelay answers as a relay that already holds the generation, so a
// successful sync is one probe and a failed one exactly one delete.
func newCountingRelay(t *testing.T, want []byte) (*httptest.Server, *atomic.Int32, *atomic.Int32) {
	t.Helper()
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
	t.Cleanup(relay.Close)
	return relay, &probes, &invalidations
}

// Joining relays must consume the existing generation without rediscovering
// the source, even if the static tree changed.
func TestSourceSharesGenerationAcrossRelays(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "index.html")
	if err := os.WriteFile(path, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	source, _ := startTestSource(t, root)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	want := sha256.Sum256([]byte("first"))
	limits := types.StaticCacheLimits{MaxExposureBytes: 1024, MaxObjectSize: 512}

	firstRelay, probes, invalidations := newCountingRelay(t, want[:])
	firstURL, _ := url.Parse(firstRelay.URL)
	first := source.Subscribe(*firstURL, limits)
	defer first.Close()
	if !first.Next(ctx) {
		t.Fatal("source did not publish a shared generation")
	}
	if err := first.Sync(ctx, firstRelay.Client(), "lease-token"); err != nil {
		t.Fatalf("first relay sync: %v", err)
	}
	if probes.Load() != 1 || invalidations.Load() != 0 {
		t.Fatalf("first relay: probes=%d invalidations=%d", probes.Load(), invalidations.Load())
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}

	joinRelay, probes, invalidations := newCountingRelay(t, want[:])
	joinURL, _ := url.Parse(joinRelay.URL)
	joiner := source.Subscribe(*joinURL, limits)
	defer joiner.Close()
	if !joiner.Next(ctx) {
		t.Fatal("joining relay did not receive the shared generation")
	}
	if err := joiner.Sync(ctx, joinRelay.Client(), "lease-token"); err != nil {
		t.Fatalf("joining relay sync: %v", err)
	}
	if probes.Load() != 1 || invalidations.Load() != 0 {
		t.Fatalf("joining relay: probes=%d invalidations=%d", probes.Load(), invalidations.Load())
	}
}

// A relay whose advertised limits reject the shared generation fails locally:
// no probe reaches the relay and the failed sync invalidates exactly once.
func TestSourceLimitRejectionProbesNothingAndDeletesOnce(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	source, _ := startTestSource(t, root)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	limits := types.StaticCacheLimits{MaxExposureBytes: 1024, MaxObjectSize: 512}
	// A subscriber with room for the generation keeps the producer's shared
	// scan alive; the small relay must then reject it by itself.
	spaciousURL, _ := url.Parse("https://spacious.example")
	spacious := source.Subscribe(*spaciousURL, limits)
	defer spacious.Close()
	want := sha256.Sum256([]byte("first"))
	relay, probes, invalidations := newCountingRelay(t, want[:])
	relayURL, _ := url.Parse(relay.URL)
	small := source.Subscribe(*relayURL, types.StaticCacheLimits{MaxExposureBytes: 4, MaxObjectSize: 4})
	defer small.Close()
	if !small.Next(ctx) {
		t.Fatal("source did not publish a shared generation")
	}
	err := small.Sync(ctx, relay.Client(), "lease-token")
	if err == nil || probes.Load() != 0 || invalidations.Load() != 1 {
		t.Fatalf("relay limit bypassed: err=%v probes=%d invalidations=%d", err, probes.Load(), invalidations.Load())
	}
}

// Ending the source also releases subscribers waiting for another generation,
// even if their individual relay context has not yet been canceled.
func TestSourceShutdownReleasesWaitingSubscribers(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	source, stopSource := startTestSource(t, root)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	relayURL, _ := url.Parse("https://waiting.example")
	waiting := source.Subscribe(*relayURL, types.StaticCacheLimits{MaxExposureBytes: 1024, MaxObjectSize: 512})
	defer waiting.Close()
	if !waiting.Next(ctx) {
		t.Fatal("subscriber did not receive the current generation")
	}
	stopSource()
	source.Wait()
	waitCtx, waitCancel := context.WithTimeout(context.Background(), time.Second)
	defer waitCancel()
	if waiting.Next(waitCtx) || waitCtx.Err() != nil {
		t.Fatal("subscriber did not stop with its source")
	}
}
