package cache

import (
	"context"
	"encoding/json"
	"io"
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

// wakeSource delivers the producer's internal wake exactly as its 30-second
// rescan ticker does; no public API triggers a rescan of a changed tree, so
// this is the narrowest drive that keeps the real Run→publish→Next flow.
func wakeSource(source *Source) {
	select {
	case source.wake <- struct{}{}:
	default:
	}
}

// waitSynced receives one generation's sync result from the consume loop,
// failing the test if the producer does not deliver one promptly.
func waitSynced(t *testing.T, synced <-chan error) error {
	t.Helper()
	select {
	case err := <-synced:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("source did not publish a generation to sync")
		return nil
	}
}

func TestStaticCacheRefreshUsesContentDigest(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	var uploads atomic.Int32
	var accessToken atomic.Value
	accessToken.Store("lease-token")
	var cachedDigest string
	limits := types.StaticCacheLimits{MaxExposureBytes: 1024, MaxObjectSize: 512}
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(types.HeaderAccessToken) != accessToken.Load().(string) || r.URL.Path != types.PathSDKCache {
			http.Error(w, "unauthorized", http.StatusForbidden)
			return
		}
		if r.Method == http.MethodDelete {
			cachedDigest = ""
			utils.WriteAPIData(w, http.StatusOK, types.StaticCacheStatus{})
			return
		}
		var manifest types.StaticCacheManifest
		if r.Method == http.MethodPost {
			if err := json.NewDecoder(r.Body).Decode(&manifest); err != nil {
				t.Error(err)
				return
			}
			digest, _, err := manifestDigest(manifest, limits.MaxObjectSize, limits.MaxExposureBytes)
			if err != nil {
				t.Error(err)
				return
			}
			utils.WriteAPIData(w, http.StatusOK, types.StaticCacheStatus{Present: cachedDigest == digest})
			return
		}
		parts, err := r.MultipartReader()
		if err != nil {
			t.Error(err)
			return
		}
		part, err := parts.NextPart()
		if err != nil {
			t.Error(err)
			return
		}
		if err := json.NewDecoder(part).Decode(&manifest); err != nil {
			t.Error(err)
			return
		}
		for _, file := range manifest.Files {
			part, err = parts.NextPart()
			if err != nil {
				t.Error(err)
				return
			}
			if n, err := io.Copy(io.Discard, part); err != nil || n != file.Size {
				t.Errorf("upload size=%d expected=%d err=%v", n, file.Size, err)
				return
			}
		}
		cachedDigest, _, err = manifestDigest(manifest, limits.MaxObjectSize, limits.MaxExposureBytes)
		if err != nil {
			t.Error(err)
			return
		}
		uploads.Add(1)
		utils.WriteAPIData(w, http.StatusOK, types.StaticCacheStatus{Present: true})
	}))
	defer relay.Close()
	relayURL, _ := url.Parse(relay.URL)
	source, err := NewSource(SourceConfig{Path: root})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	syncer := source.Subscribe(*relayURL, limits)
	defer syncer.Close()
	go source.Run(ctx)
	t.Cleanup(source.Wait)
	synced := make(chan error, 8)
	go func() {
		// The SDK listener's consume loop: every published generation syncs
		// with the credentials available at that moment.
		for syncer.Next(ctx) {
			synced <- syncer.Sync(ctx, relay.Client(), accessToken.Load().(string))
		}
	}()

	if err := waitSynced(t, synced); err != nil {
		t.Fatalf("first generation: %v", err)
	}
	if uploads.Load() != 1 {
		t.Fatalf("first generation uploaded %d times", uploads.Load())
	}
	// An unchanged tree republishes the same digest, so the relay's presence
	// answer must suppress a second upload.
	wakeSource(source)
	if err := waitSynced(t, synced); err != nil {
		t.Fatalf("unchanged generation: %v", err)
	}
	if uploads.Load() != 1 {
		t.Fatalf("unchanged snapshot uploaded %d times", uploads.Load())
	}
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("second"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A later generation uses credentials renewed by the SDK, without keeping
	// an old lease token in the cache subscription.
	accessToken.Store("renewed-token")
	wakeSource(source)
	if err := waitSynced(t, synced); err != nil {
		t.Fatalf("changed generation: %v", err)
	}
	if uploads.Load() != 2 {
		t.Fatal("changed snapshot was not uploaded")
	}
	t.Run("symlink rejection", func(t *testing.T) {
		if err := os.Symlink(filepath.Join(root, "index.html"), filepath.Join(root, "link.html")); err != nil {
			t.Skipf("symlinks unavailable on this host: %v", err)
		}
		wakeSource(source)
		if err := waitSynced(t, synced); err == nil {
			t.Fatal("symlink accepted into snapshot")
		}
		if uploads.Load() != 2 {
			t.Fatal("invalid snapshot was uploaded")
		}
	})
}

func TestStaticCacheDoesNotFollowRedirects(t *testing.T) {
	var foreignRequests atomic.Int32
	foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		foreignRequests.Add(1)
		utils.WriteAPIData(w, http.StatusOK, types.StaticCacheStatus{})
	}))
	defer foreign.Close()
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("site"), 0o600); err != nil {
				t.Fatal(err)
			}
			var redirected atomic.Int32
			relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get(types.HeaderAccessToken) != "lease-token" || r.URL.Path != types.PathSDKCache {
					t.Error("cache request lost its lease authentication or fixed endpoint")
				}
				if r.Method == method {
					redirected.Add(1)
					http.Redirect(w, r, foreign.URL, http.StatusFound)
					return
				}
				utils.WriteAPIData(w, http.StatusOK, types.StaticCacheStatus{})
			}))
			defer relay.Close()
			relayURL, _ := url.Parse(relay.URL)
			source, err := NewSource(SourceConfig{Path: root})
			if err != nil {
				t.Fatal(err)
			}
			limits := types.StaticCacheLimits{MaxExposureBytes: 1024, MaxObjectSize: 512}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			syncer := source.Subscribe(*relayURL, limits)
			defer syncer.Close()
			go source.Run(ctx)
			t.Cleanup(source.Wait)
			synced := make(chan error, 4)
			go func() {
				for syncer.Next(ctx) {
					synced <- syncer.Sync(ctx, relay.Client(), "lease-token")
				}
			}()
			if method == http.MethodDelete {
				// The generation must reach the relay first, so the failed
				// generation below has a previous snapshot to invalidate.
				if err := waitSynced(t, synced); err != nil {
					t.Fatalf("initial generation: %v", err)
				}
				// A failed local generation must invalidate the previous relay
				// snapshot without following a redirect carrying its lease token.
				if err := os.Symlink(filepath.Join(root, "index.html"), filepath.Join(root, "link.html")); err != nil {
					t.Skipf("symlinks unavailable on this host: %v", err)
				}
				wakeSource(source)
			}
			if err := waitSynced(t, synced); err == nil {
				t.Fatal("redirect accepted as a successful cache operation")
			}
			if redirected.Load() != 1 || foreignRequests.Load() != 0 {
				t.Fatalf("redirect requests: configured=%d foreign=%d", redirected.Load(), foreignRequests.Load())
			}
		})
	}
}
