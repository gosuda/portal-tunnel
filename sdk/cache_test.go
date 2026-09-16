package sdk

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

	"github.com/gosuda/portal-tunnel/v2/internal/cachemanifest"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func TestStaticCacheRefreshUsesContentDigest(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	var uploads atomic.Int32
	var cachedDigest string
	limits := types.StaticCacheLimits{MaxExposureBytes: 1024, MaxObjectSize: 512}
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(types.HeaderAccessToken) != "lease-token" || r.URL.Path != types.PathSDKCache {
			http.Error(w, "unauthorized", http.StatusForbidden)
			return
		}
		var manifest types.StaticCacheManifest
		if r.Method == http.MethodPost {
			if err := json.NewDecoder(r.Body).Decode(&manifest); err != nil {
				t.Error(err)
				return
			}
			digest, _, err := cachemanifest.Digest(manifest, limits.MaxObjectSize, limits.MaxExposureBytes)
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
		cachedDigest, _, err = cachemanifest.Digest(manifest, limits.MaxObjectSize, limits.MaxExposureBytes)
		if err != nil {
			t.Error(err)
			return
		}
		uploads.Add(1)
		utils.WriteAPIData(w, http.StatusOK, types.StaticCacheStatus{Present: true})
	}))
	defer relay.Close()
	relayURL, _ := url.Parse(relay.URL)
	l := &listener{
		api:   &apiClient{relayURL: relayURL, http: relay.Client()},
		cache: newStaticCacheSource(staticCacheConfig{root: root, index: "index.html"}),
		lease: utils.NewSnapshot(listenerSnapshot{accessToken: "lease-token"}, listenerSnapshot.snapshot),
	}
	for range 2 {
		if err := l.syncStaticCache(context.Background(), limits, l.cache.scan(context.Background(), limits)); err != nil {
			t.Fatal(err)
		}
	}
	if uploads.Load() != 1 {
		t.Fatalf("unchanged snapshot uploaded %d times", uploads.Load())
	}
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("second"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := l.syncStaticCache(context.Background(), limits, l.cache.scan(context.Background(), limits)); err != nil {
		t.Fatal(err)
	}
	if uploads.Load() != 2 {
		t.Fatal("changed snapshot was not uploaded")
	}
	t.Run("symlink rejection", func(t *testing.T) {
		if err := os.Symlink(filepath.Join(root, "index.html"), filepath.Join(root, "link.html")); err != nil {
			t.Skipf("symlinks unavailable on this host: %v", err)
		}
		if err := l.syncStaticCache(context.Background(), limits, l.cache.scan(context.Background(), limits)); err == nil {
			t.Fatal("symlink accepted into snapshot")
		}
		if uploads.Load() != 2 {
			t.Fatal("invalid snapshot was uploaded")
		}
	})
}

func TestStaticCacheDoesNotFollowRedirects(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("site"), 0o600); err != nil {
		t.Fatal(err)
	}
	var foreignRequests atomic.Int32
	foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		foreignRequests.Add(1)
		utils.WriteAPIData(w, http.StatusOK, types.StaticCacheStatus{})
	}))
	defer foreign.Close()
	for _, method := range []string{http.MethodPost, http.MethodPut} {
		t.Run(method, func(t *testing.T) {
			relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == method {
					http.Redirect(w, r, foreign.URL, http.StatusFound)
					return
				}
				utils.WriteAPIData(w, http.StatusOK, types.StaticCacheStatus{})
			}))
			defer relay.Close()
			relayURL, _ := url.Parse(relay.URL)
			l := &listener{
				api:   &apiClient{relayURL: relayURL, http: relay.Client()},
				cache: newStaticCacheSource(staticCacheConfig{root: root, index: "index.html"}),
				lease: utils.NewSnapshot(listenerSnapshot{accessToken: "lease-token"}, listenerSnapshot.snapshot),
			}
			if err := l.syncStaticCache(context.Background(), types.StaticCacheLimits{MaxExposureBytes: 1024, MaxObjectSize: 512}, l.cache.scan(context.Background(), types.StaticCacheLimits{MaxExposureBytes: 1024, MaxObjectSize: 512})); err == nil {
				t.Fatal("redirect accepted as a successful cache operation")
			}
			if foreignRequests.Load() != 0 {
				t.Fatal("cache request reached an endpoint other than the configured relay")
			}
		})
	}
}
