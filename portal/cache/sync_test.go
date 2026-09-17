package cache

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

// TestStaticCacheRefreshUsesContentDigest verifies that a syncer uploads a snapshot only
// when its content digest differs from the one the relay last accepted, and that
// symlinks in the static tree are rejected from the snapshot.

func TestStaticCacheRefreshUsesContentDigest(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	var uploads atomic.Int32
	var expectedToken atomic.Value
	expectedToken.Store("lease-token")
	accessToken := "lease-token"
	var cachedDigest string
	limits := types.StaticCacheLimits{MaxExposureBytes: 1024, MaxObjectSize: 512}
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(types.HeaderAccessToken) != expectedToken.Load().(string) || r.URL.Path != types.PathSDKCache {
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
	syncer := source.Subscribe(*relayURL, limits)
	defer syncer.Close()
	for range 2 {
		syncer.snapshot = source.scan(context.Background(), limits)
		if err := syncer.Sync(context.Background(), relay.Client(), accessToken); err != nil {
			t.Fatal(err)
		}
	}
	if uploads.Load() != 1 {
		t.Fatalf("unchanged snapshot uploaded %d times", uploads.Load())
	}
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("second"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A later generation uses credentials renewed by the SDK, without keeping
	// an old lease token in the cache subscription.
	accessToken = "renewed-token"
	expectedToken.Store(accessToken)
	syncer.snapshot = source.scan(context.Background(), limits)
	if err := syncer.Sync(context.Background(), relay.Client(), accessToken); err != nil {
		t.Fatal(err)
	}
	if uploads.Load() != 2 {
		t.Fatal("changed snapshot was not uploaded")
	}
	t.Run("symlink rejection", func(t *testing.T) {
		if err := os.Symlink(filepath.Join(root, "index.html"), filepath.Join(root, "link.html")); err != nil {
			t.Skipf("symlinks unavailable on this host: %v", err)
		}
		syncer.snapshot = source.scan(context.Background(), limits)
		if err := syncer.Sync(context.Background(), relay.Client(), accessToken); err == nil {
			t.Fatal("symlink accepted into snapshot")
		}
		if uploads.Load() != 2 {
			t.Fatal("invalid snapshot was uploaded")
		}
	})
}

// TestStaticCacheDoesNotFollowRedirects verifies that cache POST, PUT, and DELETE
// operations fail if the relay responds with a redirect, preventing a lease token
// from being forwarded to an unintended host.

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
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
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
			syncer := source.Subscribe(*relayURL, limits)
			defer syncer.Close()
			syncer.snapshot = source.scan(context.Background(), limits)
			if method == http.MethodDelete {
				// A failed local generation must invalidate the previous relay
				// snapshot without following a redirect carrying its lease token.
				syncer.snapshot.err = errors.New("source unavailable")
			}
			if err := syncer.Sync(context.Background(), relay.Client(), "lease-token"); err == nil {
				t.Fatal("redirect accepted as a successful cache operation")
			}
			if redirected.Load() != 1 || foreignRequests.Load() != 0 {
				t.Fatalf("redirect requests: configured=%d foreign=%d", redirected.Load(), foreignRequests.Load())
			}
		})
	}
}
