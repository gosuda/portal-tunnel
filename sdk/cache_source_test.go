package sdk

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
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func TestStaticCacheSourceSharesGenerationAcrossRelays(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "index.html")
	if err := os.WriteFile(path, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	source := newStaticCacheSource(staticCacheConfig{root: root, index: "index.html"})
	ctx, cancel := context.WithCancel(context.Background())
	go source.run(ctx)
	t.Cleanup(func() { cancel(); <-source.done })
	limits := types.StaticCacheLimits{MaxExposureBytes: 1024, MaxObjectSize: 512}
	source.subscribe("first-relay", &limits)
	var snapshot *staticSnapshot
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for {
		current, changed := source.current()
		if current != nil {
			snapshot = current
			break
		}
		select {
		case <-changed:
		case <-deadline.C:
			t.Fatal("shared source did not publish")
		}
	}
	if snapshot.err != nil {
		t.Fatal(snapshot.err)
	}
	// A relay joining between builds must use the exposure's current manifest;
	// transport synchronization does not independently rediscover the directory.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	source.subscribe("second-relay", &limits)
	want := sha256.Sum256([]byte("first"))
	for _, name := range []string{"first-relay", "second-relay"} {
		t.Run(name, func(t *testing.T) {
			relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
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
			l := &listener{api: &apiClient{relayURL: relayURL, http: relay.Client()}, cache: source, lease: utils.NewSnapshot(listenerSnapshot{accessToken: "lease-token"}, listenerSnapshot.snapshot)}
			current, _ := source.current()
			if err := l.syncStaticCache(ctx, limits, current); err != nil {
				t.Fatal(err)
			}
			if err := l.syncStaticCache(ctx, types.StaticCacheLimits{MaxExposureBytes: 4, MaxObjectSize: 4}, current); err == nil {
				t.Fatal("shared snapshot bypassed this relay's smaller limits")
			}
		})
	}
	// Rebuilding the source reports the missing entry; a previous immutable
	// generation is unaffected and consumers can invalidate their old snapshots.
	failed := source.scan(ctx, limits)
	if failed.err == nil || snapshot.err != nil || len(snapshot.manifest.Files) != 1 {
		t.Fatal("source rebuild lost generation isolation")
	}
}
