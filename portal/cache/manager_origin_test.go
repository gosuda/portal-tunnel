package cache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
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

func TestFallbackReleasesSnapshotAndDiskFailureRequestsReupload(t *testing.T) {
	for _, failure := range []string{"method", "missing", "truncated"} {
		t.Run(failure, func(t *testing.T) {
			c := testManager(t, 16)
			l := testLease(c, "site")
			site := seedCacheSnapshot(t, c, l)
			method := corruptCacheSnapshot(t, failure, site)
			if c.Serve(httptest.NewRecorder(), httptest.NewRequest(method, "https://"+l.Hostname+"/", nil), l.Hostname) {
				t.Fatal("request did not fall back")
			}
			if site.readers != 0 {
				t.Fatal("origin fallback retained a disk pin")
			}
			if failure != "method" {
				checkBrokenSnapshotReupload(t, c, l)
			}
			checkFallbackUnblocksEviction(t, c)
		})
	}
}

func seedCacheSnapshot(t *testing.T, c *Manager, l Lease) *cachedSite {
	t.Helper()
	w := httptest.NewRecorder()
	c.Handle(w, testRequest(t, http.MethodPut, "site"), l.ID, c.Generation(l.ID))
	if w.Code != http.StatusOK {
		t.Fatal(w.Body.String())
	}
	for _, name := range []string{"second", "third", "fourth"} {
		other := testLease(c, name)
		fill := httptest.NewRecorder()
		c.Handle(fill, testRequest(t, http.MethodPut, "fill"), other.ID, c.Generation(other.ID))
		if fill.Code != http.StatusOK {
			t.Fatal(fill.Body.String())
		}
	}
	return c.entries[l.Hostname]
}

func corruptCacheSnapshot(t *testing.T, failure string, site *cachedSite) string {
	t.Helper()
	if failure == "method" {
		return http.MethodPost
	}
	path := filepath.Join(site.dir, site.files[site.index].SHA256)
	if failure == "missing" {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	} else if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	return http.MethodGet
}

func checkBrokenSnapshotReupload(t *testing.T, c *Manager, l Lease) {
	t.Helper()
	w := httptest.NewRecorder()
	c.Handle(w, testRequest(t, http.MethodPost, "site"), l.ID, c.Generation(l.ID))
	var response struct {
		Data types.StaticCacheStatus `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Data.Present || c.Has(l.Hostname) {
		t.Fatal("broken snapshot still reported present")
	}
	w = httptest.NewRecorder()
	c.Handle(w, testRequest(t, http.MethodPut, "site"), l.ID, c.Generation(l.ID))
	if w.Code != http.StatusOK || !c.Has(l.Hostname) {
		t.Fatalf("snapshot did not recover: %d %s", w.Code, w.Body.String())
	}
}

func checkFallbackUnblocksEviction(t *testing.T, c *Manager) {
	t.Helper()
	other := testLease(c, "other")
	w := httptest.NewRecorder()
	c.Handle(w, testRequest(t, http.MethodPut, "next"), other.ID, c.Generation(other.ID))
	if w.Code != http.StatusOK {
		t.Fatalf("fallback blocked eviction: %s", w.Body.String())
	}
}

type failingDiskResponse struct {
	*httptest.ResponseRecorder
	truncate func()
}

func (w *failingDiskResponse) WriteHeader(code int) {
	w.truncate()
	w.ResponseRecorder.WriteHeader(code)
}

func TestReadFailureAfterHeadersInvalidatesSnapshot(t *testing.T) {
	c := testManager(t, 16)
	l := testLease(c, "site")
	w := httptest.NewRecorder()
	c.Handle(w, testRequest(t, http.MethodPut, "site"), l.ID, c.Generation(l.ID))
	if w.Code != http.StatusOK {
		t.Fatal(w.Body.String())
	}
	site := c.entries[l.Hostname]
	path := filepath.Join(site.dir, site.files[site.index].SHA256)
	response := &failingDiskResponse{ResponseRecorder: httptest.NewRecorder(), truncate: func() {
		if err := os.Truncate(path, 0); err != nil {
			t.Fatal(err)
		}
	}}
	if !c.Serve(response, httptest.NewRequest(http.MethodGet, "https://"+l.Hostname+"/", nil), l.Hostname) {
		t.Fatal("response unexpectedly fell back before sending headers")
	}
	if c.Has(l.Hostname) || site.readers != 0 {
		t.Fatal("failed response retained a valid or pinned snapshot")
	}
}

func TestStaticCacheDoesNotFollowRedirects(t *testing.T) {
	root, content, hash := storeRedirectFixture(t)
	foreign, foreignRequests := startForeignOriginServer(t)
	defer foreign.Close()
	relay := startRedirectRelay(t, foreign)
	defer relay.Close()
	checkRedirectSyncRejected(t, root, content, hash, relay)
	checkForeignOriginIdle(t, foreignRequests)
}

func storeRedirectFixture(t *testing.T) (string, []byte, string) {
	t.Helper()
	root := t.TempDir()
	content := []byte("site")
	if err := os.WriteFile(filepath.Join(root, "index.html"), content, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	return root, content, hex.EncodeToString(sum[:])
}

func startForeignOriginServer(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var foreignRequests atomic.Int32
	foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		foreignRequests.Add(1)
		utils.WriteAPIData(w, http.StatusOK, types.StaticCacheStatus{})
	}))
	return foreign, &foreignRequests
}

func startRedirectRelay(t *testing.T, foreign *httptest.Server) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, foreign.URL, http.StatusFound)
	}))
}

func checkRedirectSyncRejected(t *testing.T, root string, content []byte, hash string, relay *httptest.Server) {
	t.Helper()
	relayURL, err := url.Parse(relay.URL)
	if err != nil {
		t.Fatal(err)
	}
	source, err := NewSource(SourceConfig{Path: root})
	if err != nil {
		t.Fatal(err)
	}
	syncer := &Syncer{
		source:   source,
		relayURL: *relayURL,
		limits:   types.StaticCacheLimits{MaxExposureBytes: 1024, MaxObjectSize: 512},
		snapshot: stageStaticSnapshot(root, hash, content),
	}
	if err := syncer.Sync(context.Background(), relay.Client(), "lease-token"); err == nil {
		t.Fatal("redirect accepted as a successful cache sync")
	}
}

func checkForeignOriginIdle(t *testing.T, foreignRequests *atomic.Int32) {
	t.Helper()
	if foreignRequests.Load() != 0 {
		t.Fatalf("foreign server received %d requests, want 0 (redirect was followed)", foreignRequests.Load())
	}
}

func TestStaticCacheRetriesTransientAdmissionErrorsWithoutDelete(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodPut} {
		for _, status := range []int{http.StatusTooManyRequests, http.StatusServiceUnavailable} {
			t.Run(method+"/"+http.StatusText(status), func(t *testing.T) {
				probe, ctx := startTransientAdmissionProbe(t, method, status)
				defer probe.stop()
				probe.checkFirstSyncFails(t, ctx)
				probe.checkRetrySucceeds(t, ctx)
			})
		}
	}
}

type transientAdmissionProbe struct {
	method          string
	status          int
	content         []byte
	hash            string
	relay           *httptest.Server
	syncer          *Syncer
	cancel          context.CancelFunc
	deleteCalls     atomic.Int32
	admissionStatus atomic.Int32
	rejected        atomic.Int32
	uploads         atomic.Int32
}

func startTransientAdmissionProbe(t *testing.T, method string, status int) (*transientAdmissionProbe, context.Context) {
	t.Helper()
	probe := &transientAdmissionProbe{method: method, status: status, content: []byte("site")}
	sum := sha256.Sum256(probe.content)
	probe.hash = hex.EncodeToString(sum[:])
	probe.admissionStatus.Store(int32(status))
	root := storeTransientFixture(t, probe)
	attachTransientRelay(t, probe, root)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	probe.cancel = cancel
	return probe, ctx
}

func storeTransientFixture(t *testing.T, probe *transientAdmissionProbe) string {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "index.html"), probe.content, 0o600); err != nil {
		t.Fatal(err)
	}
	return root
}

func attachTransientRelay(t *testing.T, probe *transientAdmissionProbe, root string) {
	t.Helper()
	probe.relay = httptest.NewServer(probe.handler(t))
	defer func() {
		if probe.syncer == nil {
			probe.relay.Close()
		}
	}()
	relayURL, err := url.Parse(probe.relay.URL)
	if err != nil {
		t.Fatal(err)
	}
	source, err := NewSource(SourceConfig{Path: root})
	if err != nil {
		t.Fatal(err)
	}
	source.mu.Lock()
	source.snapshot = stageStaticSnapshot(root, probe.hash, probe.content)
	source.mu.Unlock()
	probe.syncer = source.Subscribe(*relayURL, types.StaticCacheLimits{MaxExposureBytes: 1024, MaxObjectSize: 512})
}

func stageStaticSnapshot(root, hash string, content []byte) *sourceSnapshot {
	return &sourceSnapshot{
		root: root,
		manifest: types.StaticCacheManifest{
			Index: "index.html",
			Files: []types.StaticCacheFile{{Path: "index.html", Size: int64(len(content)), SHA256: hash}},
		},
	}
}

func (probe *transientAdmissionProbe) stop() {
	probe.cancel()
	probe.syncer.Close()
	probe.relay.Close()
}

func (probe *transientAdmissionProbe) checkFirstSyncFails(t *testing.T, ctx context.Context) {
	t.Helper()
	if !probe.syncer.Next(ctx) {
		t.Fatal("Next() = false, want initial snapshot ready")
	}
	err := probe.syncer.Sync(ctx, probe.relay.Client(), "lease-token")
	var apiErr *types.APIRequestError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != probe.status {
		t.Fatalf("Sync() error = %v, want HTTP %d", err, probe.status)
	}
	if probe.rejected.Load() == 0 {
		t.Fatalf("%s admission failure was not exercised", probe.method)
	}
	if probe.deleteCalls.Load() != 0 {
		t.Fatalf("DELETE called %d times on transient error, want 0", probe.deleteCalls.Load())
	}
}

func (probe *transientAdmissionProbe) checkRetrySucceeds(t *testing.T, ctx context.Context) {
	t.Helper()
	if !probe.syncer.Next(ctx) {
		t.Fatal("Next() after transient failure = false, want same snapshot retried")
	}
	probe.admissionStatus.Store(http.StatusOK)
	if err := probe.syncer.Sync(ctx, probe.relay.Client(), "lease-token"); err != nil {
		t.Fatalf("Sync() retry error = %v, want success", err)
	}
	if probe.uploads.Load() == 0 {
		t.Fatal("retry did not upload the selected generation")
	}
	if probe.deleteCalls.Load() != 0 {
		t.Fatal("retry deleted cached content")
	}
}

func (probe *transientAdmissionProbe) handler(t *testing.T) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodDelete:
			probe.deleteCalls.Add(1)
			w.WriteHeader(http.StatusNoContent)
		case http.MethodPost:
			probe.servePostAdmissionCheck(t, w, r)
		case http.MethodPut:
			probe.servePutAdmissionCheck(t, w, r)
		default:
			http.NotFound(w, r)
		}
	}
}

func (probe *transientAdmissionProbe) servePostAdmissionCheck(t *testing.T, w http.ResponseWriter, r *http.Request) {
	t.Helper()
	var manifest types.StaticCacheManifest
	if err := json.NewDecoder(r.Body).Decode(&manifest); err != nil {
		t.Errorf("decode manifest: %v", err)
		http.Error(w, "invalid manifest", http.StatusBadRequest)
		return
	}
	if len(manifest.Files) != 1 || manifest.Files[0].SHA256 != probe.hash {
		t.Errorf("manifest = %+v, want unchanged generation", manifest)
		http.Error(w, "changed manifest", http.StatusBadRequest)
		return
	}
	if probe.method == http.MethodPost && probe.admissionStatus.Load() != http.StatusOK {
		probe.rejected.Add(1)
		http.Error(w, "admission unavailable", int(probe.admissionStatus.Load()))
		return
	}
	utils.WriteAPIData(w, http.StatusOK, types.StaticCacheStatus{Present: false})
}

func (probe *transientAdmissionProbe) servePutAdmissionCheck(t *testing.T, w http.ResponseWriter, r *http.Request) {
	t.Helper()
	if probe.method == http.MethodPut && probe.admissionStatus.Load() != http.StatusOK {
		probe.rejected.Add(1)
		http.Error(w, "admission unavailable", int(probe.admissionStatus.Load()))
		return
	}
	if err := r.ParseMultipartForm(1024); err != nil {
		t.Errorf("parse upload: %v", err)
		http.Error(w, "invalid upload", http.StatusBadRequest)
		return
	}
	defer r.MultipartForm.RemoveAll()
	objects := r.MultipartForm.Value["object"]
	if len(objects) != 1 || objects[0] != string(probe.content) {
		t.Errorf("uploaded objects = %q, want original content", objects)
		http.Error(w, "changed content", http.StatusBadRequest)
		return
	}
	probe.uploads.Add(1)
	utils.WriteAPIData(w, http.StatusOK, types.StaticCacheStatus{Present: true})
}
