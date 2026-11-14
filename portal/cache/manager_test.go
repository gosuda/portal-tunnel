package cache

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func testManager(t *testing.T, budget int) *Manager {
	t.Helper()
	c, err := New(Config{Enabled: true, MaxBytes: budget, MaxTTL: time.Minute}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func testLease(c *Manager, name string) Lease {
	l := Lease{ID: name + "-id", Owner: types.NewServiceIdentityKey(name, "0x1"), Hostname: name + ".localhost", ExpiresAt: time.Now().Add(24 * time.Hour), LastSeenAt: time.Now()}
	c.Register(l, types.RegisterChallengeRequest{Cache: true, CacheTTL: 86400})
	return l
}

func testRequest(t *testing.T, method, content string) *http.Request {
	t.Helper()
	digest := sha256.Sum256([]byte(content))
	manifest := types.StaticCacheManifest{Index: "index.html", Files: []types.StaticCacheFile{{Path: "index.html", Size: int64(len(content)), SHA256: hex.EncodeToString(digest[:])}}}
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if method == http.MethodPost {
		return httptest.NewRequest(method, types.PathSDKCache, bytes.NewReader(raw))
	}
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormField("manifest")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = part.Write(raw)
	part, err = writer.CreateFormField("object")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(part, content)
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(method, types.PathSDKCache, &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	return req
}

func TestNewRejectsEmptyDirectoryWithoutFilesystemChanges(t *testing.T) {
	t.Chdir(t.TempDir())
	untouched := filepath.Join("static-cache", "portal-cache-existing", "keep")
	if err := os.MkdirAll(filepath.Dir(untouched), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(untouched, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{"", " \t"} {
		manager, err := New(Config{Enabled: true, MaxBytes: 32, MaxTTL: time.Minute}, dir)
		if err == nil || manager != nil {
			t.Fatalf("enabled cache accepted empty directory %q", dir)
		}
	}
	if manager, err := New(Config{}, ""); err != nil || manager != nil {
		t.Fatalf("disabled cache requires storage: %v", err)
	}
	if content, err := os.ReadFile(untouched); err != nil || string(content) != "existing" {
		t.Fatalf("empty directory modified working-directory files: %q, %v", content, err)
	}
}

func TestLeaseEventsBoundOfflineLifetime(t *testing.T) {
	c := testManager(t, 32)
	l := testLease(c, "site")
	site := seedOfflineLifetimeSite(t, c, l)
	l, ceiling := detachOfflineSiteAtCeiling(t, c, l, site)
	expireOfflineCache(t, c, site, ceiling)
	rejectLateOfflineRenewal(t, c, l)
}

func seedOfflineLifetimeSite(t *testing.T, c *Manager, l Lease) *cachedSite {
	t.Helper()
	w := httptest.NewRecorder()
	c.Handle(w, testRequest(t, http.MethodPut, "site"), l.ID, c.Generation(l.ID))
	if w.Code != http.StatusOK {
		t.Fatal(w.Body.String())
	}
	site := c.entries[l.Hostname]
	if site.expiresAt != l.LastSeenAt.Add(observationWindow+c.cfg.MaxTTL) {
		t.Fatal("long lease bypassed offline ceiling")
	}
	return site
}

func detachOfflineSiteAtCeiling(t *testing.T, c *Manager, l Lease, site *cachedSite) (Lease, time.Time) {
	t.Helper()
	l.LastSeenAt = time.Now().Add(-observationWindow - 10*time.Second)
	c.Renew(l)
	ceiling := site.expiresAt
	c.Detach(l)
	if site.expiresAt.After(ceiling) || !c.Has(l.Hostname) {
		t.Fatal("detach extended expiry or discarded still-live offline content")
	}
	return l, ceiling
}

func expireOfflineCache(t *testing.T, c *Manager, site *cachedSite, ceiling time.Time) {
	t.Helper()
	c.collect(ceiling.Add(time.Second))
	if _, err := os.Stat(site.dir); !os.IsNotExist(err) || c.used != 0 {
		t.Fatalf("expired cache persisted: %v", err)
	}
}

func rejectLateOfflineRenewal(t *testing.T, c *Manager, l Lease) {
	t.Helper()
	c.Renew(l)
	if c.Has(l.Hostname) || c.Eligible(l.ID) {
		t.Fatal("late renewal resurrected detached cache lease")
	}
}

func TestFailedOldReaderDoesNotDiscardReplacement(t *testing.T) {
	c := testManager(t, 32)
	l := testLease(c, "site")
	w := httptest.NewRecorder()
	c.Handle(w, testRequest(t, http.MethodPut, "old"), l.ID, c.Generation(l.ID))
	old := c.acquire(l.Hostname)
	w = httptest.NewRecorder()
	c.Handle(w, testRequest(t, http.MethodPut, "new"), l.ID, c.Generation(l.ID))
	if w.Code != http.StatusOK {
		t.Fatal(w.Body.String())
	}
	c.discard(old)
	c.release(old)
	if !c.Has(l.Hostname) {
		t.Fatal("failed old reader discarded replacement")
	}
}

func TestDetachOwnerRejectsInFlightCacheRequests(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodPut} {
		t.Run(method, func(t *testing.T) {
			c := testManager(t, 128)
			lease := testLease(c, "site")
			resume, codes := startGatedCacheRequest(t, c, lease, method)
			code, fresh := detachOwnerMidRequest(t, c, lease, resume, codes)
			if method == http.MethodPut {
				fresh = recheckDetachedPutRetry(t, c, lease, code, fresh)
			}
			serveFreshAfterRevoke(t, c, lease, code, fresh)
		})
	}
}

func startGatedCacheRequest(t *testing.T, c *Manager, lease Lease, method string) (chan struct{}, chan int) {
	t.Helper()
	started := make(chan struct{})
	resume := make(chan struct{})
	req := testRequest(t, method, "old")
	req.Body = &gatedBody{ReadCloser: req.Body, started: started, resume: resume}
	codes := make(chan int, 1)
	generation := c.Generation(lease.ID)
	go func() {
		response := httptest.NewRecorder()
		c.Handle(response, req, lease.ID, generation)
		codes <- response.Code
	}()
	<-started
	return resume, codes
}

func detachOwnerMidRequest(t *testing.T, c *Manager, lease Lease, resume chan struct{}, codes chan int) (int, *httptest.ResponseRecorder) {
	t.Helper()
	c.DetachOwner(lease.Owner)
	fresh := httptest.NewRecorder()
	c.Handle(fresh, testRequest(t, http.MethodPut, "new"), lease.ID, c.Generation(lease.ID))
	close(resume)
	code := <-codes
	return code, fresh
}

func recheckDetachedPutRetry(t *testing.T, c *Manager, lease Lease, code int, fresh *httptest.ResponseRecorder) *httptest.ResponseRecorder {
	t.Helper()
	if code != http.StatusForbidden || fresh.Code != http.StatusServiceUnavailable || c.Has(lease.Hostname) {
		t.Fatalf("revoked PUT = %d, overlapping upload = %d, published = %v", code, fresh.Code, c.Has(lease.Hostname))
	}
	fresh = httptest.NewRecorder()
	c.Handle(fresh, testRequest(t, http.MethodPut, "new"), lease.ID, c.Generation(lease.ID))
	return fresh
}

func serveFreshAfterRevoke(t *testing.T, c *Manager, lease Lease, code int, fresh *httptest.ResponseRecorder) {
	t.Helper()
	if code != http.StatusForbidden || fresh.Code != http.StatusOK {
		t.Fatalf("old request = %d, fresh upload = %d", code, fresh.Code)
	}
	served := httptest.NewRecorder()
	if !c.Serve(served, httptest.NewRequest(http.MethodGet, "https://"+lease.Hostname+"/", nil), lease.Hostname) || served.Body.String() != "new" {
		t.Fatalf("old request changed fresh content: %q", served.Body.String())
	}
}

func TestCacheGenerationFencesDelayedAdmission(t *testing.T) {
	c := testManager(t, 32)
	lease := testLease(c, "site")
	generation := c.Generation(lease.ID)
	c.DetachOwner(lease.Owner)
	response := httptest.NewRecorder()
	c.Handle(response, testRequest(t, http.MethodPut, "old"), lease.ID, generation)
	if response.Code != http.StatusForbidden || c.Has(lease.Hostname) {
		t.Fatal("request admitted before revocation published afterward")
	}
}

func TestDetachOwnerSuppressesCacheRouting(t *testing.T) {
	c := testManager(t, 16)
	l := testLease(c, "site")
	w := httptest.NewRecorder()
	c.Handle(w, testRequest(t, http.MethodPut, "site"), l.ID, c.Generation(l.ID))
	if w.Code != http.StatusOK {
		t.Fatal(w.Body.String())
	}
	c.DetachOwner(l.Owner)
	if c.Has(l.Hostname) {
		t.Fatal("detached identity remained routable from cache")
	}
	if !c.Eligible(l.ID) {
		t.Fatal("detaching cached content removed the live cache lease")
	}
	if c.Serve(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "https://"+l.Hostname+"/", nil), l.Hostname) {
		t.Fatal("detached identity was still served from cache")
	}
}

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

func TestAdmissionPreservesTenantAndObjectBounds(t *testing.T) {
	c := testManager(t, 32)
	lease := testLease(c, "site")
	seedTenantBoundsUpload(t, c, lease)
	checkOverBudgetManifestRejected(t, c, lease)
	checkOversizedObjectRejected(t)
}

func seedTenantBoundsUpload(t *testing.T, c *Manager, lease Lease) {
	t.Helper()
	w := httptest.NewRecorder()
	c.Handle(w, testRequest(t, http.MethodPut, "12345678"), lease.ID, c.Generation(lease.ID))
	if w.Code != http.StatusOK {
		t.Fatal(w.Body.String())
	}
}

func checkOverBudgetManifestRejected(t *testing.T, c *Manager, lease Lease) {
	t.Helper()
	manifest := types.StaticCacheManifest{Index: "index.html", Files: []types.StaticCacheFile{
		{Path: "index.html", Size: 5, SHA256: strings.Repeat("a", 64)},
		{Path: "other.html", Size: 5, SHA256: strings.Repeat("b", 64)},
	}}
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	c.Handle(w, httptest.NewRequest(http.MethodPost, types.PathSDKCache, bytes.NewReader(raw)), lease.ID, c.Generation(lease.ID))
	if w.Code != http.StatusBadRequest || c.used != 8 || !c.Has(lease.Hostname) {
		t.Fatalf("over-budget exposure modified storage: %d, %d", w.Code, c.used)
	}
}

func checkOversizedObjectRejected(t *testing.T) {
	t.Helper()
	c := testManager(t, 1<<30)
	lease := testLease(c, "site")
	manifest := types.StaticCacheManifest{Index: "index.html", Files: []types.StaticCacheFile{
		{Path: "index.html", Size: (10 << 20) + 1, SHA256: strings.Repeat("a", 64)},
	}}
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	c.Handle(w, httptest.NewRequest(http.MethodPost, types.PathSDKCache, bytes.NewReader(raw)), lease.ID, c.Generation(lease.ID))
	if w.Code != http.StatusBadRequest || c.used != 0 {
		t.Fatalf("oversized object admitted: %d, %d", w.Code, c.used)
	}
}

func TestStorageBoundIncludesReadersAndStaging(t *testing.T) {
	c := testManager(t, 24)
	pinned := pinStorageBoundSites(t, c)
	defer func() {
		for _, site := range pinned[1:] {
			c.release(site)
		}
	}()
	next := testLease(c, "next")
	rejectStorageBoundWhenPinned(t, c, next)
	admitBoundUploadAfterRelease(t, c, pinned, next)
	checkStagedDiskBytes(t, c)
}

func pinStorageBoundSites(t *testing.T, c *Manager) []*cachedSite {
	t.Helper()
	var pinned []*cachedSite
	for _, name := range []string{"first", "second", "third", "fourth"} {
		lease := testLease(c, name)
		w := httptest.NewRecorder()
		c.Handle(w, testRequest(t, http.MethodPut, "123456"), lease.ID, c.Generation(lease.ID))
		if w.Code != http.StatusOK {
			t.Fatal(w.Body.String())
		}
		pinned = append(pinned, c.acquire(lease.Hostname))
	}
	return pinned
}

func rejectStorageBoundWhenPinned(t *testing.T, c *Manager, next Lease) {
	t.Helper()
	w := httptest.NewRecorder()
	c.Handle(w, testRequest(t, http.MethodPut, "new"), next.ID, c.Generation(next.ID))
	if w.Code != http.StatusServiceUnavailable || c.used != 24 {
		t.Fatalf("pinned bound: %d, %d", w.Code, c.used)
	}
}

func admitBoundUploadAfterRelease(t *testing.T, c *Manager, pinned []*cachedSite, next Lease) {
	t.Helper()
	c.release(pinned[0])
	w := httptest.NewRecorder()
	c.Handle(w, testRequest(t, http.MethodPut, "new"), next.ID, c.Generation(next.ID))
	if w.Code != http.StatusOK || c.used != 21 || c.snapshots != 4 {
		t.Fatalf("eviction: %d, %d", w.Code, c.used)
	}
}

func checkStagedDiskBytes(t *testing.T, c *Manager) {
	t.Helper()
	var diskBytes int64
	err := filepath.Walk(c.dir, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			diskBytes += info.Size()
		}
		return nil
	})
	if err != nil || diskBytes != 21 {
		t.Fatalf("disk bytes = %d, %v", diskBytes, err)
	}
}

func TestBoundsZeroByteStagingMetadata(t *testing.T) {
	c := testManager(t, 32)
	for range maxSnapshots {
		if err := c.reserve(0); err != nil {
			t.Fatal(err)
		}
	}
	if c.reserve(0) == nil {
		t.Fatal("zero-byte staging bypassed metadata bound")
	}
}

func TestFailedStagingReleasesCapacity(t *testing.T) {
	c := testManager(t, 16)
	l := testLease(c, "site")
	dir := c.dir
	blocked := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocked, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	c.dir = blocked
	w := httptest.NewRecorder()
	c.Handle(w, testRequest(t, http.MethodPut, "site"), l.ID, c.Generation(l.ID))
	if w.Code == http.StatusOK || c.used != 0 || c.snapshots != 0 {
		t.Fatal("failed staging accepted or retained a reservation")
	}
	c.dir = dir
	w = httptest.NewRecorder()
	c.Handle(w, testRequest(t, http.MethodPut, "site"), l.ID, c.Generation(l.ID))
	if w.Code != http.StatusOK {
		t.Fatalf("retry after failed staging: %d %s", w.Code, w.Body.String())
	}
}

func TestRejectsUnsafeAndOversizedManifest(t *testing.T) {
	c := testManager(t, 16)
	l := testLease(c, "site")
	for _, content := range []string{"12345", "123"} {
		req := testRequest(t, http.MethodPut, content)
		if len(content) == 3 {
			raw, _ := io.ReadAll(req.Body)
			req.Body = io.NopCloser(strings.NewReader(strings.ReplaceAll(string(raw), "index.html", "../index.html")))
		}
		w := httptest.NewRecorder()
		c.Handle(w, req, l.ID, c.Generation(l.ID))
		if w.Code != http.StatusBadRequest || c.used != 0 {
			t.Fatalf("invalid admission: %d, %d", w.Code, c.used)
		}
	}
}

type gatedBody struct {
	io.ReadCloser
	started chan struct{}
	resume  <-chan struct{}
}

func (r *gatedBody) Read(p []byte) (int, error) {
	if r.started != nil {
		close(r.started)
		r.started = nil
		<-r.resume
	}
	return r.ReadCloser.Read(p)
}

func TestAdmissionKeepsChecksAndUploadsIndependentlyBounded(t *testing.T) {
	c := testManager(t, 32)
	l := testLease(c, "site")
	other := testLease(c, "other")
	resume, workers := occupyCheckUploadSlots(t, c, l, other)
	defer func() { close(resume); workers.Wait() }()
	rejectCheckUploadWhenFull(t, c, l)
}

func occupyCheckUploadSlots(t *testing.T, c *Manager, l, other Lease) (chan struct{}, *sync.WaitGroup) {
	t.Helper()
	resume := make(chan struct{})
	var workers sync.WaitGroup
	for i, method := range []string{http.MethodPost, http.MethodPost, http.MethodPut, http.MethodPut} {
		lease := l
		if i == 3 {
			lease = other
		}
		started := make(chan struct{})
		req := testRequest(t, method, "site")
		req.Body = &gatedBody{ReadCloser: req.Body, started: started, resume: resume}
		workers.Add(1)
		go func() { defer workers.Done(); c.Handle(httptest.NewRecorder(), req, lease.ID, c.Generation(lease.ID)) }()
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			t.Fatalf("internal %s capacity was not available", method)
		}
	}
	return resume, &workers
}

func rejectCheckUploadWhenFull(t *testing.T, c *Manager, l Lease) {
	t.Helper()
	for _, method := range []string{http.MethodPost, http.MethodPut} {
		w := httptest.NewRecorder()
		c.Handle(w, testRequest(t, method, "site"), l.ID, c.Generation(l.ID))
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s exceeded its internal bound: %d", method, w.Code)
		}
	}
}

func TestUploadRequiresOptedInLease(t *testing.T) {
	c := testManager(t, 16)
	l := Lease{ID: "plain-id", Owner: types.NewServiceIdentityKey("plain", "0x1"), Hostname: "plain.localhost", ExpiresAt: time.Now().Add(24 * time.Hour), LastSeenAt: time.Now()}
	c.Register(l, types.RegisterChallengeRequest{Cache: false})
	w := httptest.NewRecorder()
	c.Handle(w, testRequest(t, http.MethodPut, "site"), l.ID, c.Generation(l.ID))
	if w.Code != http.StatusForbidden || c.Eligible(l.ID) || c.Has(l.Hostname) || c.used != 0 {
		t.Fatalf("non-opted-in lease admitted an upload: %d", w.Code)
	}
	w = httptest.NewRecorder()
	c.Handle(w, testRequest(t, http.MethodPut, "site"), "unknown-id", c.Generation("unknown-id"))
	if w.Code != http.StatusForbidden || c.used != 0 {
		t.Fatalf("unknown lease admitted an upload: %d", w.Code)
	}
}

func TestObjectDigestMismatchRejectsUpload(t *testing.T) {
	c := testManager(t, 16)
	l := testLease(c, "site")
	req := testRequest(t, http.MethodPut, "site")
	raw, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatal(err)
	}
	req.Body = io.NopCloser(strings.NewReader(strings.Replace(string(raw), "site", "sita", 1)))
	w := httptest.NewRecorder()
	c.Handle(w, req, l.ID, c.Generation(l.ID))
	if w.Code != http.StatusBadRequest || c.Has(l.Hostname) || c.used != 0 {
		t.Fatalf("corrupt object admitted: %d, %d", w.Code, c.used)
	}
}

func TestLeaseReplacementRejectsInFlightUpload(t *testing.T) {
	c := testManager(t, 32)
	first := Lease{ID: "first-id", Owner: types.NewServiceIdentityKey("site", "0x1"), Hostname: "first.localhost", ExpiresAt: time.Now().Add(24 * time.Hour), LastSeenAt: time.Now()}
	c.Register(first, types.RegisterChallengeRequest{Cache: true, CacheTTL: 86400})
	resume, codes := startGatedReplacementUpload(t, c, first)
	replacement := checkReplacementUploadRejected(t, c, resume, codes, first)
	publishReplacementUpload(t, c, replacement)
}

func startGatedReplacementUpload(t *testing.T, c *Manager, first Lease) (chan struct{}, chan int) {
	t.Helper()
	started := make(chan struct{})
	resume := make(chan struct{})
	req := testRequest(t, http.MethodPut, "site")
	req.Body = &gatedBody{ReadCloser: req.Body, started: started, resume: resume}
	codes := make(chan int, 1)
	go func() {
		w := httptest.NewRecorder()
		c.Handle(w, req, first.ID, c.Generation(first.ID))
		codes <- w.Code
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("upload never started reading its body")
	}
	return resume, codes
}

func checkReplacementUploadRejected(t *testing.T, c *Manager, resume chan struct{}, codes chan int, first Lease) Lease {
	t.Helper()
	replacement := Lease{ID: "second-id", Owner: types.NewServiceIdentityKey("site", "0x1"), Hostname: "second.localhost", ExpiresAt: time.Now().Add(24 * time.Hour), LastSeenAt: time.Now()}
	c.Register(replacement, types.RegisterChallengeRequest{Cache: true, CacheTTL: 86400})
	close(resume)
	var code int
	select {
	case code = <-codes:
	case <-time.After(5 * time.Second):
		t.Fatal("replaced upload never completed")
	}
	if code != http.StatusForbidden || c.Eligible(first.ID) || c.Has(first.Hostname) {
		t.Fatalf("replaced lease published an in-flight upload: %d", code)
	}
	if !c.Eligible(replacement.ID) {
		t.Fatal("replacement lease lost upload eligibility")
	}
	return replacement
}

func publishReplacementUpload(t *testing.T, c *Manager, replacement Lease) {
	t.Helper()
	w := httptest.NewRecorder()
	c.Handle(w, testRequest(t, http.MethodPut, "site"), replacement.ID, c.Generation(replacement.ID))
	if w.Code != http.StatusOK || !c.Has(replacement.Hostname) {
		t.Fatalf("replacement lease could not publish: %d %s", w.Code, w.Body.String())
	}
}

func TestUploadAdmissionIsolatesServiceIdentities(t *testing.T) {
	c := testManager(t, 64)
	first := testLease(c, "first")
	other := testLease(c, "other")
	resume, done := startGatedUpload(t, c, first, "first")
	defer func() {
		close(resume)
		if code := <-done; code != http.StatusOK {
			t.Errorf("first upload = %d, want 200", code)
		}
	}()
	checkUploadSlotIsolation(t, c, first, other)
}

func startGatedUpload(t *testing.T, c *Manager, lease Lease, content string) (chan struct{}, <-chan int) {
	t.Helper()
	started := make(chan struct{})
	resume := make(chan struct{})
	done := make(chan int, 1)
	req := testRequest(t, http.MethodPut, content)
	req.Body = &gatedBody{ReadCloser: req.Body, started: started, resume: resume}
	go func() {
		w := httptest.NewRecorder()
		c.Handle(w, req, lease.ID, c.Generation(lease.ID))
		done <- w.Code
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("first upload did not start")
	}
	return resume, done
}

func checkUploadSlotIsolation(t *testing.T, c *Manager, first, other Lease) {
	t.Helper()
	duplicate := httptest.NewRecorder()
	c.Handle(duplicate, testRequest(t, http.MethodPut, "duplicate"), first.ID, c.Generation(first.ID))
	if duplicate.Code != http.StatusServiceUnavailable {
		t.Fatalf("duplicate upload = %d, want 503", duplicate.Code)
	}
	second := httptest.NewRecorder()
	c.Handle(second, testRequest(t, http.MethodPut, "other"), other.ID, c.Generation(other.ID))
	if second.Code != http.StatusOK {
		t.Fatalf("another service could not use the remaining slot: %d", second.Code)
	}
	bad := httptest.NewRequest(http.MethodPut, types.PathSDKCache, strings.NewReader("invalid"))
	invalid := httptest.NewRecorder()
	c.Handle(invalid, bad, other.ID, c.Generation(other.ID))
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("malformed upload = %d, want 400", invalid.Code)
	}
	retry := httptest.NewRecorder()
	c.Handle(retry, testRequest(t, http.MethodPut, "retry"), other.ID, c.Generation(other.ID))
	if retry.Code != http.StatusOK {
		t.Fatalf("failed upload retained admission: %d", retry.Code)
	}
}

func TestChangedManifestFallsBackAcrossRejectedUploadAndRenewal(t *testing.T) {
	c := testManager(t, 64)
	lease := testLease(c, "site")
	seedCacheUploadOK(t, c, lease, "old")
	resume, workers := occupyUploadSlots(t, c, "first", "second")
	defer func() {
		if resume != nil {
			close(resume)
		}
		workers.Wait()
	}()
	lease = checkSupersededSnapshotFallsBack(t, c, lease)
	close(resume)
	resume = nil
	workers.Wait()
	checkReplacementPublishServesNew(t, c, lease)
}

func seedCacheUploadOK(t *testing.T, c *Manager, lease Lease, content string) {
	t.Helper()
	w := httptest.NewRecorder()
	c.Handle(w, testRequest(t, http.MethodPut, content), lease.ID, c.Generation(lease.ID))
	if w.Code != http.StatusOK {
		t.Fatal(w.Body.String())
	}
}

func occupyUploadSlots(t *testing.T, c *Manager, names ...string) (chan struct{}, *sync.WaitGroup) {
	t.Helper()
	resume := make(chan struct{})
	var workers sync.WaitGroup
	for _, name := range names {
		other := testLease(c, name)
		started := make(chan struct{})
		req := testRequest(t, http.MethodPut, name)
		req.Body = &gatedBody{ReadCloser: req.Body, started: started, resume: resume}
		workers.Add(1)
		go func() {
			defer workers.Done()
			c.Handle(httptest.NewRecorder(), req, other.ID, c.Generation(other.ID))
		}()
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			t.Fatal("occupying upload did not start")
		}
	}
	return resume, &workers
}

func checkSupersededSnapshotFallsBack(t *testing.T, c *Manager, lease Lease) Lease {
	t.Helper()
	presence := httptest.NewRecorder()
	c.Handle(presence, testRequest(t, http.MethodPost, "new"), lease.ID, c.Generation(lease.ID))
	if presence.Code != http.StatusOK {
		t.Fatal(presence.Body.String())
	}
	rejected := httptest.NewRecorder()
	c.Handle(rejected, testRequest(t, http.MethodPut, "new"), lease.ID, c.Generation(lease.ID))
	if rejected.Code != http.StatusServiceUnavailable {
		t.Fatalf("upload at capacity = %d, want 503", rejected.Code)
	}
	lease.LastSeenAt = time.Now().Add(time.Minute)
	c.Renew(lease)
	if c.Serve(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "https://"+lease.Hostname+"/", nil), lease.Hostname) {
		t.Fatal("renewal served a known superseded snapshot after rejected replacement")
	}
	return lease
}

func checkReplacementPublishServesNew(t *testing.T, c *Manager, lease Lease) {
	t.Helper()
	w := httptest.NewRecorder()
	c.Handle(w, testRequest(t, http.MethodPut, "new"), lease.ID, c.Generation(lease.ID))
	if w.Code != http.StatusOK {
		t.Fatalf("replacement after capacity recovered = %d, want 200", w.Code)
	}
	served := httptest.NewRecorder()
	if !c.Serve(served, httptest.NewRequest(http.MethodGet, "https://"+lease.Hostname+"/", nil), lease.Hostname) || served.Body.String() != "new" {
		t.Fatalf("replacement content = %q, want new", served.Body.String())
	}
}

func TestReserveKeepsPinnedReadersRouted(t *testing.T) {
	c := testManager(t, 24)
	pinned, hosts := pinReserveRoutedSites(t, c)
	defer func() {
		for _, site := range pinned {
			c.release(site)
		}
	}()
	next := testLease(c, "next")
	rejectReserveOverBudget(t, c, next)
	checkReserveRoutingKept(t, c, hosts)
}

func pinReserveRoutedSites(t *testing.T, c *Manager) ([]*cachedSite, []string) {
	t.Helper()
	var pinned []*cachedSite
	var hosts []string
	for _, name := range []string{"first", "second", "third", "fourth"} {
		lease := testLease(c, name)
		w := httptest.NewRecorder()
		c.Handle(w, testRequest(t, http.MethodPut, "123456"), lease.ID, c.Generation(lease.ID))
		if w.Code != http.StatusOK {
			t.Fatal(w.Body.String())
		}
		pinned = append(pinned, c.acquire(lease.Hostname))
		hosts = append(hosts, lease.Hostname)
	}
	return pinned, hosts
}

func rejectReserveOverBudget(t *testing.T, c *Manager, next Lease) {
	t.Helper()
	w := httptest.NewRecorder()
	c.Handle(w, testRequest(t, http.MethodPut, "new"), next.ID, c.Generation(next.ID))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("over-budget upload admitted with pinned readers: %d", w.Code)
	}
}

func checkReserveRoutingKept(t *testing.T, c *Manager, hosts []string) {
	t.Helper()
	for _, host := range hosts {
		if !c.Has(host) {
			t.Fatalf("pinned snapshot %q lost routing under admission pressure", host)
		}
	}
}
