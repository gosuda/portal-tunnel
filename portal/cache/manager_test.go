package cache

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/policy"
	"github.com/gosuda/portal-tunnel/v2/types"
)

func testManager(t *testing.T, budget int) *Manager {
	t.Helper()
	policy, err := policy.NewRuntime(false, false, false, "")
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(Config{Enabled: true, MaxBytes: budget, MaxTTL: time.Minute}, t.TempDir(), policy)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func testLease(c *Manager, name string) Lease {
	l := Lease{ID: name + "-id", Owner: name, Hostname: name + ".localhost", ExpiresAt: time.Now().Add(24 * time.Hour), LastSeenAt: time.Now()}
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
	runtime, err := policy.NewRuntime(false, false, false, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{"", " \t"} {
		manager, err := New(Config{Enabled: true, MaxBytes: 32, MaxTTL: time.Minute}, dir, runtime)
		if err == nil || manager != nil {
			t.Fatalf("enabled cache accepted empty directory %q", dir)
		}
	}
	if manager, err := New(Config{}, "", runtime); err != nil || manager != nil {
		t.Fatalf("disabled cache requires storage: %v", err)
	}
	if content, err := os.ReadFile(untouched); err != nil || string(content) != "existing" {
		t.Fatalf("empty directory modified working-directory files: %q, %v", content, err)
	}
}

func TestAdmissionPreservesTenantAndObjectBounds(t *testing.T) {
	c := testManager(t, 32)
	lease := testLease(c, "site")
	w := httptest.NewRecorder()
	c.Handle(w, testRequest(t, http.MethodPut, "12345678"), lease.ID)
	if w.Code != http.StatusOK {
		t.Fatal(w.Body.String())
	}
	// Each object fits, but their sum exceeds this exposure's share while
	// remaining well below the relay's total budget.
	manifest := types.StaticCacheManifest{Index: "index.html", Files: []types.StaticCacheFile{
		{Path: "index.html", Size: 5, SHA256: strings.Repeat("a", 64)},
		{Path: "other.html", Size: 5, SHA256: strings.Repeat("b", 64)},
	}}
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	c.Handle(w, httptest.NewRequest(http.MethodPost, types.PathSDKCache, bytes.NewReader(raw)), lease.ID)
	if w.Code != http.StatusBadRequest || c.used != 8 || !c.Has(lease.Hostname) {
		t.Fatalf("over-budget exposure modified storage: %d, %d", w.Code, c.used)
	}

	// A large total budget must still reject oversized individual objects.
	c = testManager(t, 1<<30)
	lease = testLease(c, "site")
	manifest.Files = manifest.Files[:1]
	manifest.Files[0].Size = (10 << 20) + 1
	raw, err = json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	c.Handle(w, httptest.NewRequest(http.MethodPost, types.PathSDKCache, bytes.NewReader(raw)), lease.ID)
	if w.Code != http.StatusBadRequest || c.used != 0 {
		t.Fatalf("oversized object admitted: %d, %d", w.Code, c.used)
	}
}

func TestStorageBoundIncludesReadersAndStaging(t *testing.T) {
	c := testManager(t, 24)
	var pinned []*cachedSite
	for _, name := range []string{"first", "second", "third", "fourth"} {
		lease := testLease(c, name)
		w := httptest.NewRecorder()
		c.Handle(w, testRequest(t, http.MethodPut, "123456"), lease.ID)
		if w.Code != http.StatusOK {
			t.Fatal(w.Body.String())
		}
		pinned = append(pinned, c.acquire(lease.Hostname))
	}
	defer func() {
		for _, site := range pinned[1:] {
			c.release(site)
		}
	}()
	next := testLease(c, "next")
	w := httptest.NewRecorder()
	c.Handle(w, testRequest(t, http.MethodPut, "new"), next.ID)
	if w.Code != http.StatusServiceUnavailable || c.used != 24 {
		t.Fatalf("pinned bound: %d, %d", w.Code, c.used)
	}
	c.release(pinned[0])
	w = httptest.NewRecorder()
	c.Handle(w, testRequest(t, http.MethodPut, "new"), next.ID)
	if w.Code != http.StatusOK || c.used != 21 || c.snapshots != 4 {
		t.Fatalf("eviction: %d, %d", w.Code, c.used)
	}
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
	c.Handle(w, testRequest(t, http.MethodPut, "site"), l.ID)
	if w.Code == http.StatusOK || c.used != 0 || c.snapshots != 0 {
		t.Fatal("failed staging accepted or retained a reservation")
	}
	c.dir = dir
	w = httptest.NewRecorder()
	c.Handle(w, testRequest(t, http.MethodPut, "site"), l.ID)
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
		c.Handle(w, req, l.ID)
		if w.Code != http.StatusBadRequest || c.used != 0 {
			t.Fatalf("invalid admission: %d, %d", w.Code, c.used)
		}
	}
}

func TestLeaseEventsBoundOfflineLifetime(t *testing.T) {
	c := testManager(t, 32)
	l := testLease(c, "site")
	w := httptest.NewRecorder()
	c.Handle(w, testRequest(t, http.MethodPut, "site"), l.ID)
	if w.Code != http.StatusOK {
		t.Fatal(w.Body.String())
	}
	site := c.entries[l.Hostname]
	if site.expiresAt != l.LastSeenAt.Add(observationWindow+c.cfg.MaxTTL) {
		t.Fatal("long lease bypassed offline ceiling")
	}
	l.LastSeenAt = time.Now().Add(-observationWindow - 10*time.Second)
	c.Renew(l)
	ceiling := site.expiresAt
	c.Detach(l)
	if site.expiresAt.After(ceiling) || !c.Has(l.Hostname) {
		t.Fatal("detach extended expiry or discarded still-live offline content")
	}
	c.collect(ceiling.Add(time.Second))
	if _, err := os.Stat(site.dir); !os.IsNotExist(err) || c.used != 0 {
		t.Fatalf("expired cache persisted: %v", err)
	}
	c.Renew(l)
	if c.Has(l.Hostname) || c.Eligible(l.ID) {
		t.Fatal("late renewal resurrected detached cache lease")
	}
}

func TestFallbackReleasesSnapshotAndDiskFailureRequestsReupload(t *testing.T) {
	for _, failure := range []string{"method", "missing", "truncated"} {
		t.Run(failure, func(t *testing.T) {
			c := testManager(t, 16)
			l := testLease(c, "site")
			w := httptest.NewRecorder()
			c.Handle(w, testRequest(t, http.MethodPut, "site"), l.ID)
			if w.Code != http.StatusOK {
				t.Fatal(w.Body.String())
			}
			site := c.entries[l.Hostname]
			for _, name := range []string{"second", "third", "fourth"} {
				other := testLease(c, name)
				fill := httptest.NewRecorder()
				c.Handle(fill, testRequest(t, http.MethodPut, "fill"), other.ID)
				if fill.Code != http.StatusOK {
					t.Fatal(fill.Body.String())
				}
			}
			method := http.MethodPost
			if failure != "method" {
				method = http.MethodGet
				path := filepath.Join(site.dir, site.files[site.index].SHA256)
				if failure == "missing" {
					if err := os.Remove(path); err != nil {
						t.Fatal(err)
					}
				} else if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if c.Serve(httptest.NewRecorder(), httptest.NewRequest(method, "https://"+l.Hostname+"/", nil), l.Hostname) {
				t.Fatal("request did not fall back")
			}
			if site.readers != 0 {
				t.Fatal("origin fallback retained a disk pin")
			}
			if failure != "method" {
				w = httptest.NewRecorder()
				c.Handle(w, testRequest(t, http.MethodPost, "site"), l.ID)
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
				c.Handle(w, testRequest(t, http.MethodPut, "site"), l.ID)
				if w.Code != http.StatusOK || !c.Has(l.Hostname) {
					t.Fatalf("snapshot did not recover: %d %s", w.Code, w.Body.String())
				}
			}
			// The entire budget is reclaimable before any origin request ends.
			other := testLease(c, "other")
			w = httptest.NewRecorder()
			c.Handle(w, testRequest(t, http.MethodPut, "next"), other.ID)
			if w.Code != http.StatusOK {
				t.Fatalf("fallback blocked eviction: %s", w.Body.String())
			}
		})
	}
}

func TestFailedOldReaderDoesNotDiscardReplacement(t *testing.T) {
	c := testManager(t, 32)
	l := testLease(c, "site")
	w := httptest.NewRecorder()
	c.Handle(w, testRequest(t, http.MethodPut, "old"), l.ID)
	old := c.acquire(l.Hostname)
	w = httptest.NewRecorder()
	c.Handle(w, testRequest(t, http.MethodPut, "new"), l.ID)
	if w.Code != http.StatusOK {
		t.Fatal(w.Body.String())
	}
	c.discard(old)
	c.release(old)
	if !c.Has(l.Hostname) {
		t.Fatal("failed old reader discarded replacement")
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
	c := testManager(t, 32) // Cache owns a separate two-request pool for each operation.
	l := testLease(c, "site")
	resume := make(chan struct{})
	var workers sync.WaitGroup
	defer func() { close(resume); workers.Wait() }()
	for _, method := range []string{http.MethodPost, http.MethodPost, http.MethodPut, http.MethodPut} {
		started := make(chan struct{})
		req := testRequest(t, method, "site")
		req.Body = &gatedBody{ReadCloser: req.Body, started: started, resume: resume}
		workers.Add(1)
		go func() { defer workers.Done(); c.Handle(httptest.NewRecorder(), req, l.ID) }()
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			t.Fatalf("internal %s capacity was not available", method)
		}
	}
	for _, method := range []string{http.MethodPost, http.MethodPut} {
		w := httptest.NewRecorder()
		c.Handle(w, testRequest(t, method, "site"), l.ID)
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s exceeded its internal bound: %d", method, w.Code)
		}
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
	c.Handle(w, testRequest(t, http.MethodPut, "site"), l.ID)
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

func TestUploadRequiresOptedInLease(t *testing.T) {
	c := testManager(t, 16)
	l := Lease{ID: "plain-id", Owner: "plain", Hostname: "plain.localhost", ExpiresAt: time.Now().Add(24 * time.Hour), LastSeenAt: time.Now()}
	c.Register(l, types.RegisterChallengeRequest{Cache: false})
	w := httptest.NewRecorder()
	c.Handle(w, testRequest(t, http.MethodPut, "site"), l.ID)
	if w.Code != http.StatusForbidden || c.Eligible(l.ID) || c.Has(l.Hostname) || c.used != 0 {
		t.Fatalf("non-opted-in lease admitted an upload: %d", w.Code)
	}
	w = httptest.NewRecorder()
	c.Handle(w, testRequest(t, http.MethodPut, "site"), "unknown-id")
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
	// The manifest still announces the declared size, but the object bytes no
	// longer hash to the declared SHA-256.
	req.Body = io.NopCloser(strings.NewReader(strings.Replace(string(raw), "site", "tampered", 1)))
	w := httptest.NewRecorder()
	c.Handle(w, req, l.ID)
	if w.Code != http.StatusBadRequest || c.Has(l.Hostname) || c.used != 0 {
		t.Fatalf("corrupt object admitted: %d, %d", w.Code, c.used)
	}
}

func TestLeaseReplacementRejectsInFlightUpload(t *testing.T) {
	c := testManager(t, 32)
	first := Lease{ID: "first-id", Owner: "site", Hostname: "first.localhost", ExpiresAt: time.Now().Add(24 * time.Hour), LastSeenAt: time.Now()}
	c.Register(first, types.RegisterChallengeRequest{Cache: true, CacheTTL: 86400})
	started := make(chan struct{})
	resume := make(chan struct{})
	req := testRequest(t, http.MethodPut, "site")
	req.Body = &gatedBody{ReadCloser: req.Body, started: started, resume: resume}
	codes := make(chan int, 1)
	go func() {
		w := httptest.NewRecorder()
		c.Handle(w, req, first.ID)
		codes <- w.Code
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("upload never started reading its body")
	}
	// Re-registering the same identity replaces the lease while the old
	// upload is still streaming its body.
	replacement := Lease{ID: "second-id", Owner: "site", Hostname: "second.localhost", ExpiresAt: time.Now().Add(24 * time.Hour), LastSeenAt: time.Now()}
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
	w := httptest.NewRecorder()
	c.Handle(w, testRequest(t, http.MethodPut, "site"), replacement.ID)
	if w.Code != http.StatusOK || !c.Has(replacement.Hostname) {
		t.Fatalf("replacement lease could not publish: %d %s", w.Code, w.Body.String())
	}
}

func TestPolicyBanSuspendsCacheRouting(t *testing.T) {
	runtime, err := policy.NewRuntime(false, false, false, "")
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(Config{Enabled: true, MaxBytes: 16, MaxTTL: time.Minute}, t.TempDir(), runtime)
	if err != nil {
		t.Fatal(err)
	}
	l := testLease(c, "site")
	w := httptest.NewRecorder()
	c.Handle(w, testRequest(t, http.MethodPut, "site"), l.ID)
	if w.Code != http.StatusOK {
		t.Fatal(w.Body.String())
	}
	runtime.BanIdentity(l.Owner)
	if c.Has(l.Hostname) || c.Eligible(l.ID) {
		t.Fatal("banned identity remained routable from cache")
	}
	if c.Serve(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "https://"+l.Hostname+"/", nil), l.Hostname) {
		t.Fatal("banned identity was still served from cache")
	}
	// A ban is a routing decision; the retained snapshot returns on unban.
	runtime.UnbanIdentity(l.Owner)
	if !c.Has(l.Hostname) {
		t.Fatal("unban discarded retained cache content")
	}
}
