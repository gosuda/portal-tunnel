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

func TestAdmissionPreservesTenantAndObjectBounds(t *testing.T) {
	c := testManager(t, 32)
	lease := testLease(c, "site")
	w := httptest.NewRecorder()
	c.Handle(w, testRequest(t, http.MethodPut, "12345678"), lease.ID, c.Generation(lease.ID))
	if w.Code != http.StatusOK {
		t.Fatal(w.Body.String())
	}
	manifest := types.StaticCacheManifest{Index: "index.html", Files: []types.StaticCacheFile{
		{Path: "index.html", Size: 5, SHA256: strings.Repeat("a", 64)},
		{Path: "other.html", Size: 5, SHA256: strings.Repeat("b", 64)},
	}}
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	c.Handle(w, httptest.NewRequest(http.MethodPost, types.PathSDKCache, bytes.NewReader(raw)), lease.ID, c.Generation(lease.ID))
	if w.Code != http.StatusBadRequest || c.used != 8 || !c.Has(lease.Hostname) {
		t.Fatalf("over-budget exposure modified storage: %d, %d", w.Code, c.used)
	}

	c = testManager(t, 1<<30)
	lease = testLease(c, "site")
	manifest.Files = manifest.Files[:1]
	manifest.Files[0].Size = (10 << 20) + 1
	raw, err = json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	c.Handle(w, httptest.NewRequest(http.MethodPost, types.PathSDKCache, bytes.NewReader(raw)), lease.ID, c.Generation(lease.ID))
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
		c.Handle(w, testRequest(t, http.MethodPut, "123456"), lease.ID, c.Generation(lease.ID))
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
	c.Handle(w, testRequest(t, http.MethodPut, "new"), next.ID, c.Generation(next.ID))
	if w.Code != http.StatusServiceUnavailable || c.used != 24 {
		t.Fatalf("pinned bound: %d, %d", w.Code, c.used)
	}
	c.release(pinned[0])
	w = httptest.NewRecorder()
	c.Handle(w, testRequest(t, http.MethodPut, "new"), next.ID, c.Generation(next.ID))
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

func TestLeaseEventsBoundOfflineLifetime(t *testing.T) {
	c := testManager(t, 32)
	l := testLease(c, "site")
	w := httptest.NewRecorder()
	c.Handle(w, testRequest(t, http.MethodPut, "site"), l.ID, c.Generation(l.ID))
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
			c.Handle(w, testRequest(t, http.MethodPut, "site"), l.ID, c.Generation(l.ID))
			if w.Code != http.StatusOK {
				t.Fatal(w.Body.String())
			}
			site := c.entries[l.Hostname]
			for _, name := range []string{"second", "third", "fourth"} {
				other := testLease(c, name)
				fill := httptest.NewRecorder()
				c.Handle(fill, testRequest(t, http.MethodPut, "fill"), other.ID, c.Generation(other.ID))
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
			other := testLease(c, "other")
			w = httptest.NewRecorder()
			c.Handle(w, testRequest(t, http.MethodPut, "next"), other.ID, c.Generation(other.ID))
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
	resume := make(chan struct{})
	var workers sync.WaitGroup
	defer func() { close(resume); workers.Wait() }()
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
	for _, method := range []string{http.MethodPost, http.MethodPut} {
		w := httptest.NewRecorder()
		c.Handle(w, testRequest(t, method, "site"), l.ID, c.Generation(l.ID))
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
	w := httptest.NewRecorder()
	c.Handle(w, testRequest(t, http.MethodPut, "site"), replacement.ID, c.Generation(replacement.ID))
	if w.Code != http.StatusOK || !c.Has(replacement.Hostname) {
		t.Fatalf("replacement lease could not publish: %d %s", w.Code, w.Body.String())
	}
}

func TestDetachOwnerRejectsInFlightCacheRequests(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodPut} {
		t.Run(method, func(t *testing.T) {
			c := testManager(t, 128)
			lease := testLease(c, "site")
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
			c.DetachOwner(lease.Owner)
			fresh := httptest.NewRecorder()
			c.Handle(fresh, testRequest(t, http.MethodPut, "new"), lease.ID, c.Generation(lease.ID))
			close(resume)
			code := <-codes
			if method == http.MethodPut {
				if code != http.StatusForbidden || fresh.Code != http.StatusServiceUnavailable || c.Has(lease.Hostname) {
					t.Fatalf("revoked PUT = %d, overlapping upload = %d, published = %v", code, fresh.Code, c.Has(lease.Hostname))
				}
				fresh = httptest.NewRecorder()
				c.Handle(fresh, testRequest(t, http.MethodPut, "new"), lease.ID, c.Generation(lease.ID))
			}
			if code != http.StatusForbidden || fresh.Code != http.StatusOK {
				t.Fatalf("old request = %d, fresh upload = %d", code, fresh.Code)
			}
			served := httptest.NewRecorder()
			if !c.Serve(served, httptest.NewRequest(http.MethodGet, "https://"+lease.Hostname+"/", nil), lease.Hostname) || served.Body.String() != "new" {
				t.Fatalf("old request changed fresh content: %q", served.Body.String())
			}
		})
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

func TestStaticCacheDoesNotFollowRedirects(t *testing.T) {
	root := t.TempDir()
	content := []byte("site")
	if err := os.WriteFile(filepath.Join(root, "index.html"), content, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	hash := hex.EncodeToString(sum[:])

	var foreignRequests atomic.Int32
	foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		foreignRequests.Add(1)
		utils.WriteAPIData(w, http.StatusOK, types.StaticCacheStatus{})
	}))
	defer foreign.Close()

	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, foreign.URL, http.StatusFound)
	}))
	defer relay.Close()

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
		snapshot: &sourceSnapshot{
			root: root,
			manifest: types.StaticCacheManifest{
				Index: "index.html",
				Files: []types.StaticCacheFile{{Path: "index.html", Size: int64(len(content)), SHA256: hash}},
			},
		},
	}

	err = syncer.Sync(context.Background(), relay.Client(), "lease-token")
	if err == nil {
		t.Fatal("redirect accepted as a successful cache sync")
	}
	if foreignRequests.Load() != 0 {
		t.Fatalf("foreign server received %d requests, want 0 (redirect was followed)", foreignRequests.Load())
	}
}

func TestUploadAdmissionIsolatesServiceIdentities(t *testing.T) {
	c := testManager(t, 64)
	first := testLease(c, "first")
	other := testLease(c, "other")
	started := make(chan struct{})
	resume := make(chan struct{})
	done := make(chan int, 1)
	req := testRequest(t, http.MethodPut, "first")
	req.Body = &gatedBody{ReadCloser: req.Body, started: started, resume: resume}
	go func() {
		w := httptest.NewRecorder()
		c.Handle(w, req, first.ID, c.Generation(first.ID))
		done <- w.Code
	}()
	defer func() {
		close(resume)
		if code := <-done; code != http.StatusOK {
			t.Errorf("first upload = %d, want 200", code)
		}
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("first upload did not start")
	}
	w := httptest.NewRecorder()
	c.Handle(w, testRequest(t, http.MethodPut, "duplicate"), first.ID, c.Generation(first.ID))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("duplicate upload = %d, want 503", w.Code)
	}
	w = httptest.NewRecorder()
	c.Handle(w, testRequest(t, http.MethodPut, "other"), other.ID, c.Generation(other.ID))
	if w.Code != http.StatusOK {
		t.Fatalf("another service could not use the remaining slot: %d", w.Code)
	}
	bad := httptest.NewRequest(http.MethodPut, types.PathSDKCache, strings.NewReader("invalid"))
	w = httptest.NewRecorder()
	c.Handle(w, bad, other.ID, c.Generation(other.ID))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("malformed upload = %d, want 400", w.Code)
	}
	w = httptest.NewRecorder()
	c.Handle(w, testRequest(t, http.MethodPut, "retry"), other.ID, c.Generation(other.ID))
	if w.Code != http.StatusOK {
		t.Fatalf("failed upload retained admission: %d", w.Code)
	}
}

func TestChangedManifestFallsBackAcrossRejectedUploadAndRenewal(t *testing.T) {
	c := testManager(t, 64)
	lease := testLease(c, "site")
	w := httptest.NewRecorder()
	c.Handle(w, testRequest(t, http.MethodPut, "old"), lease.ID, c.Generation(lease.ID))
	if w.Code != http.StatusOK {
		t.Fatal(w.Body.String())
	}
	resume := make(chan struct{})
	var workers sync.WaitGroup
	defer func() {
		if resume != nil {
			close(resume)
		}
		workers.Wait()
	}()
	for _, name := range []string{"first", "second"} {
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
	w = httptest.NewRecorder()
	c.Handle(w, testRequest(t, http.MethodPost, "new"), lease.ID, c.Generation(lease.ID))
	if w.Code != http.StatusOK {
		t.Fatal(w.Body.String())
	}
	w = httptest.NewRecorder()
	c.Handle(w, testRequest(t, http.MethodPut, "new"), lease.ID, c.Generation(lease.ID))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("upload at capacity = %d, want 503", w.Code)
	}
	lease.LastSeenAt = time.Now().Add(time.Minute)
	c.Renew(lease)
	if c.Serve(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "https://"+lease.Hostname+"/", nil), lease.Hostname) {
		t.Fatal("renewal served a known superseded snapshot after rejected replacement")
	}
	close(resume)
	resume = nil
	workers.Wait()
	w = httptest.NewRecorder()
	c.Handle(w, testRequest(t, http.MethodPut, "new"), lease.ID, c.Generation(lease.ID))
	if w.Code != http.StatusOK {
		t.Fatalf("replacement after capacity recovered = %d, want 200", w.Code)
	}
	w = httptest.NewRecorder()
	if !c.Serve(w, httptest.NewRequest(http.MethodGet, "https://"+lease.Hostname+"/", nil), lease.Hostname) || w.Body.String() != "new" {
		t.Fatalf("replacement content = %q, want new", w.Body.String())
	}
}

func TestStaticCacheRetriesTransientAdmissionErrorsWithoutDelete(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodPut} {
		for _, status := range []int{http.StatusTooManyRequests, http.StatusServiceUnavailable} {
			t.Run(method+"/"+http.StatusText(status), func(t *testing.T) {
				root := t.TempDir()
				content := []byte("site")
				if err := os.WriteFile(filepath.Join(root, "index.html"), content, 0o600); err != nil {
					t.Fatal(err)
				}
				sum := sha256.Sum256(content)
				hash := hex.EncodeToString(sum[:])

				var deleteCalls atomic.Int32
				var admissionStatus atomic.Int32
				admissionStatus.Store(int32(status))
				var rejected atomic.Int32
				var uploads atomic.Int32

				relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					switch r.Method {
					case http.MethodDelete:
						deleteCalls.Add(1)
						w.WriteHeader(http.StatusNoContent)
					case http.MethodPost:
						var manifest types.StaticCacheManifest
						if err := json.NewDecoder(r.Body).Decode(&manifest); err != nil {
							t.Errorf("decode manifest: %v", err)
							http.Error(w, "invalid manifest", http.StatusBadRequest)
							return
						}
						if len(manifest.Files) != 1 || manifest.Files[0].SHA256 != hash {
							t.Errorf("manifest = %+v, want unchanged generation", manifest)
							http.Error(w, "changed manifest", http.StatusBadRequest)
							return
						}
						if method == http.MethodPost && admissionStatus.Load() != http.StatusOK {
							rejected.Add(1)
							http.Error(w, "admission unavailable", int(admissionStatus.Load()))
							return
						}
						utils.WriteAPIData(w, http.StatusOK, types.StaticCacheStatus{Present: false})
					case http.MethodPut:
						if method == http.MethodPut && admissionStatus.Load() != http.StatusOK {
							rejected.Add(1)
							http.Error(w, "admission unavailable", int(admissionStatus.Load()))
							return
						}
						if err := r.ParseMultipartForm(1024); err != nil {
							t.Errorf("parse upload: %v", err)
							http.Error(w, "invalid upload", http.StatusBadRequest)
							return
						}
						defer r.MultipartForm.RemoveAll()
						objects := r.MultipartForm.Value["object"]
						if len(objects) != 1 || objects[0] != string(content) {
							t.Errorf("uploaded objects = %q, want original content", objects)
							http.Error(w, "changed content", http.StatusBadRequest)
							return
						}
						uploads.Add(1)
						utils.WriteAPIData(w, http.StatusOK, types.StaticCacheStatus{Present: true})
					default:
						http.NotFound(w, r)
					}
				}))
				defer relay.Close()

				relayURL, err := url.Parse(relay.URL)
				if err != nil {
					t.Fatal(err)
				}

				source, err := NewSource(SourceConfig{Path: root})
				if err != nil {
					t.Fatal(err)
				}
				snap := &sourceSnapshot{
					root: root,
					manifest: types.StaticCacheManifest{
						Index: "index.html",
						Files: []types.StaticCacheFile{{Path: "index.html", Size: int64(len(content)), SHA256: hash}},
					},
				}
				source.mu.Lock()
				source.snapshot = snap
				source.mu.Unlock()

				syncer := source.Subscribe(*relayURL, types.StaticCacheLimits{MaxExposureBytes: 1024, MaxObjectSize: 512})
				defer syncer.Close()

				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()

				if !syncer.Next(ctx) {
					t.Fatal("Next() = false, want initial snapshot ready")
				}

				err = syncer.Sync(ctx, relay.Client(), "lease-token")
				var apiErr *types.APIRequestError
				if !errors.As(err, &apiErr) || apiErr.StatusCode != status {
					t.Fatalf("Sync() error = %v, want HTTP %d", err, status)
				}
				if rejected.Load() == 0 {
					t.Fatalf("%s admission failure was not exercised", method)
				}
				if deleteCalls.Load() != 0 {
					t.Fatalf("DELETE called %d times on transient error, want 0", deleteCalls.Load())
				}

				if !syncer.Next(ctx) {
					t.Fatal("Next() after transient failure = false, want same snapshot retried")
				}

				admissionStatus.Store(http.StatusOK)
				if err := syncer.Sync(ctx, relay.Client(), "lease-token"); err != nil {
					t.Fatalf("Sync() retry error = %v, want success", err)
				}
				if uploads.Load() == 0 {
					t.Fatal("retry did not upload the selected generation")
				}
				if deleteCalls.Load() != 0 {
					t.Fatal("retry deleted cached content")
				}
			})
		}
	}
}

func TestReserveKeepsPinnedReadersRouted(t *testing.T) {
	c := testManager(t, 24)
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
	defer func() {
		for _, site := range pinned {
			c.release(site)
		}
	}()
	next := testLease(c, "next")
	w := httptest.NewRecorder()
	c.Handle(w, testRequest(t, http.MethodPut, "new"), next.ID, c.Generation(next.ID))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("over-budget upload admitted with pinned readers: %d", w.Code)
	}
	for _, host := range hosts {
		if !c.Has(host) {
			t.Fatalf("pinned snapshot %q lost routing under admission pressure", host)
		}
	}
}
