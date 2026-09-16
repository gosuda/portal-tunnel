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
	c, err := New(Config{Enabled: true, Dir: t.TempDir(), MaxBytes: budget, MaxExposureBytes: budget, MaxObjectSize: budget, MaxTTL: time.Minute, PopulationConcurrency: 1, CheckConcurrency: 2}, policy)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func testLease(c *Manager, name string) Lease {
	l := Lease{ID: name + "-id", Owner: name, Hostname: name + ".localhost", ClientIP: "203.0.113.1", ExpiresAt: time.Now().Add(24 * time.Hour), LastSeenAt: time.Now()}
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

func TestStorageBoundIncludesReadersAndStaging(t *testing.T) {
	c := testManager(t, 6)
	first, second := testLease(c, "first"), testLease(c, "second")
	w := httptest.NewRecorder()
	c.Handle(w, testRequest(t, http.MethodPut, "first"), first.ID)
	if w.Code != http.StatusOK {
		t.Fatal(w.Body.String())
	}
	pinned := c.acquire(first.Hostname)
	w = httptest.NewRecorder()
	c.Handle(w, testRequest(t, http.MethodPut, "new"), second.ID)
	if w.Code != http.StatusServiceUnavailable || c.used != 5 {
		t.Fatalf("pinned bound: %d, %d", w.Code, c.used)
	}
	c.release(pinned)
	w = httptest.NewRecorder()
	c.Handle(w, testRequest(t, http.MethodPut, "new"), second.ID)
	if w.Code != http.StatusOK || c.used != 3 || c.snapshots != 1 {
		t.Fatalf("eviction: %d, %d", w.Code, c.used)
	}
	var diskBytes int64
	err := filepath.Walk(c.cfg.Dir, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			diskBytes += info.Size()
		}
		return nil
	})
	if err != nil || diskBytes != 3 {
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
	c := testManager(t, 4)
	l := testLease(c, "site")
	dir := c.cfg.Dir
	blocked := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocked, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	c.cfg.Dir = blocked
	w := httptest.NewRecorder()
	c.Handle(w, testRequest(t, http.MethodPut, "site"), l.ID)
	if w.Code == http.StatusOK {
		t.Fatal("unusable directory accepted")
	}
	c.cfg.Dir = dir
	w = httptest.NewRecorder()
	c.Handle(w, testRequest(t, http.MethodPut, "site"), l.ID)
	if w.Code != http.StatusOK {
		t.Fatalf("full-capacity retry: %d %s", w.Code, w.Body.String())
	}
}

func TestRejectsUnsafeAndOversizedManifest(t *testing.T) {
	c := testManager(t, 4)
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
			c := testManager(t, 4)
			l := testLease(c, "site")
			w := httptest.NewRecorder()
			c.Handle(w, testRequest(t, http.MethodPut, "site"), l.ID)
			if w.Code != http.StatusOK {
				t.Fatal(w.Body.String())
			}
			site := c.entries[l.Hostname]
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
	c := testManager(t, 8)
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

func TestAdmissionUsesSeparateConfiguredLimits(t *testing.T) {
	c := testManager(t, 32) // One upload and two checks are explicitly configured.
	l := testLease(c, "site")
	resume := make(chan struct{})
	var workers sync.WaitGroup
	defer func() { close(resume); workers.Wait() }()
	for _, method := range []string{http.MethodPost, http.MethodPost, http.MethodPut} {
		started := make(chan struct{})
		req := testRequest(t, method, "site")
		req.Body = &gatedBody{ReadCloser: req.Body, started: started, resume: resume}
		workers.Add(1)
		go func() { defer workers.Done(); c.Handle(httptest.NewRecorder(), req, l.ID) }()
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			t.Fatalf("configured %s capacity was not available", method)
		}
	}
	for _, method := range []string{http.MethodPost, http.MethodPut} {
		w := httptest.NewRecorder()
		c.Handle(w, testRequest(t, method, "site"), l.ID)
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s exceeded its configured bound: %d", method, w.Code)
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
	c := testManager(t, 4)
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
