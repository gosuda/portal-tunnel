package cache

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
)

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
