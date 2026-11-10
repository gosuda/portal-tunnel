package cache

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

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
