package portal

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func cacheTestServer(t *testing.T, budget int) *Server {
	t.Helper()
	registry := newTestRegistry(t)
	cache, err := newStaticCache(types.RelayCacheConfig{Enabled: true, Dir: t.TempDir(), MaxBytes: budget, MaxExposureBytes: budget, MaxObjectSize: budget, MaxTTL: time.Minute, PopulationConcurrency: 1})
	if err != nil {
		t.Fatal(err)
	}
	registry.cache = cache
	t.Cleanup(func() { registry.CloseAll() })
	return &Server{registry: registry}
}

func cacheTestUpload(t *testing.T, token, content string) *http.Request {
	t.Helper()
	digest := sha256.Sum256([]byte(content))
	manifest := types.StaticCacheManifest{Index: "index.html", Files: []types.StaticCacheFile{{Path: "index.html", Size: int64(len(content)), SHA256: hex.EncodeToString(digest[:])}}}
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormField("manifest")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.NewEncoder(part).Encode(manifest); err != nil {
		t.Fatal(err)
	}
	part, err = writer.CreateFormField("object")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(part, content)
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPut, types.PathSDKCache, &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set(types.HeaderAccessToken, token)
	return req
}

func cacheTestRegister(t *testing.T, server *Server, name string, optIn bool) (*leaseRecord, string) {
	t.Helper()
	record, response, err := server.registry.Register(types.RegisterChallengeRequest{Identity: newTestLeaseIdentity(t, name), Cache: optIn, CacheTTL: 86400}, "203.0.113.1", "", types.RelayDescriptor{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return record, response.AccessToken
}

func TestStaticCachePermissionIntegrityAndLeaseReplacement(t *testing.T) {
	s := cacheTestServer(t, 32)
	uncached, token := cacheTestRegister(t, s, "uncached", false)
	result := httptest.NewRecorder()
	s.handleStaticCache(result, cacheTestUpload(t, token, "site"))
	if result.Code != http.StatusForbidden || uncached.Cache {
		t.Fatalf("non-opted-in upload = %d", result.Code)
	}
	record, token := cacheTestRegister(t, s, "cached", true)
	if record.CacheTTL != time.Minute {
		t.Fatalf("TTL hint was not clamped: %s", record.CacheTTL)
	}
	bad := cacheTestUpload(t, token, "site")
	body, _ := io.ReadAll(bad.Body)
	bad.Body = io.NopCloser(bytes.NewReader(bytes.Replace(body, []byte("\r\nsite\r\n"), []byte("\r\nfake\r\n"), 1)))
	result = httptest.NewRecorder()
	s.handleStaticCache(result, bad)
	if result.Code != http.StatusBadRequest || s.registry.cache.used != 0 {
		t.Fatalf("corrupt upload status=%d charged=%d", result.Code, s.registry.cache.used)
	}
	request := cacheTestUpload(t, token, "site")
	request.Body = &cacheReplacementReader{ReadCloser: request.Body, replace: func() {
		_, _, err := s.registry.Register(types.RegisterChallengeRequest{Identity: record.Identity}, "203.0.113.1", "", types.RelayDescriptor{}, nil)
		if err != nil {
			t.Fatal(err)
		}
	}}
	result = httptest.NewRecorder()
	s.handleStaticCache(result, request)
	if result.Code != http.StatusForbidden || s.registry.cache.used != 0 || len(s.registry.cache.entries) != 0 {
		t.Fatalf("replaced lease published an in-flight upload: %d", result.Code)
	}
}

type cacheReplacementReader struct {
	io.ReadCloser
	replace func()
}

func (r *cacheReplacementReader) Read(p []byte) (int, error) {
	if r.replace != nil {
		r.replace()
		r.replace = nil
	}
	return r.ReadCloser.Read(p)
}

func TestStaticCacheOfflineExpiryAndHostIsolation(t *testing.T) {
	s := cacheTestServer(t, 32)
	record, token := cacheTestRegister(t, s, "site", true)
	result := httptest.NewRecorder()
	s.handleStaticCache(result, cacheTestUpload(t, token, "hello"))
	if result.Code != http.StatusOK {
		t.Fatalf("upload: %s", result.Body.String())
	}
	if _, err := s.registry.Unregister(types.UnregisterRequest{AccessToken: token}); err != nil {
		t.Fatal(err)
	}
	for _, route := range []string{"/", "/app/route", types.PathSDKDomain} {
		req := httptest.NewRequest(http.MethodGet, "https://"+record.Hostname+route, nil)
		req.TLS = &tls.ConnectionState{ServerName: record.Hostname}
		result = httptest.NewRecorder()
		s.serveCachedSite(result, req, record.Hostname)
		if result.Code != http.StatusOK || result.Body.String() != "hello" {
			t.Fatalf("offline %s: %d %s", route, result.Code, result.Body.String())
		}
	}
	spoofed := httptest.NewRequest(http.MethodGet, "https://example.com/sdk/domain", nil)
	spoofed.TLS = &tls.ConnectionState{ServerName: record.Hostname}
	result = httptest.NewRecorder()
	s.serveCachedSite(result, spoofed, "example.com")
	if result.Code != http.StatusMisdirectedRequest {
		t.Fatalf("spoofed root host status = %d", result.Code)
	}
	s.registry.policy.BanIdentity(record.Key())
	if site := s.registry.acquireCachedSite(record.Hostname); site != nil {
		t.Fatal("banned identity still served from cache")
	}
	s.registry.policy.UnbanIdentity(record.Key())
	site := s.registry.cache.entries[record.Hostname]
	site.expiresAt = time.Now().Add(-time.Second)
	s.registry.cache.collect(time.Now())
	if _, err := os.Stat(site.dir); !os.IsNotExist(err) || s.registry.cache.used != 0 {
		t.Fatalf("expired cache remains on disk: %v, %d bytes", err, s.registry.cache.used)
	}
}

func TestStaticCacheStorageBoundIncludesReadersAndStaging(t *testing.T) {
	s := cacheTestServer(t, 6)
	first, token := cacheTestRegister(t, s, "first", true)
	result := httptest.NewRecorder()
	s.handleStaticCache(result, cacheTestUpload(t, token, "first"))
	if result.Code != http.StatusOK {
		t.Fatal(result.Body.String())
	}
	pinned := s.registry.acquireCachedSite(first.Hostname)
	_, secondToken := cacheTestRegister(t, s, "second", true)
	result = httptest.NewRecorder()
	s.handleStaticCache(result, cacheTestUpload(t, secondToken, "new"))
	if result.Code != http.StatusServiceUnavailable || s.registry.cache.used != 5 {
		t.Fatalf("pinned cache bound: %d, %d", result.Code, s.registry.cache.used)
	}
	s.registry.cache.release(pinned)
	result = httptest.NewRecorder()
	s.handleStaticCache(result, cacheTestUpload(t, secondToken, "new"))
	if result.Code != http.StatusOK || s.registry.cache.used != 3 || s.registry.cache.snapshots != 1 {
		t.Fatalf("LRU admission: %d, %d", result.Code, s.registry.cache.used)
	}
	var diskBytes int64
	_ = filepath.Walk(s.registry.cache.cfg.Dir, func(_ string, info os.FileInfo, err error) error {
		if err == nil && info.Mode().IsRegular() {
			diskBytes += info.Size()
		}
		return err
	})
	if diskBytes != 3 {
		t.Fatalf("disk bytes = %d", diskBytes)
	}
	// Full/busy cache admission never removes the live tunnel registration.
	if _, ok := s.registry.Lookup(first.Hostname); !ok {
		t.Fatal("eviction removed the origin tunnel")
	}
}

func TestStaticCacheRejectsUnsafeAndOversizedManifest(t *testing.T) {
	s := cacheTestServer(t, 4)
	_, token := cacheTestRegister(t, s, "site", true)
	for _, content := range []string{"12345", "123"} {
		req := cacheTestUpload(t, token, content)
		if len(content) == 3 {
			raw, _ := io.ReadAll(req.Body)
			req.Body = io.NopCloser(strings.NewReader(strings.ReplaceAll(string(raw), "index.html", "../index.html")))
		}
		result := httptest.NewRecorder()
		s.handleStaticCache(result, req)
		if result.Code != http.StatusBadRequest || s.registry.cache.used != 0 {
			t.Fatalf("invalid admission: %d, %d", result.Code, s.registry.cache.used)
		}
	}
}

func TestStaticCacheBoundsZeroByteStagingMetadata(t *testing.T) {
	s := cacheTestServer(t, 32)
	for range types.StaticCacheMaxEntries {
		if err := s.registry.cache.reserve(0); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.registry.cache.reserve(0); err == nil {
		t.Fatal("zero-byte staging bypassed the snapshot count limit")
	}
}

func TestStaticCacheLeaseTTLDoesNotOverrideOfflineCeiling(t *testing.T) {
	s := cacheTestServer(t, 32)
	record, response, err := s.registry.Register(types.RegisterChallengeRequest{Identity: newTestLeaseIdentity(t, "long-lease"), Cache: true, TTL: 86400}, "203.0.113.1", "", types.RelayDescriptor{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	result := httptest.NewRecorder()
	s.handleStaticCache(result, cacheTestUpload(t, response.AccessToken, "site"))
	if result.Code != http.StatusOK {
		t.Fatal(result.Body.String())
	}
	site := s.registry.cache.entries[record.Hostname]
	if site.expiresAt.After(record.LastSeenAt.Add(defaultLeaseTTL + s.registry.cache.cfg.MaxTTL)) {
		t.Fatal("origin lease TTL bypassed the relay's offline cache ceiling")
	}
	site.expiresAt = time.Now().Add(-time.Second)
	if _, err := s.registry.Unregister(types.UnregisterRequest{AccessToken: response.AccessToken}); err != nil {
		t.Fatal(err)
	}
	if site := s.registry.acquireCachedSite(record.Hostname); site != nil {
		t.Fatal("unregister resurrected an expired snapshot")
	}
}
