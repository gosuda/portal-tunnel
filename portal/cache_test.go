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
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/cache"
	"github.com/gosuda/portal-tunnel/v2/types"
)

func cacheTestServer(t *testing.T, budget int) *Server {
	t.Helper()
	registry := newTestRegistry(t)
	manager, err := cache.New(cache.Config{Enabled: true, MaxBytes: budget, MaxTTL: time.Minute}, t.TempDir(), registry.policy)
	if err != nil {
		t.Fatal(err)
	}
	registry.cache = manager
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

// TestStaticCachePermissionIntegrityAndLeaseReplacement verifies that uploads are rejected
// when the lease has not opted into caching, that a corrupt manifest is rejected,
// and that uploading with a replaced lease (same identity but different id) is rejected.

func TestStaticCachePermissionIntegrityAndLeaseReplacement(t *testing.T) {
	s := cacheTestServer(t, 32)
	uncached, token := cacheTestRegister(t, s, "uncached", false)
	result := httptest.NewRecorder()
	s.handleStaticCache(result, cacheTestUpload(t, token, "site"))
	if result.Code != http.StatusForbidden || s.registry.cache.Eligible(uncached.id) {
		t.Fatalf("non-opted-in upload = %d", result.Code)
	}
	record, token := cacheTestRegister(t, s, "cached", true)
	bad := cacheTestUpload(t, token, "site")
	body, _ := io.ReadAll(bad.Body)
	bad.Body = io.NopCloser(bytes.NewReader(bytes.Replace(body, []byte("\r\nsite\r\n"), []byte("\r\nfake\r\n"), 1)))
	result = httptest.NewRecorder()
	s.handleStaticCache(result, bad)
	if result.Code != http.StatusBadRequest {
		t.Fatalf("corrupt upload status=%d", result.Code)
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
	if result.Code != http.StatusForbidden || s.registry.cache.Has(record.Hostname) {
		t.Fatalf("replaced lease published an in-flight upload: %d", result.Code)
	}
}

// TestStaticCacheOfflineExpiryAndHostIsolation verifies that after a lease expires or is
// unregistered, its cached content is still served offline for the duration of the
// TTL, that a spoofed Host header at the root path is rejected, and that banning
// an identity immediately evicts its cached content.

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
	if s.registry.cache.Has(record.Hostname) {
		t.Fatal("banned identity still served from cache")
	}
	s.registry.policy.UnbanIdentity(record.Key())

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
