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
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
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
