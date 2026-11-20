package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestServeFrontendCustomDirectoryConfinesSymlinksAndKeepsLiveFiles(t *testing.T) {
	parent := t.TempDir()
	frontendDir := filepath.Join(parent, "frontend")
	if err := os.Mkdir(frontendDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(frontendDir, "index.html"), []byte("index"), 0o600); err != nil {
		t.Fatal(err)
	}
	assetPath := filepath.Join(frontendDir, "asset.txt")
	if err := os.WriteFile(assetPath, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("asset.txt", filepath.Join(frontendDir, "internal.txt")); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	secret := filepath.Join(parent, "secret.txt")
	if err := os.WriteFile(secret, []byte("TOP-SECRET"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(frontendDir, "direct.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("..", filepath.Join(frontendDir, "parent")); err != nil {
		t.Fatal(err)
	}

	frontendFS, frontendRoot, err := resolveFrontendFS(frontendDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = frontendRoot.Close() })
	api := &RelayAPI{frontendFS: frontendFS}
	request := func(target string) *httptest.ResponseRecorder {
		t.Helper()
		response := httptest.NewRecorder()
		api.serveFrontend(response, httptest.NewRequest(http.MethodGet, target, nil))
		return response
	}

	for _, target := range []string{"/direct.txt", "/parent/secret.txt"} {
		response := request(target)
		if response.Code != http.StatusNotFound {
			t.Fatalf("%s status = %d, want 404; body = %q", target, response.Code, response.Body.String())
		}
		if strings.Contains(response.Body.String(), "TOP-SECRET") {
			t.Fatalf("%s leaked a file outside the frontend root", target)
		}
	}

	for _, target := range []string{"/asset.txt", "/internal.txt"} {
		response := request(target)
		if response.Code != http.StatusOK || response.Body.String() != "first" {
			t.Fatalf("%s initial response: status = %d, body = %q", target, response.Code, response.Body.String())
		}
	}
	if err := os.WriteFile(assetPath, []byte("updated"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"/asset.txt", "/internal.txt"} {
		response := request(target)
		if response.Code != http.StatusOK || response.Body.String() != "updated" {
			t.Fatalf("%s updated response: status = %d, body = %q", target, response.Code, response.Body.String())
		}
	}
}
