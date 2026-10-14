package utils

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newStaticSite(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, content := range files {
		full := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("MkdirAll(%q) error = %v", name, err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatalf("WriteFile(%q) error = %v", name, err)
		}
	}
	return root
}

func TestResolveStaticSiteDirectoryUsesDefaultIndex(t *testing.T) {
	t.Parallel()

	dir := newStaticSite(t, map[string]string{"index.html": "<html>index</html>"})

	root, index, err := ResolveStaticSite(dir)
	if err != nil {
		t.Fatalf("ResolveStaticSite() error = %v", err)
	}
	if root != dir {
		t.Fatalf("root = %q, want %q", root, dir)
	}
	if index != DefaultStaticIndex {
		t.Fatalf("index = %q, want %q", index, DefaultStaticIndex)
	}
}

func TestResolveStaticSiteFileUsesParentDirectory(t *testing.T) {
	t.Parallel()

	dir := newStaticSite(t, map[string]string{"main.html": "<html>main</html>"})

	root, index, err := ResolveStaticSite(filepath.Join(dir, "main.html"))
	if err != nil {
		t.Fatalf("ResolveStaticSite() error = %v", err)
	}
	if root != dir {
		t.Fatalf("root = %q, want %q", root, dir)
	}
	if index != "main.html" {
		t.Fatalf("index = %q, want main.html", index)
	}
}

func TestResolveStaticSiteRejectsMissingEntry(t *testing.T) {
	t.Parallel()

	// A directory without index.html has no SPA entry to fall back to.
	dir := newStaticSite(t, map[string]string{"assets/app.css": "body{}"})
	if _, _, err := ResolveStaticSite(dir); err == nil {
		t.Fatal("ResolveStaticSite() error = nil, want missing entry error")
	}

	if _, _, err := ResolveStaticSite(filepath.Join(dir, "nope")); err == nil {
		t.Fatal("ResolveStaticSite() error = nil, want missing path error")
	}
}

func TestStaticSiteRequestPathStripsPrefixAndRejectsTraversal(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		prefix  string
		urlPath string
		want    string
		wantOK  bool
	}{
		{name: "root prefix", prefix: "/", urlPath: "/assets/app.css", want: "/assets/app.css", wantOK: true},
		{name: "prefix exact", prefix: "/app", urlPath: "/app", want: "/", wantOK: true},
		{name: "prefix stripped", prefix: "/app", urlPath: "/app/assets/app.css", want: "/assets/app.css", wantOK: true},
		{name: "traversal", prefix: "/", urlPath: "/../secret.txt", want: "", wantOK: false},
		{name: "nested traversal", prefix: "/", urlPath: "/sub/../../secret.txt", want: "", wantOK: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, ok := StaticSiteRequestPath(tt.prefix, tt.urlPath)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if got != tt.want {
				t.Fatalf("path = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestStaticSiteHandlerServesConcreteFile(t *testing.T) {
	t.Parallel()

	root := newStaticSite(t, map[string]string{
		"index.html":     "<html>index</html>",
		"assets/app.css": "body{color:red}",
	})
	handler := NewStaticSiteHandler("/", root, DefaultStaticIndex)

	req := httptest.NewRequest(http.MethodGet, "https://public.example/assets/app.css", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Body.String(); got != "body{color:red}" {
		t.Fatalf("body = %q, want css content", got)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/css") {
		t.Fatalf("Content-Type = %q, want text/css", ct)
	}
}

func TestStaticSiteHandlerFallsBackToIndex(t *testing.T) {
	t.Parallel()

	root := newStaticSite(t, map[string]string{"index.html": "<html>spa</html>"})
	handler := NewStaticSiteHandler("/", root, "")

	// The root, an unknown client-side route, and a directory all return the
	// entry file so client-side routing works and nothing is listed.
	for _, target := range []string{
		"https://public.example/",
		"https://public.example/deep/client/route",
	} {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("%s status = %d, want 200", target, rec.Code)
		}
		if got := rec.Body.String(); got != "<html>spa</html>" {
			t.Fatalf("%s body = %q, want index content", target, got)
		}
	}
}

func TestStaticSiteHandlerReturnsIndexForDirectory(t *testing.T) {
	t.Parallel()

	root := newStaticSite(t, map[string]string{
		"index.html":   "<html>index</html>",
		"sub/keep.txt": "keep",
	})
	handler := NewStaticSiteHandler("/", root, DefaultStaticIndex)

	req := httptest.NewRequest(http.MethodGet, "https://public.example/sub", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Body.String(); got != "<html>index</html>" {
		t.Fatalf("body = %q, want index content (no directory listing)", got)
	}
}

func TestStaticSiteHandlerRejectsTraversal(t *testing.T) {
	t.Parallel()

	root := newStaticSite(t, map[string]string{"index.html": "<html>index</html>"})
	// A secret file one level above the served root must never be reachable.
	secret := filepath.Join(filepath.Dir(root), "secret.txt")
	if err := os.WriteFile(secret, []byte("TOP-SECRET"), 0o644); err != nil {
		t.Fatalf("WriteFile(secret) error = %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(secret) })

	handler := NewStaticSiteHandler("/", root, DefaultStaticIndex)

	for _, target := range []string{"/../secret.txt", "/../../secret.txt", "/sub/../../secret.txt"} {
		req := httptest.NewRequest(http.MethodGet, "https://public.example/", nil)
		req.URL.Path = target
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if strings.Contains(rec.Body.String(), "TOP-SECRET") {
			t.Fatalf("%s leaked the out-of-root secret file", target)
		}
	}
}

func TestStaticSiteHandlerRejectsOutOfRootSymlinks(t *testing.T) {
	t.Parallel()

	parent := t.TempDir()
	root := filepath.Join(parent, "site")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatalf("Mkdir(root) error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, DefaultStaticIndex), []byte("<html>spa</html>"), 0o644); err != nil {
		t.Fatalf("WriteFile(index) error = %v", err)
	}
	secret := filepath.Join(parent, "secret.txt")
	if err := os.WriteFile(secret, []byte("TOP-SECRET"), 0o644); err != nil {
		t.Fatalf("WriteFile(secret) error = %v", err)
	}
	if err := os.Symlink(secret, filepath.Join(root, "direct.txt")); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}
	if err := os.Symlink("..", filepath.Join(root, "parent")); err != nil {
		t.Fatalf("Symlink(parent) error = %v", err)
	}

	handler := NewStaticSiteHandler("/", root, DefaultStaticIndex)
	for _, target := range []string{"/direct.txt", "/parent/secret.txt"} {
		t.Run(target, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "https://public.example"+target, nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusNotFound {
				t.Fatalf("%s status = %d, want 404; body = %q", target, rec.Code, rec.Body.String())
			}
			if strings.Contains(rec.Body.String(), "TOP-SECRET") {
				t.Fatalf("%s leaked a file outside the static root", target)
			}
		})
	}
}

func TestStaticSiteHandlerRejectsOutOfRootIndexSymlink(t *testing.T) {
	t.Parallel()

	parent := t.TempDir()
	root := filepath.Join(parent, "site")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatalf("Mkdir(root) error = %v", err)
	}
	secret := filepath.Join(parent, "secret.txt")
	if err := os.WriteFile(secret, []byte("TOP-SECRET"), 0o644); err != nil {
		t.Fatalf("WriteFile(secret) error = %v", err)
	}
	if err := os.Symlink(secret, filepath.Join(root, DefaultStaticIndex)); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	handler := NewStaticSiteHandler("/", root, DefaultStaticIndex)
	for _, target := range []string{"/", "/client/route"} {
		req := httptest.NewRequest(http.MethodGet, "https://public.example"+target, nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s status = %d, want 404; body = %q", target, rec.Code, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), "TOP-SECRET") {
			t.Fatalf("%s leaked a file outside the static root", target)
		}
	}
}

func TestStaticSiteHandlerAllowsInRootSymlinks(t *testing.T) {
	t.Parallel()

	root := newStaticSite(t, map[string]string{
		"index.html":     "<html>spa</html>",
		"assets/app.css": "body{color:red}",
	})
	if err := os.Symlink("assets/app.css", filepath.Join(root, "shortcut.css")); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}
	if err := os.Symlink("assets", filepath.Join(root, "assets-link")); err != nil {
		t.Fatalf("Symlink(assets) error = %v", err)
	}

	handler := NewStaticSiteHandler("/", root, DefaultStaticIndex)
	for _, target := range []string{"/shortcut.css", "/assets-link/app.css"} {
		req := httptest.NewRequest(http.MethodGet, "https://public.example"+target, nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("%s status = %d, want 200", target, rec.Code)
		}
		if got := rec.Body.String(); got != "body{color:red}" {
			t.Fatalf("%s body = %q, want CSS content", target, got)
		}
	}
}
