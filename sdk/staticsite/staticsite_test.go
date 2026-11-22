package staticsite_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gosuda/portal-tunnel/v2/sdk/staticsite"
	"github.com/gosuda/portal-tunnel/v2/utils"
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

func newHandler(t *testing.T, prefix, root, index string) *staticsite.Handler {
	t.Helper()
	handler, err := staticsite.NewHandler(prefix, root, index)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = handler.Close() })
	return handler
}

func TestStaticSiteHandlerServesConcreteFile(t *testing.T) {
	t.Parallel()

	root := newStaticSite(t, map[string]string{
		"index.html":     "<html>index</html>",
		"assets/app.css": "body{color:red}",
	})
	handler := newHandler(t, "/", root, utils.DefaultStaticIndex)

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
	handler := newHandler(t, "/", root, "")

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

func TestStaticSiteHandlerRejectsTraversal(t *testing.T) {
	t.Parallel()

	root := newStaticSite(t, map[string]string{"index.html": "<html>index</html>"})
	// A secret file one level above the served root must never be reachable.
	secret := filepath.Join(filepath.Dir(root), "secret.txt")
	if err := os.WriteFile(secret, []byte("TOP-SECRET"), 0o644); err != nil {
		t.Fatalf("WriteFile(secret) error = %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(secret) })

	handler := newHandler(t, "/", root, utils.DefaultStaticIndex)

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

	root := createStaticOutOfRootFixture(t)
	handler := newHandler(t, "/", root, utils.DefaultStaticIndex)
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

func createStaticOutOfRootFixture(t *testing.T) string {
	t.Helper()
	parent := t.TempDir()
	root := filepath.Join(parent, "site")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatalf("Mkdir(root) error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, utils.DefaultStaticIndex), []byte("<html>spa</html>"), 0o644); err != nil {
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
	return root
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
	if err := os.Symlink(secret, filepath.Join(root, utils.DefaultStaticIndex)); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	if handler, err := staticsite.NewHandler("/", root, utils.DefaultStaticIndex); err == nil {
		_ = handler.Close()
		t.Fatal("NewHandler() error = nil, want rejection of an index outside the static root")
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

	handler := newHandler(t, "/", root, utils.DefaultStaticIndex)
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

func TestStaticSiteHandlerPinsOpenedRoot(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "site")
	replacement := filepath.Join(parent, "replacement")
	for path, content := range map[string]string{
		root:        "original content",
		replacement: "replacement secret",
	} {
		if err := os.Mkdir(path, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, utils.DefaultStaticIndex), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	handler, err := staticsite.NewHandler("/", root, utils.DefaultStaticIndex)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = handler.Close() })
	if err := os.Rename(root, filepath.Join(parent, "opened-site")); err != nil {
		t.Skipf("cannot rename opened static root: %v", err)
	}
	if err := os.Rename(replacement, root); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://public.example/", nil))
	if rec.Code != http.StatusOK || rec.Body.String() != "original content" {
		t.Fatalf("replacement root served: status = %d, body = %q", rec.Code, rec.Body.String())
	}
}
