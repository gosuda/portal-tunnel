package utils

import (
	"os"
	"path/filepath"
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
