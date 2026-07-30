package utils

import (
	"fmt"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// DefaultStaticIndex is the SPA entry file served for a directory and for any
// unknown path under a static site.
const DefaultStaticIndex = "index.html"

// ResolveStaticSite turns a user-supplied path into a static site root
// directory and its SPA entry file. A directory serves DefaultStaticIndex; a
// file serves its parent directory with that file as the entry. The entry file
// must exist. Callers add their own flag or field context to the error.
func ResolveStaticSite(input string) (root string, index string, err error) {
	abs, err := filepath.Abs(strings.TrimSpace(input))
	if err != nil {
		return "", "", err
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", "", err
	}
	if info.IsDir() {
		root, index = abs, DefaultStaticIndex
	} else {
		root, index = filepath.Dir(abs), filepath.Base(abs)
	}

	indexInfo, err := os.Stat(filepath.Join(root, index))
	if err != nil {
		return "", "", fmt.Errorf("entry file %q not found: %w", index, err)
	}
	if indexInfo.IsDir() {
		return "", "", fmt.Errorf("entry %q is a directory", index)
	}
	return root, index, nil
}

// StaticSiteRequestPath strips the route prefix from a request path and returns
// a clean, root-relative path. It reports false for parent-directory traversal.
func StaticSiteRequestPath(prefix, urlPath string) (string, bool) {
	// Reject before normalizing: NormalizeURLPath cleans ".." away, so a check
	// after it would never fire.
	if containsDotDot(urlPath) {
		return "", false
	}

	p := NormalizeURLPath(urlPath)
	if prefix != "/" {
		switch {
		case p == prefix:
			p = "/"
		case strings.HasPrefix(p, prefix+"/"):
			p = strings.TrimPrefix(p, prefix)
		}
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return path.Clean(p), true
}

// NewStaticSiteHandler serves files under root with SPA/CSR fallback: a
// concrete file is served as-is, while the root and any unknown path return
// index. http.Dir already refuses paths that escape the root directory.
func NewStaticSiteHandler(prefix, root, index string) http.Handler {
	if strings.TrimSpace(index) == "" {
		index = DefaultStaticIndex
	}
	dir := http.Dir(root)
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		rel, ok := StaticSiteRequestPath(prefix, req.URL.Path)
		if !ok {
			http.NotFound(w, req)
			return
		}
		if rel != "/" && serveStaticFile(w, req, dir, rel) {
			return
		}
		serveStaticIndex(w, req, dir, index)
	})
}

func containsDotDot(v string) bool {
	if !strings.Contains(v, "..") {
		return false
	}
	for _, ent := range strings.FieldsFunc(v, func(r rune) bool { return r == '/' || r == '\\' }) {
		if ent == ".." {
			return true
		}
	}
	return false
}

func serveStaticFile(w http.ResponseWriter, req *http.Request, dir http.FileSystem, rel string) bool {
	f, err := dir.Open(rel)
	if err != nil {
		return false
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || info.IsDir() {
		return false
	}
	http.ServeContent(w, req, info.Name(), info.ModTime(), f)
	return true
}

func serveStaticIndex(w http.ResponseWriter, req *http.Request, dir http.FileSystem, index string) {
	f, err := dir.Open("/" + index)
	if err != nil {
		http.NotFound(w, req)
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || info.IsDir() {
		http.NotFound(w, req)
		return
	}
	http.ServeContent(w, req, info.Name(), info.ModTime(), f)
}
