package utils

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// DefaultStaticIndex is the SPA entry file served for a directory and for any
// unknown path under a static site.
const DefaultStaticIndex = "index.html"

func EnsureParentDir(path string) error {
	dir := filepath.Dir(strings.TrimSpace(path))
	if dir == "." {
		return nil
	}
	return os.MkdirAll(dir, 0o700)
}

func FileExists(path string) bool {
	path = strings.TrimSpace(path)
	if path == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}

func WriteFileAtomic(path string, data []byte, mode os.FileMode) error {
	path = strings.TrimSpace(path)
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}

func ReadJSONFile(path string, out any) error {
	raw, err := os.ReadFile(strings.TrimSpace(path))
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, out)
}

func ReadJSONFileIfExists(path string, out any) (bool, error) {
	err := ReadJSONFile(path, out)
	switch {
	case err == nil:
		return true, nil
	case os.IsNotExist(err):
		return false, nil
	default:
		return false, err
	}
}

func WriteJSONFile(path string, payload any, mode os.FileMode) error {
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	if err := EnsureParentDir(path); err != nil {
		return err
	}
	return WriteFileAtomic(path, data, mode)
}

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
	return p, true
}

// NewStaticSiteHandler serves files under root with SPA/CSR fallback: a
// concrete file is served as-is, while the root and any unknown path return
// index. File access stays within root even when a path contains symlinks.
func NewStaticSiteHandler(prefix, root, index string) http.Handler {
	if strings.TrimSpace(index) == "" {
		index = DefaultStaticIndex
	}
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		rel, ok := StaticSiteRequestPath(prefix, req.URL.Path)
		if !ok {
			http.NotFound(w, req)
			return
		}
		dir, err := os.OpenRoot(root)
		if err != nil {
			http.NotFound(w, req)
			return
		}
		defer dir.Close()

		if rel != "/" {
			served, err := serveStaticFile(w, req, dir, rel)
			if err != nil {
				http.NotFound(w, req)
				return
			}
			if served {
				return
			}
		}
		if served, err := serveStaticFile(w, req, dir, "/"+index); err != nil || !served {
			http.NotFound(w, req)
		}
	})
}

func containsDotDot(v string) bool {
	if !strings.Contains(v, "..") {
		return false
	}
	return slices.Contains(strings.FieldsFunc(v, func(r rune) bool { return r == '/' || r == '\\' }), "..")
}

func serveStaticFile(w http.ResponseWriter, req *http.Request, dir *os.Root, rel string) (bool, error) {
	f, err := dir.Open(strings.TrimPrefix(rel, "/"))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return false, err
	}
	if info.IsDir() {
		return false, nil
	}
	http.ServeContent(w, req, info.Name(), info.ModTime(), f)
	return true, nil
}
