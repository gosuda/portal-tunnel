// Package staticsite serves local static sites with SPA fallback and root-confined file access.
package staticsite

import (
	"errors"
	"net/http"
	"os"
	"strings"

	"github.com/gosuda/portal-tunnel/v2/utils"
)

// NewHandler serves files under root with SPA/CSR fallback: a
// concrete file is served as-is, while the root and any unknown path return
// index. File access stays within root even when a path contains symlinks.
func NewHandler(prefix, root, index string) http.Handler {
	if strings.TrimSpace(index) == "" {
		index = utils.DefaultStaticIndex
	}
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		rel, ok := utils.StaticSiteRequestPath(prefix, req.URL.Path)
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

		if serveStaticSiteFile(w, req, dir, rel) {
			return
		}
		if served, err := serveStaticFile(w, req, dir, "/"+index); err != nil || !served {
			http.NotFound(w, req)
		}
	})
}

func serveStaticSiteFile(w http.ResponseWriter, req *http.Request, dir *os.Root, rel string) bool {
	if rel == "/" {
		return false
	}
	served, err := serveStaticFile(w, req, dir, rel)
	if err != nil {
		http.NotFound(w, req)
		return true
	}
	return served
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
