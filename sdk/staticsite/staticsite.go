// Package staticsite serves local static sites with SPA fallback and root-confined file access.
package staticsite

import (
	"errors"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/gosuda/portal-tunnel/v2/utils"
)

// Handler serves one static site from the directory pinned by NewHandler.
type Handler struct {
	prefix   string
	index    string
	root     *os.Root
	closeErr error
	close    sync.Once
}

// NewHandler opens root once and serves it with SPA/CSR fallback: a concrete
// file is served as-is, while the root and any unknown path return index. File
// access stays within the opened root even when its pathname is later replaced.
// The caller owns the handler and must call Close after serving has stopped.
func NewHandler(prefix, root, index string) (*Handler, error) {
	dir, index, err := utils.OpenStaticSite(root, index)
	if err != nil {
		return nil, err
	}
	return &Handler{prefix: prefix, index: index, root: dir}, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	rel, ok := utils.StaticSiteRequestPath(h.prefix, req.URL.Path)
	if !ok || h.root == nil {
		http.NotFound(w, req)
		return
	}
	if serveStaticSiteFile(w, req, h.root, rel) {
		return
	}
	if served, err := serveStaticFile(w, req, h.root, "/"+h.index); err != nil || !served {
		http.NotFound(w, req)
	}
}

// Close releases the pinned directory. It is safe to call more than once.
func (h *Handler) Close() error {
	if h == nil {
		return nil
	}
	h.close.Do(func() {
		if h.root != nil {
			h.closeErr = h.root.Close()
		}
	})
	return h.closeErr
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
