package cache

import (
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gosuda/portal-tunnel/v2/utils"
)

// Serve returns false for origin fallback. Disk pins are confined to this
// method, so the caller never retains cached bytes while contacting an origin.
func (c *Manager) Serve(w http.ResponseWriter, req *http.Request, host string) bool {
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		return false
	}
	site := c.acquire(host)
	if site == nil {
		return false
	}
	defer c.release(site)
	rel, valid := utils.StaticSiteRequestPath("/", req.URL.Path)
	if !valid {
		http.NotFound(w, req)
		return true
	}
	file, found := site.files[strings.TrimPrefix(rel, "/")]
	if !found {
		file = site.files[site.index]
	}
	input, err := os.OpenInRoot(site.dir, file.SHA256)
	if err != nil {
		c.discard(site)
		return false
	}
	defer input.Close()
	info, err := input.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != file.Size {
		c.discard(site)
		return false
	}
	w.Header().Set("ETag", `"`+file.SHA256+`"`)
	w.Header().Set("Cache-Control", "no-cache")
	reader := &siteReader{File: input, size: info.Size()}
	http.ServeContent(w, req, file.Path, time.Time{}, reader)
	if reader.failed {
		c.discard(site)
	}
	return true
}

func (c *Manager) discard(site *cachedSite) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// A failed reader of an older snapshot cannot invalidate its replacement.
	if c.entries[site.host] == site {
		c.retireLocked(site)
	}
}

// siteReader observes failures after headers have been written: the response
// cannot fall back at that point, but the next probe must request a new upload.
type siteReader struct {
	*os.File
	failed         bool
	position, size int64
}

func (r *siteReader) Read(p []byte) (int, error) {
	n, err := r.File.Read(p)
	r.position += int64(n)
	short := err == io.EOF && r.position < r.size
	if short || (err != nil && err != io.EOF) {
		r.failed = true
	}
	return n, err
}

func (r *siteReader) Seek(offset int64, whence int) (int64, error) {
	n, err := r.File.Seek(offset, whence)
	if err != nil {
		r.failed = true
	} else {
		r.position = n
	}
	return n, err
}
