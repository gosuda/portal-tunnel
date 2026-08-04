package main

import (
	"fmt"
	"io/fs"
	"mime"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
)

const embeddedFrontendRoot = "dist/app"

func resolveFrontendFS(frontendDir string) (fs.FS, error) {
	frontendDir = strings.TrimSpace(frontendDir)
	if frontendDir == "" {
		frontendFS, err := fs.Sub(embeddedDistFS, embeddedFrontendRoot)
		if err != nil {
			return nil, fmt.Errorf("open embedded frontend: %w", err)
		}
		return frontendFS, nil
	}

	absDir, err := filepath.Abs(frontendDir)
	if err != nil {
		return nil, fmt.Errorf("resolve frontend directory %q: %w", frontendDir, err)
	}
	frontendFS := os.DirFS(absDir)
	entry, err := fs.Stat(frontendFS, "index.html")
	if err != nil {
		return nil, fmt.Errorf("frontend directory %q requires index.html: %w", absDir, err)
	}
	if !entry.Mode().IsRegular() {
		return nil, fmt.Errorf("frontend directory %q requires a regular index.html", absDir)
	}
	return frontendFS, nil
}

func (api *RelayAPI) serveFrontend(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", http.MethodGet+", "+http.MethodHead)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	requestPath := path.Clean("/" + strings.TrimSpace(r.URL.Path))
	if reservedPortalPath(requestPath) {
		http.NotFound(w, r)
		return
	}

	assetPath := strings.TrimPrefix(requestPath, "/")
	if assetPath == "" || assetPath == "." {
		assetPath = "index.html"
	}
	data, err := fs.ReadFile(api.frontendFS, assetPath)
	if err != nil {
		if path.Ext(assetPath) != "" {
			http.NotFound(w, r)
			return
		}
		assetPath = "index.html"
		data, err = fs.ReadFile(api.frontendFS, assetPath)
		if err != nil {
			http.NotFound(w, r)
			return
		}
	}

	contentType := mime.TypeByExtension(path.Ext(assetPath))
	if contentType == "" {
		contentType = http.DetectContentType(data)
	}
	w.Header().Set("Content-Type", contentType)
	if assetPath == "index.html" {
		w.Header().Set("Cache-Control", "no-cache, must-revalidate")
	} else {
		w.Header().Set("Cache-Control", "public, max-age=3600")
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = w.Write(data)
	}
}

func reservedPortalPath(requestPath string) bool {
	for _, prefix := range []string{"/api", "/sdk", "/discovery", "/v1"} {
		if requestPath == prefix || strings.HasPrefix(requestPath, prefix+"/") {
			return true
		}
	}
	return false
}
