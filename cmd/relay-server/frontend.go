package main

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io/fs"
	"mime"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/gosuda/portal-tunnel/v2/types"
)

const embeddedFrontendRoot = "dist/app"

type frontendAsset struct {
	contentType string
	data        []byte
	gzipData    []byte
}

func resolveFrontendFS(frontendDir string) (fs.FS, error) {
	frontendDir = strings.TrimSpace(frontendDir)
	var frontendFS fs.FS
	frontendSource := "embedded frontend"

	if frontendDir == "" {
		var err error
		frontendFS, err = fs.Sub(embeddedDistFS, embeddedFrontendRoot)
		if err != nil {
			return nil, fmt.Errorf("open embedded frontend (run 'make build-frontend' before building the relay server): %w", err)
		}
	} else {
		absDir, err := filepath.Abs(frontendDir)
		if err != nil {
			return nil, fmt.Errorf("resolve frontend directory %q: %w", frontendDir, err)
		}
		frontendFS = os.DirFS(absDir)
		frontendSource = fmt.Sprintf("frontend directory %q", absDir)
	}

	entry, err := fs.Stat(frontendFS, "index.html")
	if err != nil {
		if frontendDir == "" {
			return nil, fmt.Errorf("embedded frontend is missing index.html; run 'make build-frontend' before building the relay server: %w", err)
		}
		return nil, fmt.Errorf("%s requires index.html: %w", frontendSource, err)
	}
	if !entry.Mode().IsRegular() {
		return nil, fmt.Errorf("%s requires a regular index.html", frontendSource)
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
	for _, prefix := range types.ReservedRootPrefixes {
		if requestPath == prefix || strings.HasPrefix(requestPath, prefix+"/") {
			http.NotFound(w, r)
			return
		}
	}

	assetPath := strings.TrimPrefix(requestPath, "/")
	if assetPath == "" {
		assetPath = "index.html"
	}
	asset, err := api.loadFrontendAsset(assetPath)
	if err != nil {
		// Missing static assets (paths with a recognized file extension) must
		// 404 instead of serving HTML with a wrong content type; only
		// client-route-looking paths fall back to the SPA entry point.
		if assetPath == "index.html" || mime.TypeByExtension(path.Ext(assetPath)) != "" {
			http.NotFound(w, r)
			return
		}
		assetPath = "index.html"
		asset, err = api.loadFrontendAsset(assetPath)
		if err != nil {
			http.NotFound(w, r)
			return
		}
	}

	data := asset.data
	w.Header().Set("Content-Type", asset.contentType)
	if len(asset.gzipData) > 0 {
		w.Header().Add("Vary", "Accept-Encoding")
		for value := range strings.SplitSeq(r.Header.Get("Accept-Encoding"), ",") {
			encoding, _, _ := strings.Cut(value, ";")
			if strings.EqualFold(strings.TrimSpace(encoding), "gzip") {
				data = asset.gzipData
				w.Header().Set("Content-Encoding", "gzip")
				break
			}
		}
	}
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

func (api *RelayAPI) loadFrontendAsset(assetPath string) (*frontendAsset, error) {
	if api.frontendCacheEnabled {
		if cached, ok := api.frontendCache.Load(assetPath); ok {
			return cached.(*frontendAsset), nil
		}
	}

	data, err := fs.ReadFile(api.frontendFS, assetPath)
	if err != nil {
		return nil, err
	}
	contentType := mime.TypeByExtension(path.Ext(assetPath))
	if contentType == "" {
		contentType = http.DetectContentType(data)
	}
	asset := &frontendAsset{contentType: contentType, data: data}
	compressible := strings.HasPrefix(contentType, "text/") ||
		strings.HasPrefix(contentType, "application/javascript") ||
		strings.HasPrefix(contentType, "application/json") ||
		strings.HasPrefix(contentType, "application/wasm") ||
		strings.HasPrefix(contentType, "application/xml") ||
		strings.HasPrefix(contentType, "image/svg+xml")
	if len(data) >= 1024 && compressible {
		var compressed bytes.Buffer
		writer, err := gzip.NewWriterLevel(&compressed, gzip.BestSpeed)
		if err != nil {
			return nil, err
		}
		if _, err := writer.Write(data); err != nil {
			_ = writer.Close()
			return nil, err
		}
		if err := writer.Close(); err != nil {
			return nil, err
		}
		asset.gzipData = compressed.Bytes()
	}
	if !api.frontendCacheEnabled {
		return asset, nil
	}
	actual, _ := api.frontendCache.LoadOrStore(assetPath, asset)
	return actual.(*frontendAsset), nil
}
