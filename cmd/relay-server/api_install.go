package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	portaltunnel "github.com/gosuda/portal-tunnel/v2"
	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/installer"
	"github.com/gosuda/portal-tunnel/v2/types"
)

func installContentType(filename string) string {
	if strings.HasSuffix(filename, ".wasm") {
		return "application/wasm"
	}
	if strings.HasSuffix(filename, ".js") {
		return "text/javascript; charset=utf-8"
	}
	return "application/octet-stream"
}

func serveInstallBinary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", http.MethodGet+", "+http.MethodHead)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	slug := strings.Trim(strings.TrimPrefix(r.URL.Path, types.PathInstallBinPrefix), "/")
	checksumRequest := strings.HasSuffix(slug, ".sha256")
	if checksumRequest {
		slug = strings.TrimSuffix(slug, ".sha256")
	}

	filename, ok := installer.AssetFilename(slug)
	if !ok {
		http.NotFound(w, r)
		return
	}
	requestedVersion := strings.TrimSpace(r.URL.Query().Get("version"))
	if requestedVersion != "" && requestedVersion != types.ReleaseVersion {
		http.Error(w, "artifact version does not match this relay", http.StatusConflict)
		return
	}
	data, err := embeddedDistFS.ReadFile("dist/tunnel/" + filename)
	if err != nil {
		releasePath := "/latest/download/"
		if requestedVersion != "" {
			releasePath = "/download/" + url.PathEscape(types.ReleaseVersion) + "/"
		}
		redirectURL := types.OfficialReleaseBaseURL + releasePath + filename
		if checksumRequest {
			redirectURL += ".sha256"
		}
		http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
		return
	}
	sum := sha256.Sum256(data)
	checksumHex := hex.EncodeToString(sum[:])

	if checksumRequest {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if r.Method == http.MethodGet {
			_, _ = fmt.Fprintf(w, "%s  %s\n", checksumHex, filename)
		}
		return
	}

	contentType := installContentType(filename)
	w.Header().Set("Content-Type", contentType)
	if contentType == "application/octet-stream" {
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	}
	if requestedVersion == types.ReleaseVersion {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		w.Header().Set("Cache-Control", "no-cache")
	}
	w.Header().Set("ETag", `"`+checksumHex+`"`)
	w.Header().Set("X-Checksum-Sha256", checksumHex)
	if r.Method == http.MethodGet {
		_, _ = w.Write(data)
	}
}

func serveInstallScript(w http.ResponseWriter, r *http.Request, portalURL string, isWindows bool) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", http.MethodGet+", "+http.MethodHead)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	script, filename, contentType, err := installer.RelayScript(portalURL, isWindows)
	if err != nil {
		http.Error(w, "failed to render install script", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("inline; filename=%q", filename))
	if r.Method == http.MethodGet {
		_, _ = w.Write([]byte(script))
	}
}

func serveLLMs(w http.ResponseWriter, r *http.Request, portalURL string) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", http.MethodGet+", "+http.MethodHead)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if r.Method == http.MethodHead {
		return
	}

	body := strings.ReplaceAll(string(portaltunnel.LLMsTXT), "%s", portalURL)
	_, _ = w.Write([]byte(body))
}
