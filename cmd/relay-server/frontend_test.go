package main

import (
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

func TestServeFrontendFallsBackForDottedClientRoute(t *testing.T) {
	api := &RelayAPI{frontendFS: fstest.MapFS{
		"index.html": {Data: []byte("<html>portal</html>")},
	}}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/users/jane.doe", nil)

	api.serveFrontend(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}
	if body := recorder.Body.String(); body != "<html>portal</html>" {
		t.Fatalf("body = %q, want SPA index", body)
	}
}

func TestServeFrontendDoesNotHandleReservedPortalPath(t *testing.T) {
	api := &RelayAPI{frontendFS: fstest.MapFS{
		"index.html": {Data: []byte("<html>portal</html>")},
	}}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/missing", nil)

	api.serveFrontend(recorder, request)

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusNotFound)
	}
}

func TestServeFrontendCachesAndCompressesAssets(t *testing.T) {
	source := strings.Repeat("const portal = true;\n", 128)
	api := &RelayAPI{frontendFS: fstest.MapFS{
		"index.html":    {Data: []byte("<html>portal</html>")},
		"assets/app.js": {Data: []byte(source)},
	}}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/assets/app.js", nil)
	request.Header.Set("Accept-Encoding", "gzip")

	api.serveFrontend(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}
	if encoding := recorder.Header().Get("Content-Encoding"); encoding != "gzip" {
		t.Fatalf("Content-Encoding = %q, want gzip", encoding)
	}
	reader, err := gzip.NewReader(recorder.Body)
	if err != nil {
		t.Fatalf("open gzip response: %v", err)
	}
	decompressed, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read gzip response: %v", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatalf("close gzip response: %v", err)
	}
	if string(decompressed) != source {
		t.Fatal("decompressed response did not match source asset")
	}
}
