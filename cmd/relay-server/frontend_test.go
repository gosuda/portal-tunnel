package main

import (
	"net/http"
	"net/http/httptest"
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

func TestServeFrontendReturnsNotFoundForMissingAsset(t *testing.T) {
	api := &RelayAPI{frontendFS: fstest.MapFS{
		"index.html": {Data: []byte("<html>portal</html>")},
	}}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/assets/app-oldhash.js", nil)

	api.serveFrontend(recorder, request)

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusNotFound)
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
