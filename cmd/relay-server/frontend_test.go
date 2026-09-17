package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"
)

// TestServeFrontendFallsBackForDottedClientRoute verifies that unknown client-side
// routes (e.g. "/users/jane.doe") return the SPA entry file instead of 404.
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

// TestServeFrontendReturnsNotFoundForMissingAsset verifies that a request for
// a non-existent file asset (e.g. a stale hashed asset) returns 404, not the
// SPA index, so the browser does not load stale content.
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

// TestServeFrontendDoesNotHandleReservedPortalPath verifies that paths reserved
// for the relay API (e.g. "/api/...") are not consumed by the frontend handler
// and fall through to the API mux, which returns 404.
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
