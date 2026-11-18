package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestServeLLMs(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/llms.txt", nil)
	rec := httptest.NewRecorder()

	serveLLMs(rec, req, "https://relay.example.com")

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "irm https://relay.example.com/api/install.ps1 | iex;") {
		t.Errorf("expected llms.txt to include semicolon after iex, got:\n%s", body)
	}
}

func TestServeInstallScript_NoCRLF(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/install.sh", nil)
	rec := httptest.NewRecorder()

	serveInstallScript(rec, req, "https://relay.example.com", false)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec.Code)
	}
	if rec.Header().Get("Content-Type") != "text/x-shellscript" {
		t.Errorf("unexpected Content-Type: %q", rec.Header().Get("Content-Type"))
	}
	if strings.Contains(rec.Body.String(), "\r") {
		t.Errorf("install.sh output contains carriage returns (\\r)")
	}
}
