package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gosuda/portal-tunnel/v2/cmd/relay-server/policy"
	"github.com/gosuda/portal-tunnel/v2/portal"
	"github.com/gosuda/portal-tunnel/v2/types"
)

func newTestReputationAPI(t *testing.T) *RelayAPI {
	t.Helper()
	dir := t.TempDir()
	server, err := portal.NewServer(portal.ServerConfig{PortalURL: "https://localhost", StateDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	frontend := t.TempDir()
	if err := os.WriteFile(filepath.Join(frontend, "index.html"), []byte("portal"), 0o600); err != nil {
		t.Fatal(err)
	}
	api, err := NewRelayAPI(server, policy.NewAccess(), nil, filepath.Join(dir, types.RelayPolicyFilename), "admin-test", frontend, false)
	if err != nil {
		t.Fatal(err)
	}
	return api
}

func TestReputationHTTPValidationAndRateLimit(t *testing.T) {
	api := newTestReputationAPI(t)
	post := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, pathReputationVote, strings.NewReader(body))
		req.RemoteAddr = "203.0.113.11:2000"
		rec := httptest.NewRecorder()
		api.Handler().ServeHTTP(rec, req)
		return rec
	}
	if got := post(`{"hostname":"demo.example.com","vote":"invalid"}`).Code; got != http.StatusBadRequest {
		t.Fatalf("invalid vote status = %d", got)
	}
	if got := post(`{"hostname":"fake.example.com","vote":"up"}`).Code; got != http.StatusNotFound {
		t.Fatalf("unknown hostname status = %d", got)
	}
	var limited bool
	for range 22 {
		rec := post(`{"hostname":"fake.example.com","vote":"up"}`)
		if rec.Code == http.StatusTooManyRequests {
			limited = rec.Header().Get("Retry-After") != ""
			break
		}
	}
	if !limited {
		t.Fatal("vote source limit was not enforced")
	}
	read := httptest.NewRecorder()
	api.Handler().ServeHTTP(read, httptest.NewRequest(http.MethodGet, types.PathState, nil))
	var response types.APIEnvelope[publicStateResponse]
	if read.Code != http.StatusOK || json.Unmarshal(read.Body.Bytes(), &response) != nil || len(response.Data.Reputation) != 0 {
		t.Fatalf("directory response: status=%d body=%s", read.Code, read.Body.String())
	}
}
