package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gosuda/portal-tunnel/v2/portal"
)

func TestLegacyIPBanMigrationPreservesIdentityPolicy(t *testing.T) {
	dir := t.TempDir()
	server, err := portal.NewServer(portal.ServerConfig{PortalURL: "https://localhost", StateDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(path, []byte(`{"approval_mode":"manual","banned_ips":["127.0.0.1"],"banned_identity_keys":["blocked"],"approved_identity_keys":["allowed"]}`), 0600); err != nil {
		t.Fatal(err)
	}
	frontend := t.TempDir()
	if err := os.WriteFile(filepath.Join(frontend, "index.html"), []byte("portal"), 0600); err != nil {
		t.Fatal(err)
	}
	api, err := NewRelayAPI(server, path, "admin-test", frontend, false)
	if err != nil {
		t.Fatal(err)
	}
	if !server.PolicyRuntime().IsIdentityBanned("blocked") || !server.PolicyRuntime().IsIdentityRoutable("allowed") {
		t.Fatal("identity policy lost during migration")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	if _, ok := fields["banned_ips"]; ok {
		t.Fatal("legacy bans remain persisted")
	}
	if _, err := NewRelayAPI(server, path, "admin-test", frontend, false); err != nil {
		t.Fatalf("restart: %v", err)
	}
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		req := httptest.NewRequest(method, "/api/policy/ips", nil)
		req.Header.Set("Authorization", "Bearer admin-test")
		response := httptest.NewRecorder()
		api.Handler().ServeHTTP(response, req)
		if response.Code != http.StatusNotFound {
			t.Fatalf("removed IP policy endpoint: %d", response.Code)
		}
	}
}
