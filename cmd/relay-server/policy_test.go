package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gosuda/portal-tunnel/v2/portal"
	"github.com/gosuda/portal-tunnel/v2/types"
)

// newPolicyAPI builds a RelayAPI over an optional policy.json payload and
// returns the server so tests can assert on the applied runtime state.
func newPolicyAPI(t *testing.T, policyJSON string) (*RelayAPI, *portal.Server, error) {
	t.Helper()
	dir := t.TempDir()
	server, err := portal.NewServer(portal.ServerConfig{PortalURL: "https://localhost", StateDir: dir})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	path := filepath.Join(dir, types.RelayPolicyFilename)
	if policyJSON != "" {
		if err := os.WriteFile(path, []byte(policyJSON), 0600); err != nil {
			t.Fatal(err)
		}
	}
	frontend := t.TempDir()
	if err := os.WriteFile(filepath.Join(frontend, "index.html"), []byte("portal"), 0600); err != nil {
		t.Fatal(err)
	}
	api, err := NewRelayAPI(server, path, "admin-test", frontend, false, defaultReputationConfig())
	return api, server, err
}

func TestLegacyIPBanMigrationPreservesIdentityPolicy(t *testing.T) {
	dir := t.TempDir()
	server, err := portal.NewServer(portal.ServerConfig{PortalURL: "https://localhost", StateDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, types.RelayPolicyFilename)
	if err := os.WriteFile(path, []byte(`{"approval_mode":"manual","banned_ips":["127.0.0.1"],"banned_identity_keys":["blocked:addr"],"approved_identity_keys":["allowed:addr"]}`), 0600); err != nil {
		t.Fatal(err)
	}
	frontend := t.TempDir()
	if err := os.WriteFile(filepath.Join(frontend, "index.html"), []byte("portal"), 0600); err != nil {
		t.Fatal(err)
	}
	api, err := NewRelayAPI(server, path, "admin-test", frontend, false, defaultReputationConfig())
	if err != nil {
		t.Fatal(err)
	}
	if !server.PolicyRuntime().IsIdentityBanned("blocked:addr") || !server.PolicyRuntime().IsIdentityRoutable("allowed:addr") {
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
	if _, err := NewRelayAPI(server, path, "admin-test", frontend, false, defaultReputationConfig()); err != nil {
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

func TestPolicyLoadNormalizesUnnormalizedIdentityKeys(t *testing.T) {
	_, server, err := newPolicyAPI(t, `{"approval_mode":"manual","banned_identity_keys":["  Blocked : ADDR "],"approved_identity_keys":[" ALLOWED : addr "],"denied_identity_keys":["  DENIED : Key "],"identity_bps":{" Floody : Key ":1500,"floody:key":1500}}`)
	if err != nil {
		t.Fatal(err)
	}
	runtime := server.PolicyRuntime()
	if !runtime.IsIdentityBanned("blocked:addr") {
		t.Fatal("unnormalized ban not applied to canonical key")
	}
	if !runtime.IsIdentityRoutable("allowed:addr") {
		t.Fatal("unnormalized approval not effective for canonical key")
	}
	if !runtime.IsIdentityDenied("denied:key") {
		t.Fatal("unnormalized denial not applied to canonical key")
	}
	limits := runtime.BPSManager().IdentityBPSLimits()
	if len(limits) != 1 || limits["floody:key"] != 1500 {
		t.Fatalf("identity_bps not normalized to canonical keys: %v", limits)
	}
}

func TestPolicyLoadRejectsMalformedIdentityKey(t *testing.T) {
	_, _, err := newPolicyAPI(t, `{"identity_bps":{"no-separator":100}}`)
	if err == nil {
		t.Fatal("malformed identity key accepted at load")
	}
	if !strings.Contains(err.Error(), "identity_bps") || !strings.Contains(err.Error(), "no-separator") {
		t.Fatalf("load error %q must name the section and the offending key", err)
	}
}

func TestPolicyLoadRejectsConflictingIdentityBPSLimits(t *testing.T) {
	_, _, err := newPolicyAPI(t, `{"identity_bps":{" Floody : Key ":1500,"floody:key":2000}}`)
	if err == nil {
		t.Fatal("conflicting canonical identity_bps limits accepted at load")
	}
	// Either raw spelling may surface as the conflicting entry depending on
	// map iteration order; the canonical key is named either way.
	if !strings.Contains(err.Error(), "identity_bps") || !strings.Contains(err.Error(), "floody:key") {
		t.Fatalf("load error %q must name the section and the canonical key", err)
	}
}

func TestAdminMutationRejectsMalformedIdentityKey(t *testing.T) {
	api, _, err := newPolicyAPI(t, "")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, types.PathPolicyLeases, strings.NewReader(`{"identity_key":"no-separator","is_banned":true}`))
	req.Header.Set("Authorization", "Bearer admin-test")
	response := httptest.NewRecorder()
	api.Handler().ServeHTTP(response, req)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("malformed identity key mutation: %d, want 400", response.Code)
	}
}
