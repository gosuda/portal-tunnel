package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/gosuda/portal-tunnel/v2/cmd/relay-server/policy"
	"github.com/gosuda/portal-tunnel/v2/portal"
	"github.com/gosuda/portal-tunnel/v2/types"
)

func postReputationVote(t *testing.T, api *RelayAPI, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, pathReputationVote, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "203.0.113.11:2000"
	rec := httptest.NewRecorder()
	api.Handler().ServeHTTP(rec, req)
	return rec
}

func TestReputationHTTPValidationAndRateLimit(t *testing.T) {
	api, _, err := newTestRelayAPI(t, "")
	if err != nil {
		t.Fatal(err)
	}
	if got := postReputationVote(t, api, `{"hostname":"demo.example.com","vote":"invalid"}`).Code; got != http.StatusBadRequest {
		t.Fatalf("invalid vote status = %d", got)
	}
	if got := postReputationVote(t, api, `{"hostname":"fake.example.com","vote":"up"}`).Code; got != http.StatusNotFound {
		t.Fatalf("unknown hostname status = %d", got)
	}
	var limited bool
	for range 22 {
		rec := postReputationVote(t, api, `{"hostname":"fake.example.com","vote":"up"}`)
		if rec.Code == http.StatusTooManyRequests {
			limited = rec.Header().Get("Retry-After") != ""
			break
		}
	}
	if !limited {
		t.Fatal("vote source limit was not enforced")
	}

	for _, id := range []string{"", "  "} {
		req := httptest.NewRequest(http.MethodPost, types.PathCommentsVote, strings.NewReader(`{"hostname":"demo.example.com","id":"`+id+`","vote":"up"}`))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "203.0.113.11:2000"
		rec := httptest.NewRecorder()
		api.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("missing comment ID: status=%d body=%s", rec.Code, rec.Body.String())
		}
	}

	read := httptest.NewRecorder()
	api.Handler().ServeHTTP(read, httptest.NewRequest(http.MethodGet, types.PathState, nil))
	var response types.APIEnvelope[publicStateResponse]
	if read.Code != http.StatusOK || json.Unmarshal(read.Body.Bytes(), &response) != nil || len(response.Data.Reputation) != 0 {
		t.Fatalf("directory response: status=%d body=%s", read.Code, read.Body.String())
	}
}

func TestPublicIdentityLeasesUsesServiceIdentity(t *testing.T) {
	const owner = "0x1111111111111111111111111111111111111111"
	first := types.Lease{Name: "first", Address: owner, Hostname: "first.example.com"}
	second := types.Lease{Name: "second", Address: owner, Hostname: "second.example.com"}
	canonical := types.Lease{Address: owner, Namespace: types.LocalTLSNamespaceV1, CanonicalHostname: "default." + owner[2:] + ".example.com"}
	hidden := first
	hidden.Address = "0x2222222222222222222222222222222222222222"
	hidden.Metadata.Hide = true
	policies := make([]types.PolicyLease, 0)
	for _, lease := range []types.Lease{hidden, first, first, second, canonical} {
		policies = append(policies, types.PolicyLease{
			Lease:       lease,
			IdentityKey: types.NewServiceIdentityKey(lease.Name, lease.Address).String(),
		})
	}
	leases := publicIdentityLeases([]types.Lease{first, second, canonical}, policies)
	got := make([]string, 0, len(leases))
	for _, lease := range leases {
		got = append(got, lease.IdentityKey)
	}
	want := []string{
		types.NewServiceIdentityKey(first.Name, owner).String(),
		types.NewServiceIdentityKey(second.Name, owner).String(),
		types.NewServiceIdentityKey(canonical.Name, owner).String(),
	}
	if !slices.Equal(got, want) {
		t.Fatalf("public identities = %v, want %v", got, want)
	}
}

func newTestRelayAPI(t *testing.T, policyJSON string) (*RelayAPI, *portal.Server, error) {
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
	api, err := NewRelayAPI(server, policy.NewStore(), nil, path, "admin-test", frontend, types.PolicySettings{})
	if err == nil {
		t.Cleanup(func() { _ = api.close() })
	}
	return api, server, err
}

func checkMigratedIdentitySnapshot(t *testing.T, api *RelayAPI) {
	t.Helper()
	if !api.policies.Snapshot().IsBanned(types.NewServiceIdentityKey("blocked", "addr")) || api.policies.Snapshot().Access(types.NewServiceIdentityKey("allowed", "addr")) != types.LeaseRoutable {
		t.Fatal("identity policy lost during migration")
	}
}

func checkMigratedPolicyFile(t *testing.T, path string) {
	t.Helper()
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
}

func checkRemovedIPEndpoints(t *testing.T, api *RelayAPI) {
	t.Helper()
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

func TestLegacyIPBanMigrationPreservesIdentityPolicy(t *testing.T) {
	api, server, err := newTestRelayAPI(t, `{"approval_mode":"manual","banned_ips":["127.0.0.1"],"banned_identity_keys":["blocked:addr"],"approved_identity_keys":["allowed:addr"]}`)
	if err != nil {
		t.Fatal(err)
	}
	checkMigratedIdentitySnapshot(t, api)
	checkMigratedPolicyFile(t, api.policyStatePath)
	restarted, err := NewRelayAPI(server, policy.NewStore(), nil, api.policyStatePath, "admin-test", api.frontendRoot.Name(), types.PolicySettings{})
	if err != nil {
		t.Fatalf("restart: %v", err)
	}
	t.Cleanup(func() { _ = restarted.close() })
	checkMigratedIdentitySnapshot(t, restarted)
	checkRemovedIPEndpoints(t, restarted)
}

func TestPolicyLoadNormalizesUnnormalizedIdentityKeys(t *testing.T) {
	api, server, err := newTestRelayAPI(t, `{"approval_mode":"manual","banned_identity_keys":["  Blocked : ADDR "],"approved_identity_keys":[" ALLOWED : addr "],"denied_identity_keys":["  DENIED : Key "],"identity_bps":{" Floody : Key ":1500,"floody:key":1500}}`)
	if err != nil {
		t.Fatal(err)
	}
	if !api.policies.Snapshot().IsBanned(types.NewServiceIdentityKey("blocked", "addr")) {
		t.Fatal("unnormalized ban not applied to canonical key")
	}
	if api.policies.Snapshot().Access(types.NewServiceIdentityKey("allowed", "addr")) != types.LeaseRoutable {
		t.Fatal("unnormalized approval not effective for canonical key")
	}
	if !api.policies.Snapshot().IsDenied(types.NewServiceIdentityKey("denied", "key")) {
		t.Fatal("unnormalized denial not applied to canonical key")
	}
	key := types.NewServiceIdentityKey("floody", "key")
	limits := api.policies.Snapshot().IdentityBPS
	if len(limits) != 1 || limits[key] != 1500 || server.BPSManager().IdentityBPS(key) != 1500 {
		t.Fatalf("identity_bps not normalized to canonical keys: %v", limits)
	}
}

func TestPolicyLoadRejectsMalformedIdentityKey(t *testing.T) {
	_, _, err := newTestRelayAPI(t, `{"identity_bps":{"no-separator":100}}`)
	if err == nil {
		t.Fatal("malformed identity key accepted at load")
	}
	if !strings.Contains(err.Error(), "identity_bps") || !strings.Contains(err.Error(), "no-separator") {
		t.Fatalf("load error %q must name the section and the offending key", err)
	}
}

func TestPolicyLoadRejectsConflictingIdentityBPSLimits(t *testing.T) {
	_, _, err := newTestRelayAPI(t, `{"identity_bps":{" Floody : Key ":1500,"floody:key":2000}}`)
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
	api, _, err := newTestRelayAPI(t, "")
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
