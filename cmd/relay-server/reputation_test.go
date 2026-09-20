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

	"github.com/gosuda/portal-tunnel/v2/portal"
	"github.com/gosuda/portal-tunnel/v2/types"
)

func newTestReputationStore(t *testing.T) *ReputationStore {
	t.Helper()
	store, err := newReputationStore(filepath.Join(t.TempDir(), reputationFilename))
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func testLeases(names ...string) []types.PolicyLease {
	leases := make([]types.PolicyLease, 0, len(names))
	for _, name := range names {
		leases = append(leases, types.PolicyLease{Lease: types.Lease{Hostname: name}, IdentityKey: "id:" + name})
	}
	return leases
}

func TestReputationVoteSwitchAndRestart(t *testing.T) {
	store := newTestReputationStore(t)
	first, cookie, err := store.castVote("demo.example.com", "id:demo.example.com", voteUp, "", "203.0.113.10")
	if err != nil || first.Up != 1 || cookie == "" {
		t.Fatalf("first vote = %+v, cookie=%q, err=%v", first, cookie, err)
	}
	same, _, err := store.castVote("demo.example.com", "id:demo.example.com", voteUp, cookie, "203.0.113.10")
	if err != nil || same.Up != 1 {
		t.Fatalf("same vote changed state: %+v, err=%v", same, err)
	}
	switched, _, err := store.castVote("demo.example.com", "id:demo.example.com", voteDown, cookie, "203.0.113.10")
	if err != nil || switched.Up != 0 || switched.Down != 1 || switched.ViewerVote != voteDown {
		t.Fatalf("switched vote = %+v, err=%v", switched, err)
	}
	reloaded, err := newReputationStore(store.path)
	if err != nil {
		t.Fatal(err)
	}
	if got := reloaded.summaries(reloaded.viewerHashFor(cookie), testLeases("demo.example.com"))[0]; got.Down != 1 || got.ViewerVote != voteDown {
		t.Fatalf("reloaded vote = %+v", got)
	}
}

func TestReputationDirectoryProjectsLiveHostsAndViewerVote(t *testing.T) {
	store := newTestReputationStore(t)
	_, cookie, err := store.castVote("voted.example.com", "id:voted.example.com", voteUp, "", "203.0.113.10")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.castVote("old.example.com", "id:old.example.com", voteUp, cookie, "203.0.113.10"); err != nil {
		t.Fatal(err)
	}
	summaries := store.summaries(store.viewerHashFor(cookie), testLeases("voted.example.com", "old.example.com", "fresh.example.com"))
	want := []reputationSummary{
		{Hostname: "fresh.example.com"},
		{Hostname: "old.example.com", Up: 1, Down: 0, Total: 1, ViewerVote: voteUp},
		{Hostname: "voted.example.com", Up: 1, Down: 0, Total: 1, ViewerVote: voteUp},
	}
	if !slices.Equal(summaries, want) {
		t.Fatalf("directory rows = %+v, want %+v", summaries, want)
	}
}

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
	api, err := NewRelayAPI(server, filepath.Join(dir, types.RelayPolicyFilename), "admin-test", frontend, false)
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
	for i := 0; i < 22; i++ {
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
