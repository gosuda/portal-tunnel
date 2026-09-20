package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal"
	"github.com/gosuda/portal-tunnel/v2/portal/policy"
	"github.com/gosuda/portal-tunnel/v2/types"
)

func newTestReputationStore(t *testing.T) *ReputationStore {
	t.Helper()
	store, err := newReputationStore(filepath.Join(t.TempDir(), reputationFilename), defaultReputationConfig())
	if err != nil {
		t.Fatal(err)
	}
	store.mintLimiter = policy.NewSourceLimiter(1000, 1000, 0, 0)
	return store
}

func TestReputationVoteSwitchAndRestart(t *testing.T) {
	store := newTestReputationStore(t)
	live := map[string]bool{"demo.example.com": true}
	first, cookie, err := store.castVote("demo.example.com", voteUp, "", "203.0.113.10", live)
	if err != nil || first.Up != 1 || cookie == "" {
		t.Fatalf("first vote = %+v, cookie=%q, err=%v", first, cookie, err)
	}
	seen := store.state.Hostnames["demo.example.com"].LastSeenAt
	same, _, err := store.castVote("demo.example.com", voteUp, cookie, "203.0.113.10", live)
	if err != nil || same.Up != 1 || !store.state.Hostnames["demo.example.com"].LastSeenAt.Equal(seen) {
		t.Fatalf("same vote changed state: %+v, err=%v", same, err)
	}
	switched, _, err := store.castVote("demo.example.com", voteDown, cookie, "203.0.113.10", live)
	if err != nil || switched.Up != 0 || switched.Down != 1 || switched.ViewerVote != voteDown {
		t.Fatalf("switched vote = %+v, err=%v", switched, err)
	}
	reloaded, err := newReputationStore(store.path, defaultReputationConfig())
	if err != nil {
		t.Fatal(err)
	}
	if got := reloaded.summary("demo.example.com", reloaded.viewerHashFor(cookie), live); got.Down != 1 || got.ViewerVote != voteDown {
		t.Fatalf("reloaded vote = %+v", got)
	}
}

func TestReputationKnownHostAndRetention(t *testing.T) {
	store := newTestReputationStore(t)
	now := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	if _, _, err := store.castVote("fake.example.com", voteUp, "", "203.0.113.10", nil); !errors.Is(err, errReputationUnknownHostname) {
		t.Fatalf("unknown hostname error = %v", err)
	}
	live := map[string]bool{"demo.example.com": true}
	_, cookie, err := store.castVote("demo.example.com", voteUp, "", "203.0.113.10", live)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(store.cfg.Retention + time.Second)
	if got := store.summary("demo.example.com", store.viewerHashFor(cookie), nil); got.Total != 0 {
		t.Fatalf("expired absent hostname = %+v", got)
	}
	if got := store.summary("demo.example.com", store.viewerHashFor(cookie), live); got.Total != 1 {
		t.Fatalf("live hostname lost retained vote = %+v", got)
	}
	if _, _, err := store.castVote("demo.example.com", voteDown, cookie, "203.0.113.10", nil); !errors.Is(err, errReputationUnknownHostname) {
		t.Fatalf("expired absent hostname vote error = %v", err)
	}
	if got, _, err := store.castVote("demo.example.com", voteDown, cookie, "203.0.113.10", live); err != nil || got.Down != 1 || got.Up != 0 {
		t.Fatalf("live hostname vote after retention = %+v, err=%v", got, err)
	}
}

func TestReputationPersistFailureRestoresVote(t *testing.T) {
	store := newTestReputationStore(t)
	live := map[string]bool{"demo.example.com": true}
	_, cookie, err := store.castVote("demo.example.com", voteUp, "", "203.0.113.10", live)
	if err != nil {
		t.Fatal(err)
	}
	store.persistFn = func() error { return errors.New("disk unavailable") }
	if _, _, err := store.castVote("demo.example.com", voteDown, cookie, "203.0.113.10", live); !errors.Is(err, errReputationPersist) {
		t.Fatalf("persist error = %v", err)
	}
	if got := store.summary("demo.example.com", store.viewerHashFor(cookie), live); got.Up != 1 || got.Down != 0 {
		t.Fatalf("failed write changed vote: %+v", got)
	}
}

func TestReputationDirectoryProjectsLiveHostsAndViewerVote(t *testing.T) {
	store := newTestReputationStore(t)
	live := map[string]bool{"voted.example.com": true, "old.example.com": true}
	_, cookie, err := store.castVote("voted.example.com", voteUp, "", "203.0.113.10", live)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.castVote("old.example.com", voteUp, cookie, "203.0.113.10", live); err != nil {
		t.Fatal(err)
	}
	// old.example.com drops out of the live set but its record stays within
	// the retention window, so it keeps its directory row; fresh.example.com
	// is live with no record yet and must still get a zero-count row.
	live = map[string]bool{"voted.example.com": true, "fresh.example.com": true}
	directory := store.directory(store.viewerHashFor(cookie), live)
	want := []reputationSummary{
		{Hostname: "fresh.example.com"},
		{Hostname: "old.example.com", Up: 1, Down: 0, Total: 1, ViewerVote: voteUp},
		{Hostname: "voted.example.com", Up: 1, Down: 0, Total: 1, ViewerVote: voteUp},
	}
	if !slices.Equal(directory.Hostnames, want) {
		t.Fatalf("directory rows = %+v, want %+v", directory.Hostnames, want)
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
	api, err := NewRelayAPI(server, filepath.Join(dir, types.RelayPolicyFilename), "admin-test", frontend, false, defaultReputationConfig())
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
	for i := 0; i < reputationVoteSourceBurst+2; i++ {
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
	api.Handler().ServeHTTP(read, httptest.NewRequest(http.MethodGet, pathReputation, nil))
	var response types.APIEnvelope[reputationDirectory]
	if read.Code != http.StatusOK || json.Unmarshal(read.Body.Bytes(), &response) != nil || len(response.Data.Hostnames) != 0 {
		t.Fatalf("directory response: status=%d body=%s", read.Code, read.Body.String())
	}
}
