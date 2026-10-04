package policy

import (
	"path/filepath"
	"testing"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func newTestReputationStore(t *testing.T) *ReputationStore {
	t.Helper()
	store, err := NewReputationStore(filepath.Join(t.TempDir(), ReputationFilename))
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
	first, cookie, err := store.CastVote("demo.example.com", "id:demo.example.com", VoteUp, "", "203.0.113.10")
	if err != nil || first.Up != 1 || cookie == "" {
		t.Fatalf("first vote = %+v, cookie=%q, err=%v", first, cookie, err)
	}
	same, _, err := store.CastVote("demo.example.com", "id:demo.example.com", VoteUp, cookie, "203.0.113.10")
	if err != nil || same.Up != 1 {
		t.Fatalf("same vote changed state: %+v, err=%v", same, err)
	}
	switched, _, err := store.CastVote("demo.example.com", "id:demo.example.com", VoteDown, cookie, "203.0.113.10")
	if err != nil || switched.Up != 0 || switched.Down != 1 || switched.ViewerVote != VoteDown {
		t.Fatalf("switched vote = %+v, err=%v", switched, err)
	}
	reloaded, err := NewReputationStore(store.path)
	if err != nil {
		t.Fatal(err)
	}
	if got := reloaded.Summaries(reloaded.ViewerHashFor(cookie), testLeases("demo.example.com"))[0]; got.Down != 1 || got.ViewerVote != VoteDown {
		t.Fatalf("reloaded vote = %+v", got)
	}
}

func TestReputationDirectoryProjectsLiveHostsAndViewerVote(t *testing.T) {
	store := newTestReputationStore(t)
	_, cookie, err := store.CastVote("voted.example.com", "id:voted.example.com", VoteUp, "", "203.0.113.10")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.CastVote("old.example.com", "id:old.example.com", VoteUp, cookie, "203.0.113.10"); err != nil {
		t.Fatal(err)
	}
	summaries := store.Summaries(store.ViewerHashFor(cookie), testLeases("voted.example.com", "old.example.com", "fresh.example.com"))
	want := map[string]ReputationSummary{
		"fresh.example.com": {Hostname: "fresh.example.com"},
		"old.example.com":   {Hostname: "old.example.com", Up: 1, Down: 0, Total: 1, ViewerVote: VoteUp},
		"voted.example.com": {Hostname: "voted.example.com", Up: 1, Down: 0, Total: 1, ViewerVote: VoteUp},
	}
	got := make(map[string]ReputationSummary, len(summaries))
	for _, row := range summaries {
		got[row.Hostname] = row
	}
	if len(summaries) != len(want) || len(got) != len(want) {
		t.Fatalf("directory rows = %+v, want %d hostnames", summaries, len(want))
	}
	for hostname, expected := range want {
		row, ok := got[hostname]
		if !ok {
			t.Fatalf("missing directory row for %s", hostname)
		}
		if row != expected {
			t.Fatalf("directory row %s = %+v, want %+v", hostname, row, expected)
		}
	}
}
