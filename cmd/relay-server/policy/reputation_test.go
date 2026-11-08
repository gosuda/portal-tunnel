package policy

import (
	"encoding/base64"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func newTestReputationStore(t *testing.T) *ReputationStore {
	t.Helper()
	store, err := NewReputationStore(filepath.Join(t.TempDir(), "reputation.json"))
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func TestReputationRejectsInvalidStoredVotes(t *testing.T) {
	type storedVoteCase struct {
		name       string
		identities map[string]map[string]string
		want       error
	}
	tests := []storedVoteCase{
		{"empty identity", map[string]map[string]string{"": {"voter": VoteUp}}, errReputationStoredInvalid},
		{"blank identity", map[string]map[string]string{"  ": {"voter": VoteUp}}, errReputationStoredInvalid},
		{"empty ledger", map[string]map[string]string{"app": {}}, errReputationStoredInvalid},
		{"empty voter", map[string]map[string]string{"app": {"": VoteUp}}, errReputationStoredInvalid},
		{"blank voter", map[string]map[string]string{"app": {"  ": VoteUp}}, errReputationStoredInvalid},
		{"invalid vote", map[string]map[string]string{"app": {"voter": "invalid"}}, errReputationStoredInvalid},
		{"stored clear", map[string]map[string]string{"app": {"voter": VoteClear}}, errReputationStoredInvalid},
	}
	tooManyVoters := make(map[string]string)
	for i := range reputationMaxVoters + 1 {
		tooManyVoters[strconv.Itoa(i)] = VoteUp
	}
	tooManyIdentities := make(map[string]map[string]string)
	for i := range reputationMaxIdentities + 1 {
		tooManyIdentities[strconv.Itoa(i)] = map[string]string{"voter": VoteDown}
	}
	tests = append(tests,
		storedVoteCase{"voter capacity", map[string]map[string]string{"app": tooManyVoters}, ErrReputationCapacity},
		storedVoteCase{"identity capacity", tooManyIdentities, ErrReputationCapacity},
	)
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "reputation.json")
			state := persistedReputation{VoterSecret: make([]byte, reputationVoterIDBytes), Identities: test.identities}
			if err := utils.WriteJSONFile(path, state, 0o600); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := NewReputationStore(path); !errors.Is(err, test.want) {
				t.Fatalf("invalid stored votes: got %v, want %v", err, test.want)
			}
			after, err := os.ReadFile(path)
			if err != nil || string(before) != string(after) {
				t.Fatalf("rejected state was rewritten: %v", err)
			}
		})
	}
}

func TestReputationRotatingSourcesSpendNewVoterBudget(t *testing.T) {
	store := newTestReputationStore(t)
	now := time.Now()
	store.limiter.clock = func() time.Time { return now }
	const identity = "id:demo.example.com"
	firstSource := netip.MustParseAddr("2001:db8::1")
	var firstCookie string
	for i := 1; i <= 3; i++ {
		source := netip.MustParseAddr("2001:db8::" + strconv.Itoa(i))
		if retry := store.AllowVote(source, false); retry != 0 {
			t.Fatalf("request %d rejected before mint admission: %v", i, retry)
		}
		summary, cookie, err := store.Vote(identity, "", VoteUp, "", source)
		if err != nil || summary.Total != i || cookie == "" {
			t.Fatalf("new voter %d = %+v, cookie=%q, err=%v", i, summary, cookie, err)
		}
		if i == 1 {
			firstCookie = cookie
		}
	}
	// Three requests spent 33 of the 40 global tokens (1 + 10 each).
	// A fourth address in the same /64 can afford a request, but not a voter.
	fourthSource := netip.MustParseAddr("2001:db8::4")
	if retry := store.AllowVote(fourthSource, false); retry != 0 {
		t.Fatalf("ordinary vote request unexpectedly exhausted: %v", retry)
	}
	_, cookie, err := store.Vote(identity, "", VoteUp, "", fourthSource)
	if !errors.Is(err, ErrReputationCapacity) || cookie != "" || len(store.state.Identities[identity]) != 3 {
		t.Fatalf("rotating source bypassed mint budget: cookie=%q, err=%v", cookie, err)
	}
	if retry := store.AllowVote(firstSource, false); retry != 0 {
		t.Fatalf("existing source cannot afford an update: %v", retry)
	}
	updated, cookie, err := store.Vote(identity, "", VoteDown, "", firstSource)
	if err != nil || updated.Total != 3 || updated.Down != 1 || cookie != firstCookie {
		t.Fatalf("existing cookieless voter = %+v, cookie=%q, err=%v", updated, cookie, err)
	}
	if retry := store.AllowVote(fourthSource, false); retry != 0 {
		t.Fatalf("existing cookie cannot afford an update: %v", retry)
	}
	updated, cookie, err = store.Vote(identity, "", VoteUp, firstCookie, fourthSource)
	if err != nil || updated.Total != 3 || updated.Down != 0 || cookie != "" {
		t.Fatalf("existing cookie voter = %+v, cookie=%q, err=%v", updated, cookie, err)
	}
}

func TestReputationInvalidSourceCannotCreateVoter(t *testing.T) {
	for _, cookie := range []string{"", "forged"} {
		t.Run(cookie, func(t *testing.T) {
			store := newTestReputationStore(t)
			_, minted, err := store.Vote("id:demo.example.com", "", VoteUp, cookie, netip.Addr{})
			if !errors.Is(err, ErrReputationCapacity) || minted != "" || len(store.state.Identities) != 0 {
				t.Fatalf("invalid source created a voter: cookie=%q, err=%v", minted, err)
			}
		})
	}
}

func TestReputationLegacyCookieRemainsDistinctFromNATSource(t *testing.T) {
	store := newTestReputationStore(t)
	const identity = "id:demo.example.com"
	source := netip.MustParseAddr("203.0.113.10")
	// Pre-existing cookies contain a random ID signed with the same secret.
	id := make([]byte, reputationVoterIDBytes)
	id[0] = 42
	legacyCookie := base64.RawURLEncoding.EncodeToString(append(id, store.voterMAC(id)...))
	if _, _, err := store.Vote(identity, "", VoteUp, legacyCookie, source); err != nil {
		t.Fatal(err)
	}
	summary, sourceCookie, err := store.Vote(identity, "", VoteDown, "", source)
	if err != nil || summary.Total != 2 || summary.Up != 1 || summary.Down != 1 || sourceCookie == legacyCookie {
		t.Fatalf("NAT source replaced a legacy cookie voter: %+v, err=%v", summary, err)
	}
	summary, mappedCookie, err := store.Vote(identity, "", VoteDown, "forged", netip.MustParseAddr("::ffff:203.0.113.10"))
	if err != nil || summary.Total != 2 || mappedCookie != sourceCookie {
		t.Fatalf("mapped source or invalid cookie created another voter: %+v, err=%v", summary, err)
	}
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
	first, cookie, err := store.Vote("id:demo.example.com", "", VoteUp, "", netip.MustParseAddr("203.0.113.10"))
	if err != nil || first.Up != 1 || cookie == "" {
		t.Fatalf("first vote = %+v, cookie=%q, err=%v", first, cookie, err)
	}
	same, _, err := store.Vote("id:demo.example.com", "", VoteUp, cookie, netip.MustParseAddr("203.0.113.10"))
	if err != nil || same.Up != 1 {
		t.Fatalf("same vote changed state: %+v, err=%v", same, err)
	}
	switched, _, err := store.Vote("id:demo.example.com", "", VoteDown, cookie, netip.MustParseAddr("203.0.113.10"))
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
	_, cookie, err := store.Vote("id:voted.example.com", "", VoteUp, "", netip.MustParseAddr("203.0.113.10"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Vote("id:old.example.com", "", VoteUp, cookie, netip.MustParseAddr("203.0.113.10")); err != nil {
		t.Fatal(err)
	}
	summaries := store.Summaries(store.ViewerHashFor(cookie), testLeases("voted.example.com", "old.example.com", "fresh.example.com"))
	want := map[string]ReputationSummary{
		"fresh.example.com": {Hostname: "fresh.example.com"},
		"old.example.com":   {Hostname: "old.example.com", VoteSummary: VoteSummary{Up: 1, Total: 1, ViewerVote: VoteUp}},
		"voted.example.com": {Hostname: "voted.example.com", VoteSummary: VoteSummary{Up: 1, Total: 1, ViewerVote: VoteUp}},
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

func TestReputationRepeatVoteWithoutCookie(t *testing.T) {
	store := newTestReputationStore(t)
	source := netip.MustParseAddr("203.0.113.10")
	var firstCookie string
	for i := range 3 {
		summary, cookie, err := store.Vote("id:demo.example.com", "", VoteUp, "", source)
		if err != nil || summary.Total != 1 || cookie == "" {
			t.Fatalf("Vote(repeat=%d) = %+v, cookie=%q, err=%v, want one vote and cookie", i, summary, cookie, err)
		}
		if i == 0 {
			firstCookie = cookie
		} else if cookie != firstCookie {
			t.Fatalf("Vote(repeat=%d) cookie = %q, want %q", i, cookie, firstCookie)
		}
	}
}

func TestReputationCookielessIdentitySurvivesRestart(t *testing.T) {
	store := newTestReputationStore(t)
	source := netip.MustParseAddr("203.0.113.10")
	_, cookie, err := store.Vote("id:demo.example.com", "", VoteUp, "", source)
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := NewReputationStore(store.path)
	if err != nil {
		t.Fatal(err)
	}
	summary, again, err := restarted.Vote("id:demo.example.com", "", VoteDown, "", source)
	if err != nil || summary.Total != 1 || summary.Down != 1 || again != cookie {
		t.Fatalf("Vote(after restart) = %+v, cookie=%q, err=%v, want one updated vote and cookie %q", summary, again, err, cookie)
	}
}

func TestReputationAtCapacityExistingVoterCanChangeVote(t *testing.T) {
	store := newTestReputationStore(t)
	source := netip.MustParseAddr("203.0.113.10")
	const identity = "id:demo.example.com"
	_, cookie, err := store.Vote(identity, "", VoteUp, "", source)
	if err != nil {
		t.Fatal(err)
	}
	votes := store.state.Identities[identity]
	for i := 1; i < reputationMaxVoters; i++ {
		votes["legacy-"+strconv.Itoa(i)] = VoteUp
	}
	updated, _, err := store.Vote(identity, "", VoteDown, "", source)
	if err != nil || updated.Total != reputationMaxVoters || updated.Down != 1 {
		t.Fatalf("Vote(existing voter at capacity) = %+v, err=%v, want one updated vote", updated, err)
	}
	otherSource := netip.MustParseAddr("203.0.113.11")
	if _, _, err := store.Vote(identity, "", VoteUp, "", otherSource); !errors.Is(err, ErrReputationCapacity) {
		t.Fatalf("Vote(new voter at capacity) error = %v, want %v", err, ErrReputationCapacity)
	}
	updated, _, err = store.Vote(identity, "", VoteUp, cookie, otherSource)
	if err != nil || updated.Total != reputationMaxVoters || updated.Down != 0 {
		t.Fatalf("Vote(existing cookie at capacity) = %+v, err=%v, want unchanged capacity", updated, err)
	}
}

func TestVoteChangesAreDurableForAppsAndComments(t *testing.T) {
	for _, target := range []string{"app", "comment"} {
		t.Run(target, func(t *testing.T) {
			store := newTestReputationStore(t)
			const identity = "id:demo.example.com"
			source := netip.MustParseAddr("203.0.113.10")
			commentID := ""
			if target == "comment" {
				comments, err := store.AddComment(identity, "A comment", "", "author")
				if err != nil {
					t.Fatal(err)
				}
				commentID = comments[0].ID
				if _, _, err := store.Vote("another-app", commentID, VoteUp, "", source); !errors.Is(err, ErrCommentNotFound) {
					t.Fatalf("another app inherited comment voting rights: %v", err)
				}
			}
			first, cookie, err := store.Vote(identity, commentID, VoteUp, "", source)
			if err != nil || first.Up != 1 || first.Total != 1 || cookie == "" {
				t.Fatalf("first vote: %+v, cookie=%q, err=%v", first, cookie, err)
			}
			for _, choice := range []string{VoteUp, VoteDown, VoteClear, VoteClear} {
				summary, _, err := store.Vote(identity, commentID, choice, cookie, source)
				if err != nil {
					t.Fatal(err)
				}
				if choice == VoteClear {
					if summary.Total != 0 || summary.ViewerVote != "" {
						t.Fatalf("clear vote: %+v", summary)
					}
					continue
				}
				if summary.Total != 1 || summary.ViewerVote != choice {
					t.Fatalf("switch or repeat vote: %+v", summary)
				}
				if choice == VoteDown && summary.Down != 1 {
					t.Fatalf("switch or repeat vote: %+v", summary)
				}
			}
			store, err = NewReputationStore(store.path)
			if err != nil {
				t.Fatal(err)
			}
			cleared, _, err := store.Vote(identity, commentID, VoteClear, cookie, source)
			if err != nil || cleared.Total != 0 {
				t.Fatalf("cleared vote did not survive restart: %+v, err=%v", cleared, err)
			}
			if _, _, err := store.Vote(identity, commentID, VoteUp, cookie, source); err != nil {
				t.Fatal(err)
			}
			// A failed replacement must leave both the vote and its viewer state unchanged.
			if err := os.Remove(store.path); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(store.path, 0o700); err != nil {
				t.Fatal(err)
			}
			if _, minted, err := store.Vote(identity, commentID, VoteDown, cookie, source); err == nil || minted != "" {
				t.Fatalf("failed persistence returned success or issued a cookie: %q, %v", minted, err)
			}
			viewerHash := store.ViewerHashFor(cookie)
			if target == "comment" {
				comments := store.ListComments(identity, viewerHash, "author")
				if len(comments) != 1 || comments[0].Up != 1 || comments[0].Down != 0 || comments[0].ViewerVote != VoteUp {
					t.Fatalf("failed write changed comment vote: %+v", comments)
				}
			} else {
				row := store.Summaries(viewerHash, testLeases("demo.example.com"))[0]
				if row.Up != 1 || row.Down != 0 || row.ViewerVote != VoteUp {
					t.Fatalf("failed write changed app vote: %+v", row)
				}
			}
		})
	}
}
