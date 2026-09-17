package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal"
	"github.com/gosuda/portal-tunnel/v2/types"
)

func newTestReputationStore(t *testing.T, cfg ReputationConfig) *ReputationStore {
	t.Helper()
	store, err := newReputationStore(filepath.Join(t.TempDir(), reputationFilename), cfg)
	if err != nil {
		t.Fatal(err)
	}
	return store
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

// reputationRequest mirrors production admission: ExtractClientIP reads the
// socket address because TrustProxyHeaders is false, so tests set RemoteAddr
// instead of injecting X-Forwarded-For.
func reputationRequest(t *testing.T, api *RelayAPI, method, target, body, cookieValue, remoteAddr string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	if remoteAddr != "" {
		req.RemoteAddr = remoteAddr
	}
	if cookieValue != "" {
		req.AddCookie(&http.Cookie{Name: reputationVoterCookie, Value: cookieValue})
	}
	recorder := httptest.NewRecorder()
	api.Handler().ServeHTTP(recorder, req)
	return recorder
}

func postVote(t *testing.T, api *RelayAPI, body, cookieValue, remoteAddr string) *httptest.ResponseRecorder {
	t.Helper()
	return reputationRequest(t, api, http.MethodPost, pathReputationVote, body, cookieValue, remoteAddr)
}

func getReputation(t *testing.T, api *RelayAPI, hostname, cookieValue string) *httptest.ResponseRecorder {
	t.Helper()
	target := pathReputation
	if hostname != "" {
		target += "?" + url.Values{"hostname": {hostname}}.Encode()
	}
	return reputationRequest(t, api, http.MethodGet, target, "", cookieValue, "")
}

func decodeSummary(t *testing.T, recorder *httptest.ResponseRecorder) reputationSummary {
	t.Helper()
	var envelope types.APIEnvelope[reputationSummary]
	if err := json.Unmarshal(recorder.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	return envelope.Data
}

func decodeDirectory(t *testing.T, recorder *httptest.ResponseRecorder) reputationDirectory {
	t.Helper()
	var envelope types.APIEnvelope[reputationDirectory]
	if err := json.Unmarshal(recorder.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	return envelope.Data
}

func decodeErrorCode(t *testing.T, recorder *httptest.ResponseRecorder) string {
	t.Helper()
	var envelope types.APIEnvelope[json.RawMessage]
	if err := json.Unmarshal(recorder.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Error == nil {
		t.Fatalf("no error payload in %q", recorder.Body.String())
	}
	return envelope.Error.Code
}

func voterCookie(t *testing.T, recorder *httptest.ResponseRecorder) string {
	t.Helper()
	for _, cookie := range recorder.Result().Cookies() {
		if cookie.Name == reputationVoterCookie {
			return cookie.Value
		}
	}
	t.Fatalf("no %s cookie in response", reputationVoterCookie)
	return ""
}

// fixedClock returns a mutable instant wired into the store so tests can
// advance time without sleeps.
func fixedClock(store *ReputationStore) *time.Time {
	now := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	return &now
}

// TestReputationVoteLifecycle pins the ballot invariant: the first vote
// counts, repeating the same side is idempotent, and switching sides moves
// the count instead of adding one.
func TestReputationVoteLifecycle(t *testing.T) {
	store := newTestReputationStore(t, defaultReputationConfig())
	const hostname = "demo.example.com"

	summary, cookieA, err := store.castVote(hostname, voteUp, "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Up != 1 || summary.Down != 0 || summary.Total != 1 || summary.ViewerVote != voteUp {
		t.Fatalf("first vote = %+v", summary)
	}

	summary, _, err = store.castVote(hostname, voteUp, cookieA, "", false)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Up != 1 || summary.Total != 1 {
		t.Fatalf("idempotent revote grew the tally: %+v", summary)
	}

	summary, _, err = store.castVote(hostname, voteDown, cookieA, "", false)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Up != 0 || summary.Down != 1 || summary.Total != 1 || summary.ViewerVote != voteDown {
		t.Fatalf("switched vote = %+v", summary)
	}

	_, cookieB, err := store.castVote(hostname, voteDown, "", "", false)
	if err != nil || cookieB == "" {
		t.Fatalf("second cookieless voter: cookie=%q err=%v", cookieB, err)
	}
	summary, _, _ = store.castVote(hostname, voteDown, cookieB, "", false)
	if summary.Down != 2 || summary.Total != 2 {
		t.Fatalf("second voter tally = %+v", summary)
	}

	if anonymous := store.summary(hostname, "", nil); anonymous.ViewerVote != "" || anonymous.Down != 2 {
		t.Fatalf("anonymous summary = %+v", anonymous)
	}
}

// TestReputationRestartReloadSurvives pins durability: votes, the voter
// secret, and the mint registry all survive a store rebuild from disk, so
// existing cookies keep their vote attribution after a relay restart.
func TestReputationRestartReloadSurvives(t *testing.T) {
	path := filepath.Join(t.TempDir(), reputationFilename)
	store, err := newReputationStore(path, defaultReputationConfig())
	if err != nil {
		t.Fatal(err)
	}
	summary, cookie, err := store.castVote("demo.example.com", voteUp, "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Up != 1 || cookie == "" {
		t.Fatalf("pre-restart vote = %+v cookie=%q", summary, cookie)
	}

	reloaded, err := newReputationStore(path, defaultReputationConfig())
	if err != nil {
		t.Fatal(err)
	}
	viewerHash := reloaded.viewerHashFor(cookie)
	if viewerHash == "" {
		t.Fatal("voter cookie no longer verifies after restart")
	}
	if got := reloaded.summary("demo.example.com", viewerHash, nil); got.Up != 1 || got.ViewerVote != voteUp {
		t.Fatalf("post-restart summary = %+v", got)
	}
	// The registry survives too, so a restart cannot refresh mint budget.
	if len(reloaded.state.Voters) != 1 {
		t.Fatalf("mint registry after restart = %d entries", len(reloaded.state.Voters))
	}
}

// TestReputationReregistrationPreservesSameHostname pins the hostname-keyed
// identity: a lease re-registering under the same hostname (same or renewed
// identity) keeps first-seen and votes; an owner change is recorded, never
// punished.
func TestReputationReregistrationPreservesSameHostname(t *testing.T) {
	store := newTestReputationStore(t, defaultReputationConfig())
	now := fixedClock(store)
	const hostname = "move.example.com"

	_, firstCookie, err := store.castVote(hostname, voteUp, "", "name:0xaaa", true)
	if err != nil {
		t.Fatal(err)
	}
	first := store.state.Hostnames[hostname]

	// A new lease instance under the same hostname and owner: same cookie,
	// idempotent revote, first seen untouched.
	*now = now.Add(time.Hour)
	if _, _, err := store.castVote(hostname, voteUp, firstCookie, "name:0xaaa", true); err != nil {
		t.Fatal(err)
	}
	if got := store.state.Hostnames[hostname]; !got.FirstSeenAt.Equal(first.FirstSeenAt) {
		t.Fatalf("re-registration reset first seen: %v -> %v", first.FirstSeenAt, got.FirstSeenAt)
	}
	if got := store.summary(hostname, "", nil); got.Total != 1 {
		t.Fatalf("re-registration changed the tally: %+v", got)
	}

	*now = now.Add(time.Hour)
	summary, _, err := store.castVote(hostname, voteDown, "", "name:0xbbb", true)
	if err != nil {
		t.Fatal(err)
	}
	rec := store.state.Hostnames[hostname]
	if rec.OwnerKey != "name:0xbbb" || rec.KeyChangedAt.IsZero() {
		t.Fatalf("owner change not recorded: %+v", rec)
	}
	if summary.Up != 1 || summary.Down != 1 || summary.Total != 2 {
		t.Fatalf("owner change altered prior votes: %+v", summary)
	}
}

// TestReputationWarningThresholdBoundaries pins the gate math: total, down,
// and ratio thresholds each hold independently, and the ratio boundary is
// inclusive without float drift.
func TestReputationWarningThresholdBoundaries(t *testing.T) {
	cfg := ReputationConfig{WarningMinTotal: 3, WarningMinDown: 2, WarningDownRatioPct: 50, Retention: time.Hour}
	store := newTestReputationStore(t, cfg)
	const hostname = "gate.example.com"

	vote := func(n int) {
		t.Helper()
		for i := 0; i < n; i++ {
			if _, _, err := store.castVote(hostname, voteDown, "", "", false); err != nil {
				t.Fatal(err)
			}
		}
	}

	// 1 down: total below min-total.
	vote(1)
	if got := store.directory(nil).Hostnames[0].Warning; got {
		t.Fatal("flagged below min total")
	}
	// 2 down: meets min-down and ratio but still below min-total.
	vote(1)
	if got := store.directory(nil).Hostnames[0].Warning; got {
		t.Fatal("flagged below min total with two downs")
	}
	// 3 down / 0 up: all three thresholds hold.
	vote(1)
	if got := store.directory(nil).Hostnames[0].Warning; !got {
		t.Fatal("not flagged at 3/3 down")
	}

	// Exact ratio boundary at 50%: 2 down / 4 total flags; 51% does not.
	if !cfg.warning(4, 2) {
		t.Fatal("2/4 did not meet a 50% ratio")
	}
	tightCfg := ReputationConfig{WarningMinTotal: 3, WarningMinDown: 2, WarningDownRatioPct: 51, Retention: time.Hour}
	if tightCfg.warning(4, 2) {
		t.Fatal("2/4 passed a 51% ratio")
	}
}

// TestReputationInvalidInputRejected covers the thin handler's validation
// before any store op runs.
func TestReputationInvalidInputRejected(t *testing.T) {
	api := newTestReputationAPI(t)

	cases := []struct {
		name string
		body string
	}{
		{"bad vote value", `{"hostname":"demo.example.com","vote":"meh"}`},
		{"empty hostname", `{"hostname":"  ","vote":"up"}`},
		{"missing hostname", `{"vote":"up"}`},
		{"oversized hostname", fmt.Sprintf(`{"hostname":"%s","vote":"up"}`, strings.Repeat("a", 254))},
		{"not json", `up`},
	}
	for _, tc := range cases {
		recorder := postVote(t, api, tc.body, "", "203.0.113.10:1000")
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("%s: status %d", tc.name, recorder.Code)
		}
		if code := decodeErrorCode(t, recorder); code != types.APIErrorCodeInvalidRequest {
			t.Fatalf("%s: error code %q", tc.name, code)
		}
	}

	if recorder := postVote(t, api, `{"hostname":"demo.example.com","vote":"up"}`, "", "203.0.113.10:1000"); recorder.Code != http.StatusOK {
		t.Fatalf("valid vote rejected: %d", recorder.Code)
	}

	get := httptest.NewRequest(http.MethodGet, pathReputationVote, nil)
	getRecorder := httptest.NewRecorder()
	api.Handler().ServeHTTP(getRecorder, get)
	if getRecorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET on vote path: %d", getRecorder.Code)
	}
	post := httptest.NewRequest(http.MethodPost, pathReputation, strings.NewReader("{}"))
	postRecorder := httptest.NewRecorder()
	api.Handler().ServeHTTP(postRecorder, post)
	if postRecorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST on summary path: %d", postRecorder.Code)
	}
}

// TestReputationVoteRateLimited pins admission: the per-source burst
// exhausts, the response carries the rate_limited code and a Retry-After
// header, and nothing after the limit lands in the store.
func TestReputationVoteRateLimited(t *testing.T) {
	api := newTestReputationAPI(t)
	const remote = "203.0.113.11:2000"

	limited := 0
	for i := 0; i < reputationVoteSourceBurst+5; i++ {
		recorder := postVote(t, api, `{"hostname":"demo.example.com","vote":"up"}`, "", remote)
		if recorder.Code == http.StatusTooManyRequests {
			limited++
			if recorder.Header().Get("Retry-After") == "" {
				t.Fatal("429 without Retry-After")
			}
			if code := decodeErrorCode(t, recorder); code != types.APIErrorCodeRateLimited {
				t.Fatalf("error code %q", code)
			}
		}
	}
	if limited == 0 {
		t.Fatal("burst was never limited")
	}
	if got := api.reputation.summary("demo.example.com", "", nil).Total; got > reputationVoteSourceBurst {
		t.Fatalf("tally above admission burst: %d", got)
	}
}

// TestReputationForgedCookieMintsFresh pins the cookieless fallback: a
// structurally valid cookie with a bad MAC reads as anonymous on reads and
// mints a fresh identity on votes.
func TestReputationForgedCookieMintsFresh(t *testing.T) {
	api := newTestReputationAPI(t)
	forged := strings.Repeat("ab", reputationVoterIDBytes) + "." + strings.Repeat("cd", 32)

	recorder := postVote(t, api, `{"hostname":"demo.example.com","vote":"up"}`, forged, "203.0.113.12:3000")
	if recorder.Code != http.StatusOK {
		t.Fatalf("forged-cookie vote rejected: %d", recorder.Code)
	}
	minted := voterCookie(t, recorder)
	if minted == forged {
		t.Fatal("forged cookie echoed back")
	}

	anonymous := decodeSummary(t, getReputation(t, api, "demo.example.com", forged))
	if anonymous.ViewerVote != "" {
		t.Fatalf("forged cookie read a viewer vote: %+v", anonymous)
	}
	attributed := decodeSummary(t, getReputation(t, api, "demo.example.com", minted))
	if attributed.ViewerVote != voteUp {
		t.Fatalf("minted cookie lost attribution: %+v", attributed)
	}
}

// TestReputationAPIFlowCookieAndDirectory walks the public surface: vote via
// HTTP, cookie set, per-hostname summary with and without the cookie, and
// the directory projection shape.
func TestReputationAPIFlowCookieAndDirectory(t *testing.T) {
	api := newTestReputationAPI(t)

	first := postVote(t, api, `{"hostname":"demo.example.com","vote":"up"}`, "", "203.0.113.13:4000")
	if first.Code != http.StatusOK {
		t.Fatalf("first vote: %d", first.Code)
	}
	voterA := voterCookie(t, first)

	second := postVote(t, api, `{"hostname":"demo.example.com","vote":"down"}`, "", "203.0.113.14:4000")
	if second.Code != http.StatusOK {
		t.Fatalf("second vote: %d", second.Code)
	}
	voterB := voterCookie(t, second)
	if voterA == voterB {
		t.Fatal("distinct voters share a cookie")
	}

	summary := decodeSummary(t, getReputation(t, api, "demo.example.com", voterA))
	if summary.Up != 1 || summary.Down != 1 || summary.Total != 2 || summary.ViewerVote != voteUp {
		t.Fatalf("attributed summary = %+v", summary)
	}
	if anonymous := decodeSummary(t, getReputation(t, api, "demo.example.com", "")); anonymous.ViewerVote != "" || anonymous.Total != 2 {
		t.Fatalf("anonymous summary = %+v", anonymous)
	}
	if missing := decodeSummary(t, getReputation(t, api, "ghost.example.com", "")); missing.Total != 0 || missing.ViewerVote != "" {
		t.Fatalf("unknown hostname summary = %+v", missing)
	}

	directory := decodeDirectory(t, getReputation(t, api, "", ""))
	if len(directory.Hostnames) != 1 {
		t.Fatalf("directory rows = %+v", directory.Hostnames)
	}
	row := directory.Hostnames[0]
	if row.Hostname != "demo.example.com" || row.Up != 1 || row.Down != 1 || row.Total != 2 {
		t.Fatalf("directory row = %+v", row)
	}
	if row.Warning {
		t.Fatal("2 votes flagged a hostname needing 5")
	}
	if row.DownRatio <= 0 || row.DownRatio >= 1 {
		t.Fatalf("down ratio = %v", row.DownRatio)
	}
}

// TestReputationPersistFailureRollsBack pins the snapshot-and-rollback
// contract: a failing persist reverts the vote, the tally observation, and a
// cookieless mint reservation together.
func TestReputationPersistFailureRollsBack(t *testing.T) {
	store := newTestReputationStore(t, defaultReputationConfig())
	const hostname = "diskfull.example.com"
	failing := errors.New("disk full")
	store.persistFn = func() error { return failing }

	if _, _, err := store.castVote(hostname, voteUp, "", "", false); !errors.Is(err, errReputationPersist) {
		t.Fatalf("persist failure surfaced as %v", err)
	}
	if got := store.summary(hostname, "", nil); got.Total != 0 {
		t.Fatalf("failed vote survived rollback: %+v", got)
	}
	if len(store.state.Voters) != 0 {
		t.Fatalf("mint reservation survived rollback: %d entries", len(store.state.Voters))
	}

	// A verified-cookie vote rolls back the same way without minting.
	store.state.Voters["known-voter"] = true
	cookie := strings.Repeat("11", reputationVoterIDBytes) + "." + strings.Repeat("22", 32)
	if _, _, err := store.castVote(hostname, voteUp, cookie, "", false); !errors.Is(err, errReputationPersist) {
		t.Fatalf("verified-cookie persist failure surfaced as %v", err)
	}
	if got := store.summary(hostname, "", nil); got.Total != 0 {
		t.Fatalf("failed verified vote survived rollback: %+v", got)
	}

	// Recovery: once the file writes again, voting works from clean state.
	store.persistFn = func() error { return nil }
	if _, _, err := store.castVote(hostname, voteUp, "", "", false); err != nil {
		t.Fatal(err)
	}
	if got := store.summary(hostname, "", nil); got.Total != 1 {
		t.Fatalf("post-recovery summary = %+v", got)
	}
}

// fillHostnames stuffs the store map directly so cap tests stay cheap.
func fillHostnames(store *ReputationStore, count int, vote map[string]string, lastSeen time.Time) {
	for i := 0; len(store.state.Hostnames) < count; i++ {
		rec := &reputationRecord{FirstSeenAt: lastSeen, LastSeenAt: lastSeen, Voters: map[string]string{}}
		for hash, side := range vote {
			rec.Voters[hash] = side
		}
		store.state.Hostnames[fmt.Sprintf("fill-%05d.example.com", i)] = rec
	}
}

// TestReputationHostnameCapEvictionRespectsVotedRecords pins the griefing
// defense at the hostname cap: voteless records yield, fresh voted records
// never do, and expired voted records may.
func TestReputationHostnameCapEvictionRespectsVotedRecords(t *testing.T) {
	store := newTestReputationStore(t, defaultReputationConfig())
	now := fixedClock(store)

	// At cap with voteless records: the newcomer evicts one and lands.
	fillHostnames(store, reputationMaxHostnames, nil, *now)
	summary, _, err := store.castVote("new.example.com", voteUp, "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Up != 1 || len(store.state.Hostnames) != reputationMaxHostnames {
		t.Fatalf("voteless eviction: summary=%+v size=%d", summary, len(store.state.Hostnames))
	}

	// At cap with fresh voted records: nobody is evictable.
	for _, rec := range store.state.Hostnames {
		rec.Voters["voter"] = voteUp
	}
	if _, _, err := store.castVote("other.example.com", voteUp, "", "", false); !errors.Is(err, errReputationHostnameCapacity) {
		t.Fatalf("fresh voted records evicted: %v", err)
	}

	// Aging every record past retention makes room again.
	*now = now.Add(defaultReputationConfig().Retention + time.Hour)
	if _, _, err := store.castVote("other.example.com", voteUp, "", "", false); err != nil {
		t.Fatalf("expired voted record not evicted: %v", err)
	}
}

// TestReputationPerHostnameVoterCap bounds one hostname's ballot box.
func TestReputationPerHostnameVoterCap(t *testing.T) {
	store := newTestReputationStore(t, defaultReputationConfig())
	now := fixedClock(store)
	const hostname = "crowded.example.com"

	rec := &reputationRecord{FirstSeenAt: *now, LastSeenAt: *now, Voters: map[string]string{}}
	for i := 0; i < reputationMaxVotersPerHostname; i++ {
		rec.Voters[fmt.Sprintf("voter-%04d", i)] = voteUp
	}
	store.state.Hostnames[hostname] = rec

	// A fresh cookieless voter finds the ballot box full.
	if _, _, err := store.castVote(hostname, voteDown, "", "", false); !errors.Is(err, errReputationVoterCapacity) {
		t.Fatalf("vote past per-hostname cap: %v", err)
	}
}

// TestReputationCookielessBudgetRollback pins the mint budget: the last slot
// is consumable, the next mint fails, and a failed vote never leaves a
// reserved slot behind.
func TestReputationCookielessBudgetRollback(t *testing.T) {
	store := newTestReputationStore(t, defaultReputationConfig())
	now := fixedClock(store)

	// Fill the hostname cap with fresh voted records so votes fail on
	// capacity while mints still succeed - proving the reservation rolls
	// back instead of leaking.
	fillHostnames(store, reputationMaxHostnames, map[string]string{"voter": voteUp}, *now)
	for len(store.state.Voters) < reputationMaxVoters-1 {
		store.state.Voters[fmt.Sprintf("budget-%05d", len(store.state.Voters))] = true
	}

	if _, _, err := store.castVote("blocked.example.com", voteUp, "", "", false); !errors.Is(err, errReputationHostnameCapacity) {
		t.Fatalf("expected hostname capacity error: %v", err)
	}
	if got := len(store.state.Voters); got != reputationMaxVoters-1 {
		t.Fatalf("failed vote leaked a mint slot: %d entries", got)
	}

	// The final slot mints successfully on a hostname that can be admitted
	// (expiring one filler record), then the budget is closed.
	*now = now.Add(defaultReputationConfig().Retention + time.Hour)
	if _, cookie, err := store.castVote("last.example.com", voteUp, "", "", false); err != nil || cookie == "" {
		t.Fatalf("final mint slot: cookie=%q err=%v", cookie, err)
	}
	if _, _, err := store.castVote("blocked.example.com", voteUp, "", "", false); !errors.Is(err, errReputationVoterBudget) {
		t.Fatalf("vote past mint budget: %v", err)
	}
}

// TestReputationRetentionExpiryAtReadAndAdmission pins the no-loop retention
// rule: reads hide (and never delete) stale absent records, live hostnames
// stay visible regardless of staleness, and admission restarts an expired
// record fresh.
func TestReputationRetentionExpiryAtReadAndAdmission(t *testing.T) {
	store := newTestReputationStore(t, defaultReputationConfig())
	now := fixedClock(store)
	const hostname = "stale.example.com"

	if _, _, err := store.castVote(hostname, voteDown, "", "", false); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(defaultReputationConfig().Retention + time.Hour)

	if got := store.summary(hostname, "", nil); got.Total != 0 {
		t.Fatalf("expired record still readable: %+v", got)
	}
	if rows := store.directory(nil).Hostnames; len(rows) != 0 {
		t.Fatalf("expired record still in directory: %+v", rows)
	}
	if got := store.summary(hostname, "", map[string]bool{hostname: true}); got.Total != 1 {
		t.Fatalf("live hostname hidden by retention: %+v", got)
	}
	if len(store.state.Hostnames) != 1 {
		t.Fatal("read path deleted the record")
	}

	// Admission on the expired record restarts it fresh.
	summary, _, err := store.castVote(hostname, voteUp, "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Total != 1 || summary.Down != 0 {
		t.Fatalf("admission kept expired votes: %+v", summary)
	}
	if rec := store.state.Hostnames[hostname]; !rec.FirstSeenAt.Equal(*now) {
		t.Fatalf("expired record kept its first seen: %v", rec.FirstSeenAt)
	}
}

// TestReputationConfigValidation rejects unusable knob combinations at
// startup instead of letting the gate silently never fire.
func TestReputationConfigValidation(t *testing.T) {
	dir := t.TempDir()
	cases := []ReputationConfig{
		{WarningMinTotal: 0, WarningMinDown: 0, WarningDownRatioPct: 50, Retention: time.Hour},
		{WarningMinTotal: 5, WarningMinDown: -1, WarningDownRatioPct: 50, Retention: time.Hour},
		{WarningMinTotal: 5, WarningMinDown: 3, WarningDownRatioPct: 101, Retention: time.Hour},
		{WarningMinTotal: 5, WarningMinDown: 3, WarningDownRatioPct: 50, Retention: 0},
	}
	for _, cfg := range cases {
		if _, err := newReputationStore(filepath.Join(dir, reputationFilename), cfg); err == nil {
			t.Fatalf("config accepted: %+v", cfg)
		}
	}
}
