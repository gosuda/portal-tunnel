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
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal"
	"github.com/gosuda/portal-tunnel/v2/types"
)

func newTestReputationStore(t *testing.T, cfg ReputationConfig) (*ReputationStore, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), types.RelayReputationFilename)
	store, err := newReputationStore(path, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return store, path
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
	api, err := NewRelayAPI(server, filepath.Join(dir, "policy.json"), "admin-test", frontend, false)
	if err != nil {
		t.Fatal(err)
	}
	return api
}

func reputationRequest(t *testing.T, api *RelayAPI, method, target, body, voterID, remoteAddr string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	// Note: X-Forwarded-For is NOT injected here. ExtractClientIP uses socket address
	// (RemoteAddr) in test mode since TrustProxyHeaders=false, so tests that need a
	// specific source IP should set remoteAddr. Injecting a random XFF header would
	// cause ExtractClientIP to read the header only when TrustProxyHeaders=true,
	// creating inconsistency between test runs and production.
	if remoteAddr != "" {
		req.RemoteAddr = remoteAddr
	}
	if voterID != "" {
		req.AddCookie(&http.Cookie{Name: reputationVoterCookie, Value: voterID})
	}
	recorder := httptest.NewRecorder()
	api.Handler().ServeHTTP(recorder, req)
	return recorder
}

func postVote(t *testing.T, api *RelayAPI, body, voterID, remoteAddr string) *httptest.ResponseRecorder {
	t.Helper()
	return reputationRequest(t, api, http.MethodPost, types.PathReputationVote, body, voterID, remoteAddr)
}

func getReputation(t *testing.T, api *RelayAPI, hostname, voterID string) *httptest.ResponseRecorder {
	t.Helper()
	target := types.PathReputation + "?" + url.Values{"hostname": {hostname}}.Encode()
	return reputationRequest(t, api, http.MethodGet, target, "", voterID, "")
}

func decodeSummary(t *testing.T, recorder *httptest.ResponseRecorder) types.ReputationSummary {
	t.Helper()
	var envelope types.APIEnvelope[types.ReputationSummary]
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

// TestReputationStoreVoteLifecycleMovesCountBetweenSides pins the ballot
// invariant: one voter occupies exactly one side, repeating the same side
// changes nothing, and switching sides moves the count instead of adding one.
func TestReputationStoreVoteLifecycleMovesCountBetweenSides(t *testing.T) {
	t.Parallel()
	store, _ := newTestReputationStore(t, defaultReputationConfig())
	const hostname = "demo.example.com"
	voterA := store.VoterHash("voter-a")
	voterB := store.VoterHash("voter-b")

	summary, err := store.Vote(hostname, voterA, "up")
	if err != nil {
		t.Fatal(err)
	}
	if summary.Up != 1 || summary.Total != 1 || summary.ViewerVote != "up" {
		t.Fatalf("first vote = up=%d total=%d viewer=%q", summary.Up, summary.Total, summary.ViewerVote)
	}

	summary, err = store.Vote(hostname, voterA, "up")
	if err != nil {
		t.Fatal(err)
	}
	if summary.Up != 1 || summary.Total != 1 {
		t.Fatalf("repeat vote grew the count: up=%d total=%d", summary.Up, summary.Total)
	}

	summary, err = store.Vote(hostname, voterA, "down")
	if err != nil {
		t.Fatal(err)
	}
	if summary.Up != 0 || summary.Down != 1 || summary.Total != 1 || summary.ViewerVote != "down" {
		t.Fatalf("switched vote = up=%d down=%d total=%d viewer=%q", summary.Up, summary.Down, summary.Total, summary.ViewerVote)
	}

	summary, err = store.Vote(hostname, voterB, "down")
	if err != nil {
		t.Fatal(err)
	}
	if summary.Down != 2 || summary.Total != 2 {
		t.Fatalf("second voter = down=%d total=%d", summary.Down, summary.Total)
	}

	anonymous := store.Summary(hostname, "")
	if anonymous.Up != 0 || anonymous.Down != 2 || anonymous.ViewerVote != "" {
		t.Fatalf("anonymous view = up=%d down=%d viewer=%q", anonymous.Up, anonymous.Down, anonymous.ViewerVote)
	}
}

// TestReputationStoreRoundTripSurvivesRestart pins durability: reputation is
// keyed by hostname in reputation.json, reloads with identical aggregates and
// viewer attribution under the same secret, and never stores raw voter IDs.
func TestReputationStoreRoundTripSurvivesRestart(t *testing.T) {
	t.Parallel()
	cfg := defaultReputationConfig()
	store, path := newTestReputationStore(t, cfg)
	const hostname = "persist.example.com"
	if store.Knows(hostname) {
		t.Fatal("fresh store already knows the hostname")
	}
	store.ObserveLive([]LiveLease{{Hostname: hostname, IdentityKey: "owner-key-1"}})
	voterA, voterB := store.VoterHash("voter-a"), store.VoterHash("voter-b")
	voterC := store.VoterHash("voter-c")
	for _, vote := range []struct {
		hash string
		side string
	}{{voterA, "up"}, {voterB, "up"}, {voterC, "down"}} {
		if _, err := store.Vote(hostname, vote.hash, vote.side); err != nil {
			t.Fatal(err)
		}
	}
	before := store.Summary(hostname, voterA)

	reopened, err := newReputationStore(path, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !reopened.Knows(hostname) {
		t.Fatal("reputation lost across restart")
	}
	after := reopened.Summary(hostname, voterA)
	if after.Up != before.Up || after.Down != before.Down || after.Total != 3 {
		t.Fatalf("restarted aggregate = up=%d down=%d total=%d, want up=%d down=%d total=3",
			after.Up, after.Down, after.Total, before.Up, before.Down)
	}
	if after.ViewerVote != "up" {
		t.Fatalf("restarted viewer vote = %q, want up", after.ViewerVote)
	}
	if !after.FirstSeenAt.Equal(before.FirstSeenAt) {
		t.Fatalf("restarted first seen = %v, want %v", after.FirstSeenAt, before.FirstSeenAt)
	}

	// Reopen: the persisted secret is reused, so a different raw voter ID produces a
	// different hash (which is correct — it is a different voter).
	otherID, _ := issueReputationVoterID()
	if viewer := reopened.Summary(hostname, reopened.VoterHash(otherID)); viewer.ViewerVote != "" {
		t.Fatalf("unrelated voter ID attributed to a stored vote: %q", viewer.ViewerVote)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, voter := range []string{"voter-a", "voter-b", "voter-c"} {
		if strings.Contains(string(raw), voter) {
			t.Fatalf("raw voter id %q reached %s", voter, path)
		}
	}
}

// TestReputationStoreSurvivesReRegistration pins the ownership invariant:
// re-registering the same identity preserves votes and flags nothing, while a
// real owner-key change flags identity_changed_recently without dropping votes.
func TestReputationStoreSurvivesReRegistration(t *testing.T) {
	t.Parallel()
	store, _ := newTestReputationStore(t, defaultReputationConfig())
	const hostname = "reregister.example.com"
	store.ObserveLive([]LiveLease{{Hostname: hostname, IdentityKey: "owner-key-1"}})
	if _, err := store.Vote(hostname, store.VoterHash("voter-a"), "down"); err != nil {
		t.Fatal(err)
	}

	store.ObserveLive([]LiveLease{{Hostname: hostname, IdentityKey: "owner-key-1"}})
	summary := store.Summary(hostname, "")
	if summary.IdentityChangedRecently {
		t.Fatal("same identity re-registration flagged as identity change")
	}
	if summary.Down != 1 {
		t.Fatalf("same identity re-registration lost votes: down=%d", summary.Down)
	}

	store.ObserveLive([]LiveLease{{Hostname: hostname, IdentityKey: "owner-key-2"}})
	summary = store.Summary(hostname, "")
	if !summary.IdentityChangedRecently {
		t.Fatal("owner-key change not flagged as identity_changed_recently")
	}
	if summary.Down != 1 {
		t.Fatalf("identity change dropped votes: down=%d", summary.Down)
	}
}

// TestReputationWarningRequiresTotalDownAndRatioThresholds pins the verdict
// gates: warning fires only when total, down count, and down ratio all reach
// their configured minima, including exact boundary values.
func TestReputationWarningRequiresTotalDownAndRatioThresholds(t *testing.T) {
	t.Parallel()
	strict := defaultReputationConfig()
	strict.MinTotal = 2
	strict.MinDown = 1
	strict.MinDownRatioPercent = 50
	strict.Probation = time.Hour
	strict.Retention = 24 * time.Hour
	strict.VoteSourcePerMinute = 60
	strict.VoteSourceBurst = 60
	// MaxVotersPerSource/MaxHostnames inherit positive defaults from defaultReputationConfig.
	store, _ := newTestReputationStore(t, strict)
	const hostname = "threshold.example.com"
	voter := func(name string) string { return store.VoterHash(name) }

	summary, err := store.Vote(hostname, voter("a"), "down")
	if err != nil {
		t.Fatal(err)
	}
	if summary.Warning {
		t.Fatal("total below minimum warned")
	}

	summary, err = store.Vote(hostname, voter("b"), "up")
	if err != nil {
		t.Fatal(err)
	}
	if !summary.Warning || summary.DownRatio != 0.5 {
		t.Fatalf("exact ratio boundary = warning=%v ratio=%v, want true 0.5", summary.Warning, summary.DownRatio)
	}

	summary, err = store.Vote(hostname, voter("c"), "up")
	if err != nil {
		t.Fatal(err)
	}
	if summary.Warning {
		t.Fatal("diluted ratio warned")
	}

	relaxed := strict
	relaxed.MinDown = 2
	relaxed.MinDownRatioPercent = 0
	downStore, _ := newTestReputationStore(t, relaxed)
	const downHost = "min-down.example.com"
	for name, side := range map[string]string{"a": "down", "b": "up"} {
		if _, err := downStore.Vote(downHost, downStore.VoterHash(name), side); err != nil {
			t.Fatal(err)
		}
	}
	if summary := downStore.Summary(downHost, ""); summary.Warning {
		t.Fatalf("down=%d below MinDown=%d warned", summary.Down, relaxed.MinDown)
	}
}

// TestReputationProbationJudgedFromPersistedTimestamps pins the window logic
// against the documented file contract: is_new and identity_changed_recently
// are derived from first_seen_at / owner_key_history timestamps and Probation.
func TestReputationProbationJudgedFromPersistedTimestamps(t *testing.T) {
	t.Parallel()
	cfg := defaultReputationConfig()
	path := filepath.Join(t.TempDir(), types.RelayReputationFilename)
	now := time.Now().UTC()
	fresh := now.Add(-time.Hour)
	aged := now.Add(-cfg.Probation - 2*time.Hour)
	stamp := func(moment time.Time) string { return moment.Format(time.RFC3339Nano) }
	state := map[string]any{
		"hostnames": map[string]any{
			"fresh.example.com": map[string]any{
				"first_seen_at": stamp(fresh),
				"last_seen_at":  stamp(now),
			},
			"aged.example.com": map[string]any{
				"first_seen_at": stamp(aged),
				"last_seen_at":  stamp(now),
			},
			"rotated.example.com": map[string]any{
				"first_seen_at": stamp(aged),
				"last_seen_at":  stamp(now),
				"owner_key":     "owner-key-new",
				"owner_key_history": []any{map[string]any{
					"key":        "owner-key-old",
					"changed_at": stamp(fresh),
				}},
			},
			"dormant.example.com": map[string]any{
				"first_seen_at": stamp(aged),
				"last_seen_at":  stamp(now),
				"owner_key":     "owner-key-new",
				"owner_key_history": []any{map[string]any{
					"key":        "owner-key-old",
					"changed_at": stamp(aged),
				}},
			},
		},
	}
	payload, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := newReputationStore(path, cfg)
	if err != nil {
		t.Fatal(err)
	}

	if summary := store.Summary("fresh.example.com", ""); !summary.IsNew {
		t.Fatal("hostname inside probation not marked new")
	}
	if summary := store.Summary("aged.example.com", ""); summary.IsNew {
		t.Fatal("hostname past probation still marked new")
	}
	if summary := store.Summary("rotated.example.com", ""); !summary.IdentityChangedRecently {
		t.Fatal("recent owner-key change not flagged")
	}
	if summary := store.Summary("dormant.example.com", ""); summary.IdentityChangedRecently {
		t.Fatal("owner-key change past probation still flagged")
	}
}

// TestReputationAPIVoteIssuesVoterCookieOnce pins the voter-identity surface:
// the first cookieless vote mints a persistent HttpOnly voter cookie that
// attributes later reads and votes, and the cookie is never reissued.
func TestReputationAPIVoteIssuesVoterCookieOnce(t *testing.T) {
	t.Parallel()
	api := newTestReputationAPI(t)
	api.reputation.ObserveLive([]LiveLease{{Hostname: "demo.example.com", IdentityKey: "owner-key-1"}})

	recorder := postVote(t, api, `{"hostname":"demo.example.com","vote":"down"}`, "", "")
	if recorder.Code != http.StatusOK {
		t.Fatalf("first vote status = %d, want %d", recorder.Code, http.StatusOK)
	}
	var issued *http.Cookie
	for _, cookie := range recorder.Result().Cookies() {
		if cookie.Name == reputationVoterCookie {
			issued = cookie
		}
	}
	if issued == nil {
		t.Fatal("first vote did not issue a voter cookie")
	}
	if !validReputationVoterID(issued.Value) {
		t.Fatalf("issued voter id %q has unexpected shape", issued.Value)
	}
	if !issued.HttpOnly || !issued.Secure || issued.SameSite != http.SameSiteLaxMode {
		t.Fatalf("cookie flags = httponly=%v secure=%v samesite=%v", issued.HttpOnly, issued.Secure, issued.SameSite)
	}
	if issued.Path != types.PathAPIPrefix {
		t.Fatalf("cookie path = %q, want %q", issued.Path, types.PathAPIPrefix)
	}
	if want := int((365 * 24 * time.Hour).Seconds()); issued.MaxAge != want {
		t.Fatalf("cookie max age = %d, want %d", issued.MaxAge, want)
	}

	recorder = getReputation(t, api, "demo.example.com", issued.Value)
	summary := decodeSummary(t, recorder)
	if summary.ViewerVote != "down" || summary.Down != 1 {
		t.Fatalf("viewer attribution = viewer=%q down=%d", summary.ViewerVote, summary.Down)
	}

	recorder = postVote(t, api, `{"hostname":"demo.example.com","vote":"down"}`, issued.Value, "")
	if recorder.Code != http.StatusOK {
		t.Fatalf("repeat vote status = %d, want %d", recorder.Code, http.StatusOK)
	}
	if got := len(recorder.Result().Cookies()); got != 0 {
		t.Fatalf("repeat vote reissued %d cookies", got)
	}
	summary = decodeSummary(t, getReputation(t, api, "demo.example.com", issued.Value))
	if summary.Down != 1 {
		t.Fatalf("repeat vote grew the count: down=%d", summary.Down)
	}
}

// TestReputationAPIRejectsInvalidInputWithoutStateChange pins the admission
// gates: malformed hostnames, vote values, bodies, unserved hostnames, and
// wrong methods all fail with standard codes and leave no state behind.
func TestReputationAPIRejectsInvalidInputWithoutStateChange(t *testing.T) {
	t.Parallel()
	api := newTestReputationAPI(t)

	for _, hostname := range []string{"", "not a hostname", "-lead.example.com", "trail-.example.com", "under_score.example.com", "double..dot.example.com"} {
		recorder := getReputation(t, api, hostname, "")
		if recorder.Code != http.StatusBadRequest || decodeErrorCode(t, recorder) != types.APIErrorCodeInvalidRequest {
			t.Fatalf("invalid hostname %q: status=%d code=%s", hostname, recorder.Code, recorder.Body.String())
		}
	}

	summary := decodeSummary(t, getReputation(t, api, "Demo.Example.COM.", ""))
	if summary.Up != 0 || summary.Down != 0 || summary.Total != 0 || summary.ViewerVote != "" {
		t.Fatalf("unknown hostname read = %+v, want zero aggregate", summary)
	}

	for _, body := range []string{
		`{"hostname":"demo.example.com","vote":"sideways"}`,
		`{"hostname":"demo.example.com"}`,
		`{not json}`,
	} {
		recorder := postVote(t, api, body, "", "")
		if recorder.Code != http.StatusBadRequest || decodeErrorCode(t, recorder) != types.APIErrorCodeInvalidRequest {
			t.Fatalf("invalid body %s: status=%d code=%s", body, recorder.Code, recorder.Body.String())
		}
	}

	recorder := postVote(t, api, `{"hostname":"unknown.example.com","vote":"up"}`, "", "")
	if recorder.Code != http.StatusNotFound || decodeErrorCode(t, recorder) != types.APIErrorCodeNotFound {
		t.Fatalf("unserved hostname vote: status=%d code=%s", recorder.Code, recorder.Body.String())
	}
	if api.reputation.Knows("unknown.example.com") {
		t.Fatal("rejected vote left a record for an unserved hostname")
	}

	recorder = reputationRequest(t, api, http.MethodGet, types.PathReputationVote, "", "", "")
	if recorder.Code != http.StatusMethodNotAllowed || decodeErrorCode(t, recorder) != types.APIErrorCodeMethodNotAllowed {
		t.Fatalf("GET vote endpoint: status=%d code=%s", recorder.Code, recorder.Body.String())
	}
	recorder = reputationRequest(t, api, http.MethodPost, types.PathReputation, `{"hostname":"demo.example.com","vote":"up"}`, "", "")
	if recorder.Code != http.StatusMethodNotAllowed || decodeErrorCode(t, recorder) != types.APIErrorCodeMethodNotAllowed {
		t.Fatalf("POST summary endpoint: status=%d code=%s", recorder.Code, recorder.Body.String())
	}
}

// TestReputationAPIRateLimitsPerSource pins burst admission: votes past the
// per-source burst get 429 with retry guidance and change nothing, while other
// sources keep voting. Uses a pre-existing voter cookie so the cookieless mint
// budget does not interfere with the rate-limiter test.
func TestReputationAPIRateLimitsPerSource(t *testing.T) {
	t.Parallel()
	api := newTestReputationAPI(t)
	const hostname = "busy.example.com"
	api.reputation.ObserveLive([]LiveLease{{Hostname: hostname, IdentityKey: "owner-key-1"}})
	burst := defaultReputationConfig().VoteSourceBurst

	// Issue one voter cookie so the cookieless mint check is bypassed.
	existingVoterID, err := issueReputationVoterID()
	if err != nil {
		t.Fatal(err)
	}
	voterHash := api.reputation.VoterHash(existingVoterID)

	for i := range burst {
		recorder := postVote(t, api, `{"hostname":"busy.example.com","vote":"up"}`, existingVoterID, "")
		if recorder.Code != http.StatusOK {
			t.Fatalf("burst vote %d status = %d, want %d", i, recorder.Code, http.StatusOK)
		}
	}
	// Same-voter repeats are idempotent: the burst is admitted (200 above)
	// but counts a single vote.
	summary := decodeSummary(t, getReputation(t, api, hostname, voterHash))
	if summary.Up != 1 || summary.Down != 0 {
		t.Fatalf("same-voter burst aggregate = up=%d down=%d, want up=1 down=0", summary.Up, summary.Down)
	}

	rejected := postVote(t, api, `{"hostname":"busy.example.com","vote":"down"}`, existingVoterID, "")
	if rejected.Code != http.StatusTooManyRequests || decodeErrorCode(t, rejected) != types.APIErrorCodeRateLimited {
		t.Fatalf("over-burst vote: status=%d code=%s", rejected.Code, rejected.Body.String())
	}
	retryAfter, err := strconv.Atoi(rejected.Header().Get("Retry-After"))
	if err != nil || retryAfter < 1 {
		t.Fatalf("Retry-After = %q, want a positive integer", rejected.Header().Get("Retry-After"))
	}
	if got := len(rejected.Result().Cookies()); got != 0 {
		t.Fatalf("rejected vote issued %d cookies", got)
	}
	summary = decodeSummary(t, getReputation(t, api, hostname, voterHash))
	if summary.Up != 1 || summary.Down != 0 {
		t.Fatalf("rejected vote changed the aggregate: up=%d down=%d", summary.Up, summary.Down)
	}

	recorder := postVote(t, api, `{"hostname":"busy.example.com","vote":"down"}`, existingVoterID, "203.0.113.9:4444")
	if recorder.Code != http.StatusOK {
		t.Fatalf("other source status = %d, want %d", recorder.Code, http.StatusOK)
	}
	summary = decodeSummary(t, getReputation(t, api, hostname, ""))
	if summary.Down != 1 {
		t.Fatalf("other source vote missing: down=%d", summary.Down)
	}
}

// TestReputationAPIBlocksCookielessMintOverLimit pins blocker 1: cookieless votes
// are rejected with 429 once a source IP has already minted MaxVotersPerSource
// voter IDs through the HTTP layer. Existing voters presenting their cookie can
// still change their vote.
func TestReputationAPIBlocksCookielessMintOverLimit(t *testing.T) {
	t.Parallel()
	cfg := defaultReputationConfig()
	cfg.MaxVotersPerSource = 2
	cfg.VoteSourcePerMinute = 100
	cfg.VoteSourceBurst = 100
	api := newTestReputationAPI(t)
	if err := api.applyReputationConfig(cfg); err != nil {
		t.Fatal(err)
	}
	const hostname = "mint-limit.example.com"
	api.reputation.ObserveLive([]LiveLease{{Hostname: hostname, IdentityKey: "owner-key-1"}})

	// Mint MaxVotersPerSource voter IDs through the HTTP layer so the
	// per-source mint budget is actually exercised.
	body := fmt.Sprintf(`{"hostname":%q,"vote":"up"}`, hostname)
	var cookies []string
	for i := 0; i < cfg.MaxVotersPerSource; i++ {
		recorder := postVote(t, api, body, "", "")
		if recorder.Code != http.StatusOK {
			t.Fatalf("setup mint %d status = %d, want 200", i, recorder.Code)
		}
		var issued *http.Cookie
		for _, c := range recorder.Result().Cookies() {
			if c.Name == reputationVoterCookie {
				issued = c
				break
			}
		}
		if issued == nil {
			t.Fatalf("setup mint %d issued no voter cookie", i)
		}
		cookies = append(cookies, issued.Value)
	}

	// The next cookieless mint from the same source is rejected, and the
	// rejection issues no replacement cookie.
	recorder := postVote(t, api, fmt.Sprintf(`{"hostname":%q,"vote":"down"}`, hostname), "", "")
	if recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("over-limit cookieless vote status = %d, want 429", recorder.Code)
	}
	if decodeErrorCode(t, recorder) != types.APIErrorCodeRateLimited {
		t.Fatalf("error code = %s, want rate_limited", decodeErrorCode(t, recorder))
	}
	for _, c := range recorder.Result().Cookies() {
		if c.Name == reputationVoterCookie {
			t.Fatal("rejected mint issued a voter cookie")
		}
	}

	// Existing voters presenting their cookie can still change their vote.
	for i, cookie := range cookies {
		recorder := postVote(t, api, fmt.Sprintf(`{"hostname":%q,"vote":"down"}`, hostname), cookie, "")
		if recorder.Code != http.StatusOK {
			t.Fatalf("existing voter %d vote switch status = %d, want 200", i, recorder.Code)
		}
	}
	summary := decodeSummary(t, getReputation(t, api, hostname, ""))
	if summary.Up != 0 || summary.Down != 2 {
		t.Fatalf("after switches: up=%d down=%d, want up=0 down=2", summary.Up, summary.Down)
	}
}

// TestReputationHostnameVoterLimitPinsPerHostnameBudget pins blocker 2 (hostname leg):
// a new voter for a hostname is rejected with 429 when MaxVotersPerHostname is
// reached; existing voters can still change their vote.
func TestReputationHostnameVoterLimit(t *testing.T) {
	t.Parallel()
	cfg := defaultReputationConfig()
	cfg.MaxVotersPerHostname = 2
	store, _ := newTestReputationStore(t, cfg)
	const hostname = "hostname-limit.example.com"
	store.ObserveLive([]LiveLease{{Hostname: hostname, IdentityKey: "owner-key-1"}})

	var voterIDs []string
	for i := 0; i < cfg.MaxVotersPerHostname; i++ {
		voterID, err := issueReputationVoterID()
		if err != nil {
			t.Fatal(err)
		}
		voterIDs = append(voterIDs, voterID)
		if _, err := store.Vote(hostname, store.VoterHash(voterID), "up"); err != nil {
			t.Fatalf("setup vote %d: %v", i, err)
		}
	}

	// A new voter (no pre-existing entry) is rejected.
	newVoterID, _ := issueReputationVoterID()
	_, err := store.Vote(hostname, store.VoterHash(newVoterID), "up")
	if err == nil || !errors.Is(err, ErrReputationBudgetExceeded) {
		t.Fatalf("over-limit new voter: err=%v, want ErrReputationBudgetExceeded", err)
	}

	// Existing voters can still switch sides.
	_, err = store.Vote(hostname, store.VoterHash(voterIDs[0]), "down")
	if err != nil {
		t.Fatalf("existing voter vote switch: %v", err)
	}
}

// TestReputationRelayWideHostnameEviction pins blocker 2 (relay-wide leg):
// once MaxHostnames is reached, a new hostname is admitted by evicting the
// hostname whose LastSeenAt is oldest. All setup hostnames share the same
// LastSeenAt, so any one may be evicted; we verify exactly one pre-existing
// hostname survives and the new one is admitted.
func TestReputationRelayWideHostnameEviction(t *testing.T) {
	t.Parallel()
	cfg := defaultReputationConfig()
	cfg.MaxHostnames = 2
	store, _ := newTestReputationStore(t, cfg)

	// Populate MaxHostnames distinct hostnames via ObserveLive so they exist.
	names := make([]string, cfg.MaxHostnames)
	for i := range names {
		names[i] = fmt.Sprintf("host-%d.example.com", i)
		store.ObserveLive([]LiveLease{{Hostname: names[i], IdentityKey: "key"}})
		voterID, _ := issueReputationVoterID()
		if _, err := store.Vote(names[i], store.VoterHash(voterID), "up"); err != nil {
			t.Fatalf("setup vote for %s: %v", names[i], err)
		}
	}

	// All hostnames are known.
	for _, n := range names {
		if !store.Knows(n) {
			t.Fatalf("store does not know %q", n)
		}
	}

	// A new hostname vote triggers eviction of one of the existing hostnames.
	newHost := "host-new.example.com"
	newVoterID, _ := issueReputationVoterID()
	_, err := store.Vote(newHost, store.VoterHash(newVoterID), "up")
	if err != nil {
		t.Fatalf("new hostname vote: %v", err)
	}

	// Exactly one pre-existing hostname survived.
	survived := 0
	for _, n := range names {
		if store.Knows(n) {
			survived++
		}
	}
	if survived != 1 {
		t.Fatalf("survived hostnames = %d, want exactly 1", survived)
	}
	// New hostname is admitted.
	if !store.Knows(newHost) {
		t.Fatalf("new hostname %q was not admitted", newHost)
	}
}

// TestReputationCookiePathScopedToAPIPrefix pins blocker 3: the voter cookie is
// set with Path=/api so it is sent only on /api/* requests, not on arbitrary
// page loads. This is verified by the existing TestReputationAPIVoteIssuesVoterCookieOnce
// cookie path assertion, so this test documents the browser-path-scoping invariant
// and adds a cross-hostname attribution check.
func TestReputationCookiePathScopedToAPIPrefix(t *testing.T) {
	t.Parallel()
	api := newTestReputationAPI(t)
	api.reputation.ObserveLive([]LiveLease{
		{Hostname: "a.example.com", IdentityKey: "key-a"},
		{Hostname: "b.example.com", IdentityKey: "key-b"},
	})

	// Vote on a.example.com — issues a cookie.
	rec := postVote(t, api, `{"hostname":"a.example.com","vote":"up"}`, "", "")
	if rec.Code != http.StatusOK {
		t.Fatal(rec.Code)
	}
	var cookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == reputationVoterCookie {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("no cookie issued")
	}
	if cookie.Path != types.PathAPIPrefix {
		t.Fatalf("cookie path = %q, want %q", cookie.Path, types.PathAPIPrefix)
	}

	// The same cookie attributes the vote on b.example.com.
	rec2 := getReputation(t, api, "b.example.com", cookie.Value)
	summary := decodeSummary(t, rec2)
	// Cookie was issued for a.example.com, not b.example.com.
	if summary.ViewerVote != "" {
		t.Fatalf("b.example.com viewer_vote = %q, want empty (cookie scoped to /api/a.example.com path)", summary.ViewerVote)
	}

	// Cookie works on a.example.com again.
	rec3 := getReputation(t, api, "a.example.com", cookie.Value)
	summary3 := decodeSummary(t, rec3)
	if summary3.ViewerVote != "up" {
		t.Fatalf("a.example.com viewer_vote = %q, want up", summary3.ViewerVote)
	}
}

// TestReputationSecretSurvivesRestart pins blocker 5: the voter secret is
// persisted in reputation.json and voter identity is stable across restarts,
// without deriving from the relay identity.
func TestReputationSecretSurvivesRestart(t *testing.T) {
	t.Parallel()
	cfg := defaultReputationConfig()
	store, path := newTestReputationStore(t, cfg)

	voterID, _ := issueReputationVoterID()
	voterHash := store.VoterHash(voterID)
	store.Vote("stable.example.com", voterHash, "up")

	// Reopen with same config.
	store2, err := newReputationStore(path, cfg)
	if err != nil {
		t.Fatal(err)
	}
	// VoterHash must be identical — secret persisted.
	if got := store2.VoterHash(voterID); got != voterHash {
		t.Fatalf("voter hash after restart = %q, want %q", got, voterHash)
	}
	// Attribution preserved.
	summary := store2.Summary("stable.example.com", voterHash)
	if summary.ViewerVote != "up" {
		t.Fatalf("viewer vote after restart = %q, want up", summary.ViewerVote)
	}
}

// TestReputationPersistFailureRollsBackMemory pins blocker 7: when persistLocked
// fails, the in-memory state is fully restored (including records created during
// the Vote call).
func TestReputationPersistFailureRollsBackMemory(t *testing.T) {
	cfg := defaultReputationConfig()
	store, _ := newTestReputationStore(t, cfg)
	const hostname = "rollback.example.com"

	// Make persist always fail.
	origPersist := store.persistFn
	store.persistFn = func() error { return errors.New("simulated write failure") }

	_, err := store.Vote(hostname, store.VoterHash("voter-x"), "up")
	if err == nil {
		t.Fatal("expected persist error, got nil")
	}

	// In-memory state must be rolled back.
	summary := store.Summary(hostname, store.VoterHash("voter-x"))
	if summary.Total != 0 {
		t.Fatalf("rolled-back total = %d, want 0", summary.Total)
	}
	if store.Knows(hostname) {
		t.Fatal("rolled-back hostname is still known")
	}

	// Restore and verify normal operation.
	store.persistFn = origPersist
	_, err = store.Vote(hostname, store.VoterHash("voter-y"), "up")
	if err != nil {
		t.Fatalf("after restore: %v", err)
	}
	summary = store.Summary(hostname, store.VoterHash("voter-y"))
	if summary.Total != 1 {
		t.Fatalf("after restore: total=%d, want 1", summary.Total)
	}
}

// TestReputationFirstSeenCapturedOnRegistration pins blocker 4: first_seen_at is
// set when ObserveLive fires during registration, without requiring a /api/state call.
func TestReputationFirstSeenCapturedOnRegistration(t *testing.T) {
	t.Parallel()
	store, _ := newTestReputationStore(t, defaultReputationConfig())
	const hostname = "first-seen.example.com"

	// Simulate registration heartbeat via ObserveLive (called by OnLeasesChanged).
	now := time.Now().UTC()
	store.ObserveLive([]LiveLease{{Hostname: hostname, IdentityKey: "owner-key-1"}})

	summary := store.Summary(hostname, "")
	if summary.FirstSeenAt.IsZero() {
		t.Fatal("first_seen_at not set after ObserveLive")
	}
	if summary.FirstSeenAt.Before(now.Add(-time.Second)) || summary.FirstSeenAt.After(now.Add(time.Second)) {
		t.Fatalf("first_seen_at = %v, want near %v", summary.FirstSeenAt, now)
	}
	if !summary.IsNew {
		t.Fatal("hostname not marked is_new immediately after ObserveLive")
	}
}
