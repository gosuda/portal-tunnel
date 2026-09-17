package main

import (
	"crypto/sha256"
	"encoding/base64"
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
	if err := store.ObserveLive([]LiveLease{{Hostname: hostname, IdentityKey: "owner-key-1"}}); err != nil {
		t.Fatal(err)
	}
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
	if err := store.ObserveLive([]LiveLease{{Hostname: hostname, IdentityKey: "owner-key-1"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Vote(hostname, store.VoterHash("voter-a"), "down"); err != nil {
		t.Fatal(err)
	}

	if err := store.ObserveLive([]LiveLease{{Hostname: hostname, IdentityKey: "owner-key-1"}}); err != nil {
		t.Fatal(err)
	}
	summary := store.Summary(hostname, "")
	if summary.IdentityChangedRecently {
		t.Fatal("same identity re-registration flagged as identity change")
	}
	if summary.Down != 1 {
		t.Fatalf("same identity re-registration lost votes: down=%d", summary.Down)
	}

	if err := store.ObserveLive([]LiveLease{{Hostname: hostname, IdentityKey: "owner-key-2"}}); err != nil {
		t.Fatal(err)
	}
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
	if err := api.reputation.ObserveLive([]LiveLease{{Hostname: "demo.example.com", IdentityKey: "owner-key-1"}}); err != nil {
		t.Fatal(err)
	}

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
	if verified, ok := api.reputation.voterIDFromCookie(issued.Value); !ok || verified == "" {
		t.Fatalf("issued voter cookie %q does not carry a verifiable signature", issued.Value)
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
	if err := api.reputation.ObserveLive([]LiveLease{{Hostname: hostname, IdentityKey: "owner-key-1"}}); err != nil {
		t.Fatal(err)
	}
	burst := defaultReputationConfig().VoteSourceBurst

	// Issue one signed voter cookie so the cookieless mint check is bypassed.
	existingVoterID, err := issueReputationVoterID()
	if err != nil {
		t.Fatal(err)
	}
	existingCookie := api.reputation.signReputationVoterID(existingVoterID)
	voterHash := api.reputation.VoterHash(existingVoterID)

	for i := range burst {
		recorder := postVote(t, api, `{"hostname":"busy.example.com","vote":"up"}`, existingCookie, "")
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

	rejected := postVote(t, api, `{"hostname":"busy.example.com","vote":"down"}`, existingCookie, "")
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

	recorder := postVote(t, api, `{"hostname":"busy.example.com","vote":"down"}`, existingCookie, "203.0.113.9:4444")
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
	if err := api.reputation.ObserveLive([]LiveLease{{Hostname: hostname, IdentityKey: "owner-key-1"}}); err != nil {
		t.Fatal(err)
	}

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
	if err := store.ObserveLive([]LiveLease{{Hostname: hostname, IdentityKey: "owner-key-1"}}); err != nil {
		t.Fatal(err)
	}

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

// TestReputationAdmissionEvictsOldestVotelessKeepsVoted pins blocker 2 (relay-wide leg):
// when MaxHostnames is reached, admission evicts the oldest voteless record.
// Voted records are never evicted, even when their LastSeenAt is older, and
// the map length never exceeds MaxHostnames.
func TestReputationAdmissionEvictsOldestVotelessKeepsVoted(t *testing.T) {
	t.Parallel()
	cfg := defaultReputationConfig()
	cfg.MaxHostnames = 2
	store, _ := newTestReputationStore(t, cfg)
	if err := store.ObserveLive([]LiveLease{
		{Hostname: "voted.example.com", IdentityKey: "key"},
		{Hostname: "stale.example.com", IdentityKey: "key"},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Vote("voted.example.com", store.VoterHash("voter-1"), "up"); err != nil {
		t.Fatal(err)
	}
	// White-box: stagger timestamps so the voted record is also the oldest —
	// age alone must not make it evictable.
	store.mu.Lock()
	store.meta.Hostnames["voted.example.com"].LastSeenAt = time.Now().UTC().Add(-time.Hour)
	store.meta.Hostnames["stale.example.com"].LastSeenAt = time.Now().UTC().Add(-time.Minute)
	store.mu.Unlock()

	newVoterID, _ := issueReputationVoterID()
	if _, err := store.Vote("fresh.example.com", store.VoterHash(newVoterID), "up"); err != nil {
		t.Fatalf("admission past a full map: %v", err)
	}
	if !store.Knows("voted.example.com") {
		t.Fatal("voted record was evicted")
	}
	if store.Knows("stale.example.com") {
		t.Fatal("voteless record was not evicted")
	}
	if !store.Knows("fresh.example.com") {
		t.Fatal("new hostname was not admitted")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.meta.Hostnames) > cfg.MaxHostnames {
		t.Fatalf("hostnames = %d, want <= %d", len(store.meta.Hostnames), cfg.MaxHostnames)
	}
}

// TestReputationAdmissionRejectsWhenFullOfVoted pins the fail-closed leg of
// bounded admission: a map full of voted records admits nothing — Vote
// returns ErrReputationBudgetExceeded and ObserveLive skips creation rather
// than evicting a voter.
func TestReputationAdmissionRejectsWhenFullOfVoted(t *testing.T) {
	t.Parallel()
	cfg := defaultReputationConfig()
	cfg.MaxHostnames = 2
	store, _ := newTestReputationStore(t, cfg)
	for _, name := range []string{"full-a.example.com", "full-b.example.com"} {
		if err := store.ObserveLive([]LiveLease{{Hostname: name, IdentityKey: "key"}}); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Vote(name, store.VoterHash(name), "up"); err != nil {
			t.Fatal(err)
		}
	}

	newVoterID, _ := issueReputationVoterID()
	_, err := store.Vote("new.example.com", store.VoterHash(newVoterID), "up")
	if !errors.Is(err, ErrReputationBudgetExceeded) {
		t.Fatalf("vote into voted-full map: err=%v, want ErrReputationBudgetExceeded", err)
	}
	if store.Knows("new.example.com") {
		t.Fatal("rejected vote left a record behind")
	}

	if err := store.ObserveLive([]LiveLease{{Hostname: "new.example.com", IdentityKey: "key"}}); err != nil {
		t.Fatal(err)
	}
	if store.Knows("new.example.com") {
		t.Fatal("ObserveLive created a record past the voted-full budget")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.meta.Hostnames) != cfg.MaxHostnames {
		t.Fatalf("hostnames = %d, want exactly %d", len(store.meta.Hostnames), cfg.MaxHostnames)
	}
}

// TestReputationObserveLiveStormStaysBounded pins the ObserveLive leg of
// bounded admission: a storm of fresh hostnames cannot push the map past
// MaxHostnames.
func TestReputationObserveLiveStormStaysBounded(t *testing.T) {
	t.Parallel()
	cfg := defaultReputationConfig()
	cfg.MaxHostnames = 8
	store, _ := newTestReputationStore(t, cfg)
	storm := make([]LiveLease, 0, 3*cfg.MaxHostnames)
	for i := range 3 * cfg.MaxHostnames {
		storm = append(storm, LiveLease{Hostname: fmt.Sprintf("storm-%d.example.com", i), IdentityKey: "key"})
	}
	if err := store.ObserveLive(storm); err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.meta.Hostnames) != cfg.MaxHostnames {
		t.Fatalf("hostnames after storm = %d, want exactly %d", len(store.meta.Hostnames), cfg.MaxHostnames)
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
	if err := api.reputation.ObserveLive([]LiveLease{
		{Hostname: "a.example.com", IdentityKey: "key-a"},
		{Hostname: "b.example.com", IdentityKey: "key-b"},
	}); err != nil {
		t.Fatal(err)
	}

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
// set when ObserveLive runs (the relay API's reconcile loop pulls the public
// lease set after registration), without requiring a /api/state call.
func TestReputationFirstSeenCapturedOnRegistration(t *testing.T) {
	t.Parallel()
	store, _ := newTestReputationStore(t, defaultReputationConfig())
	const hostname = "first-seen.example.com"

	// Simulate the reconcile loop's pull after a registration.
	now := time.Now().UTC()
	if err := store.ObserveLive([]LiveLease{{Hostname: hostname, IdentityKey: "owner-key-1"}}); err != nil {
		t.Fatal(err)
	}

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

// TestReputationForgedCookieTakesMintPath pins the self-authenticating cookie:
// a manufactured ID without a valid MAC is treated as cookieless — it counts
// against the source's mint budget instead of voting as an existing voter,
// and a correctly signed cookie keeps attributing its real voter.
func TestReputationForgedCookieTakesMintPath(t *testing.T) {
	t.Parallel()
	cfg := defaultReputationConfig()
	cfg.MaxVotersPerSource = 1
	cfg.VoteSourcePerMinute = 100
	cfg.VoteSourceBurst = 100
	api := newTestReputationAPI(t)
	if err := api.applyReputationConfig(cfg); err != nil {
		t.Fatal(err)
	}
	const hostname = "forge.example.com"
	if err := api.reputation.ObserveLive([]LiveLease{{Hostname: hostname, IdentityKey: "key"}}); err != nil {
		t.Fatal(err)
	}

	forge := func(rawID string) string {
		return rawID + "." + base64.RawURLEncoding.EncodeToString(make([]byte, sha256.Size))
	}
	// A valid-shape ID with a garbage MAC: the mint path must kick in.
	forgedID, _ := issueReputationVoterID()
	recorder := postVote(t, api, fmt.Sprintf(`{"hostname":%q,"vote":"down"}`, hostname), forge(forgedID), "203.0.113.50:1111")
	if recorder.Code != http.StatusOK {
		t.Fatalf("forged-cookie vote status = %d, want %d", recorder.Code, http.StatusOK)
	}
	// The forged ID was never recorded as an existing voter: the recorded
	// vote is the single minted replacement, and a fresh cookie was issued.
	summary := decodeSummary(t, getReputation(t, api, hostname, ""))
	if summary.Down != 1 {
		t.Fatalf("forged cookie counted as an existing voter: down=%d, want 1", summary.Down)
	}
	var reissued *http.Cookie
	for _, c := range recorder.Result().Cookies() {
		if c.Name == reputationVoterCookie {
			reissued = c
		}
	}
	if reissued == nil {
		t.Fatal("forged cookie did not take the mint path (no replacement cookie issued)")
	}
	if _, ok := api.reputation.voterIDFromCookie(reissued.Value); !ok {
		t.Fatalf("reissued cookie %q does not verify", reissued.Value)
	}
	if reissued.Value == forge(forgedID) {
		t.Fatal("mint path reissued the forged cookie value")
	}

	// The forged attempt consumed the source's single mint budget.
	recorder = postVote(t, api, fmt.Sprintf(`{"hostname":%q,"vote":"up"}`, hostname), forge(forgedID), "203.0.113.50:1111")
	if recorder.Code != http.StatusTooManyRequests || decodeErrorCode(t, recorder) != types.APIErrorCodeRateLimited {
		t.Fatalf("second forged-cookie vote: status=%d code=%s, want 429 rate_limited", recorder.Code, recorder.Body.String())
	}

	// A correctly signed cookie bypasses the mint budget entirely: the same
	// source is over its mint limit, yet the existing voter can still vote.
	// Repeating the minted voter's "down" side is a no-op on the aggregate.
	recorder = postVote(t, api, fmt.Sprintf(`{"hostname":%q,"vote":"down"}`, hostname), reissued.Value, "203.0.113.50:1111")
	if recorder.Code != http.StatusOK {
		t.Fatalf("signed-cookie vote status = %d, want %d", recorder.Code, http.StatusOK)
	}
	for _, c := range recorder.Result().Cookies() {
		if c.Name == reputationVoterCookie {
			t.Fatal("signed-cookie vote took the mint path (issued a new cookie)")
		}
	}
	summary = decodeSummary(t, getReputation(t, api, hostname, ""))
	if summary.Up != 0 || summary.Down != 1 || summary.Total != 1 {
		t.Fatalf("signed-cookie vote aggregate = up=%d down=%d total=%d, want up=0 down=1 total=1", summary.Up, summary.Down, summary.Total)
	}
}

// TestReputationAPIMintSourceCap pins the mint-source cap: once
// MaxMintSources distinct sources hold minted voter IDs, a new source's
// cookieless mint fails closed with 429 while existing sources keep voting
// and nobody's budget is flushed.
func TestReputationAPIMintSourceCap(t *testing.T) {
	t.Parallel()
	cfg := defaultReputationConfig()
	cfg.MaxMintSources = 1
	api := newTestReputationAPI(t)
	if err := api.applyReputationConfig(cfg); err != nil {
		t.Fatal(err)
	}
	const hostname = "mintcap.example.com"
	if err := api.reputation.ObserveLive([]LiveLease{{Hostname: hostname, IdentityKey: "key"}}); err != nil {
		t.Fatal(err)
	}

	// The first source mints normally.
	recorder := postVote(t, api, `{"hostname":"mintcap.example.com","vote":"up"}`, "", "203.0.113.60:1")
	if recorder.Code != http.StatusOK {
		t.Fatalf("first source mint status = %d, want %d", recorder.Code, http.StatusOK)
	}

	// A second source is rejected with 429 while the cap is held.
	recorder = postVote(t, api, `{"hostname":"mintcap.example.com","vote":"up"}`, "", "203.0.113.61:2")
	if recorder.Code != http.StatusTooManyRequests || decodeErrorCode(t, recorder) != types.APIErrorCodeRateLimited {
		t.Fatalf("second source mint: status=%d code=%s, want 429 rate_limited", recorder.Code, recorder.Body.String())
	}
	for _, c := range recorder.Result().Cookies() {
		if c.Name == reputationVoterCookie {
			t.Fatal("capped source mint issued a voter cookie")
		}
	}

	// The existing source keeps its own budget: its second mint still works
	// and no one's prior votes were flushed.
	recorder = postVote(t, api, `{"hostname":"mintcap.example.com","vote":"down"}`, "", "203.0.113.60:1")
	if recorder.Code != http.StatusOK {
		t.Fatalf("existing source mint past cap = %d, want %d", recorder.Code, http.StatusOK)
	}
	summary := decodeSummary(t, getReputation(t, api, hostname, ""))
	if summary.Up != 1 || summary.Down != 1 {
		t.Fatalf("cap disturbed other budgets: up=%d down=%d, want up=1 down=1", summary.Up, summary.Down)
	}
}

// TestReputationMintReservationRollsBackOnVoteFailure pins mint atomicity:
// when the vote fails after the reservation, the minted ID is removed again
// so the failed attempt does not consume the source's mint budget.
func TestReputationMintReservationRollsBackOnVoteFailure(t *testing.T) {
	t.Parallel()
	cfg := defaultReputationConfig()
	cfg.MaxVotersPerSource = 1
	api := newTestReputationAPI(t)
	if err := api.applyReputationConfig(cfg); err != nil {
		t.Fatal(err)
	}
	const hostname = "rollback-mint.example.com"
	if err := api.reputation.ObserveLive([]LiveLease{{Hostname: hostname, IdentityKey: "key"}}); err != nil {
		t.Fatal(err)
	}

	api.reputation.persistFn = func() error { return errors.New("simulated write failure") }
	recorder := postVote(t, api, fmt.Sprintf(`{"hostname":%q,"vote":"up"}`, hostname), "", "203.0.113.70:9")
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("persist-failure vote status = %d, want %d", recorder.Code, http.StatusInternalServerError)
	}
	api.cookielessMu.Lock()
	tracked := len(api.cookielessSources["203.0.113.70:9"])
	api.cookielessMu.Unlock()
	if tracked != 0 {
		t.Fatalf("failed mint left %d reserved voter IDs, want 0", tracked)
	}

	// With persistence working again, the same source can mint immediately.
	api.reputation.persistFn = nil
	recorder = postVote(t, api, fmt.Sprintf(`{"hostname":%q,"vote":"up"}`, hostname), "", "203.0.113.70:9")
	if recorder.Code != http.StatusOK {
		t.Fatalf("post-rollback mint status = %d, want %d", recorder.Code, http.StatusOK)
	}
}

// TestReputationKnowsRetentionReadOnlyAndVoteRefresh pins retention semantics:
// Knows turns false past Retention without mutating anything, and a vote
// refreshes LastSeenAt so a voted record keeps its directory presence.
func TestReputationKnowsRetentionReadOnlyAndVoteRefresh(t *testing.T) {
	t.Parallel()
	cfg := defaultReputationConfig()
	cfg.Retention = time.Hour
	store, _ := newTestReputationStore(t, cfg)
	const hostname = "retention.example.com"
	if err := store.ObserveLive([]LiveLease{{Hostname: hostname, IdentityKey: "key"}}); err != nil {
		t.Fatal(err)
	}

	// White-box: age the record past Retention.
	expired := time.Now().UTC().Add(-2 * cfg.Retention)
	store.mu.Lock()
	store.meta.Hostnames[hostname].LastSeenAt = expired
	store.mu.Unlock()

	if store.Knows(hostname) {
		t.Fatal("Knows returned true past retention")
	}
	// Read-only: the expired record is untouched; pruning is ObserveLive's job.
	store.mu.Lock()
	if !store.meta.Hostnames[hostname].LastSeenAt.Equal(expired) {
		t.Fatal("Knows mutated LastSeenAt")
	}
	if len(store.meta.Hostnames) != 1 {
		t.Fatalf("Knows mutated the hostname map: %d records", len(store.meta.Hostnames))
	}
	store.mu.Unlock()

	// A vote refreshes LastSeenAt to now.
	if _, err := store.Vote(hostname, store.VoterHash("voter-1"), "up"); err != nil {
		t.Fatal(err)
	}
	if !store.Knows(hostname) {
		t.Fatal("voted record unknown after LastSeenAt refresh")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.meta.Hostnames[hostname].LastSeenAt.Equal(expired) {
		t.Fatal("vote did not refresh LastSeenAt")
	}
}

// TestReputationConstructorPersistsFreshSecret pins the constructor contract:
// a fresh store persists reputation.json (carrying the voter secret) before
// newReputationStore returns, and a reload derives identical voter hashes.
func TestReputationConstructorPersistsFreshSecret(t *testing.T) {
	t.Parallel()
	cfg := defaultReputationConfig()
	path := filepath.Join(t.TempDir(), types.RelayReputationFilename)
	store, err := newReputationStore(path, cfg)
	if err != nil {
		t.Fatal(err)
	}
	voterID, _ := issueReputationVoterID()
	want := store.VoterHash(voterID)

	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("fresh store did not persist its state file: %v", err)
	}
	var meta ReputationMeta
	if err := json.Unmarshal(payload, &meta); err != nil {
		t.Fatal(err)
	}
	if len(meta.VoterSecret) != 32 {
		t.Fatalf("persisted voter secret = %d bytes, want 32", len(meta.VoterSecret))
	}

	reopened, err := newReputationStore(path, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got := reopened.VoterHash(voterID); got != want {
		t.Fatalf("voter hash after reload = %q, want %q", got, want)
	}
}

// TestReputationObserveLivePersistFailureRestores pins ObserveLive atomicity:
// a persist failure restores both the metadata and the prune clock and
// returns the error instead of discarding it.
func TestReputationObserveLivePersistFailureRestores(t *testing.T) {
	t.Parallel()
	store, _ := newTestReputationStore(t, defaultReputationConfig())
	store.persistFn = func() error { return errors.New("simulated write failure") }
	// Backdate the prune clock so the observe actually advances it before
	// the (failing) persist.
	store.mu.Lock()
	store.lastPrune = time.Now().UTC().Add(-2 * reputationPruneInterval)
	pruneBefore := store.lastPrune
	store.mu.Unlock()

	err := store.ObserveLive([]LiveLease{{Hostname: "unpersisted.example.com", IdentityKey: "key"}})
	if err == nil {
		t.Fatal("ObserveLive swallowed the persist failure")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.meta.Hostnames) != 0 {
		t.Fatalf("hostnames after failed observe = %d, want 0", len(store.meta.Hostnames))
	}
	if !store.lastPrune.Equal(pruneBefore) {
		t.Fatal("prune clock advanced past a failed persist")
	}
}
