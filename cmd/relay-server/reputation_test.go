package main

import (
	"encoding/json"
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
	store, err := newReputationStore(path, cfg, []byte("test-voter-secret"))
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

	reopened, err := newReputationStore(path, cfg, []byte("test-voter-secret"))
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

	otherSecret, err := newReputationStore(path, cfg, []byte("other-secret"))
	if err != nil {
		t.Fatal(err)
	}
	if viewer := otherSecret.Summary(hostname, otherSecret.VoterHash("voter-a")); viewer.ViewerVote != "" {
		t.Fatalf("foreign secret attributed a stored vote to %q", viewer.ViewerVote)
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
	strict := ReputationConfig{
		MinTotal:            2,
		MinDown:             1,
		MinDownRatioPercent: 50,
		Probation:           time.Hour,
		Retention:           24 * time.Hour,
		VoteSourcePerMinute: 60,
		VoteSourceBurst:     60,
	}
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
	store, err := newReputationStore(path, cfg, []byte("test-voter-secret"))
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
	if issued.Path != types.PathReputation {
		t.Fatalf("cookie path = %q, want %q", issued.Path, types.PathReputation)
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
// sources keep voting.
func TestReputationAPIRateLimitsPerSource(t *testing.T) {
	t.Parallel()
	api := newTestReputationAPI(t)
	const hostname = "busy.example.com"
	api.reputation.ObserveLive([]LiveLease{{Hostname: hostname, IdentityKey: "owner-key-1"}})
	burst := defaultReputationConfig().VoteSourceBurst

	for i := range burst {
		recorder := postVote(t, api, `{"hostname":"busy.example.com","vote":"up"}`, "", "")
		if recorder.Code != http.StatusOK {
			t.Fatalf("burst vote %d status = %d, want %d", i, recorder.Code, http.StatusOK)
		}
	}
	summary := decodeSummary(t, getReputation(t, api, hostname, ""))
	if summary.Up != burst {
		t.Fatalf("accepted burst = up=%d, want %d", summary.Up, burst)
	}

	rejected := postVote(t, api, `{"hostname":"busy.example.com","vote":"down"}`, "", "")
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
	summary = decodeSummary(t, getReputation(t, api, hostname, ""))
	if summary.Up != burst || summary.Down != 0 {
		t.Fatalf("rejected vote changed the aggregate: up=%d down=%d", summary.Up, summary.Down)
	}

	recorder := postVote(t, api, `{"hostname":"busy.example.com","vote":"down"}`, "", "203.0.113.9:4444")
	if recorder.Code != http.StatusOK {
		t.Fatalf("other source status = %d, want %d", recorder.Code, http.StatusOK)
	}
	summary = decodeSummary(t, getReputation(t, api, hostname, ""))
	if summary.Down != 1 {
		t.Fatalf("other source vote missing: down=%d", summary.Down)
	}
}
