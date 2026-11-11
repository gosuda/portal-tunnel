package appauth

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestLoginStateFromAnEarlierHoldIsRefused(t *testing.T) {
	t.Parallel()

	const alias = "alias.example"
	now := time.Now().UTC()
	expires := now.Add(applicationAuthLoginStateTTL).Unix()
	checkLoginStateHoldRefusals(t, alias, expires, now)
}

func serveLoginStateAtHold(gate *applicationAuth, since time.Time, req *http.Request) string {
	const alias = "alias.example"
	gate.publicHosts = func() []PublicHost { return []PublicHost{{URL: "https://" + alias, Since: since}} }
	rec := httptest.NewRecorder()
	gate.ServeHTTP(rec, req)
	return rec.Body.String()
}

func seedOIDCLoginStateCase(t *testing.T, alias string, expires int64) (*applicationAuth, func() *http.Request, string) {
	t.Helper()
	oidcGate := newOIDCTestGate(t, newOIDCTestIdP(t, nil), "alice@example.com")
	oidcState, err := encodeSignedApplicationAuthJSON(oidcGate.oidc.stateKey, oidcStateClaims{State: "state", Nonce: "nonce", CodeVerifier: "verifier", Host: alias, Next: "/", ExpiresAt: expires})
	if err != nil {
		t.Fatal(err)
	}
	callback := func() *http.Request {
		req := httptest.NewRequest(http.MethodGet, "https://"+alias+types.PathApplicationAuthCallback+"?state=state&code=code", nil)
		req.AddCookie(&http.Cookie{Name: applicationAuthOIDCStateCookie, Value: oidcState})
		return req
	}
	return oidcGate, callback, "invalid or expired oidc login state"
}

func seedSAMLLoginStateCase(t *testing.T, alias string, expires int64) (*applicationAuth, func() *http.Request, string) {
	t.Helper()
	samlGate := newSAMLTestGate(t, newSAMLTestIdP(t), http.NotFoundHandler(), nil)
	samlState, err := encodeSignedApplicationAuthJSON(samlGate.saml.stateKey, samlStateClaims{RequestID: "request", Host: alias, Next: "/", ExpiresAt: expires})
	if err != nil {
		t.Fatal(err)
	}
	acs := func() *http.Request {
		req := httptest.NewRequest(http.MethodPost, "https://"+alias+types.PathApplicationAuthSAMLACS, strings.NewReader("SAMLResponse=x"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(&http.Cookie{Name: applicationAuthSAMLStateCookie, Value: samlState})
		return req
	}
	return samlGate, acs, "invalid or expired saml login state"
}

func checkLoginStateHoldRefusals(t *testing.T, alias string, expires int64, now time.Time) {
	t.Helper()
	oidcGate, oidcCallback, oidcRefused := seedOIDCLoginStateCase(t, alias, expires)
	samlGate, samlCallback, samlRefused := seedSAMLLoginStateCase(t, alias, expires)
	for _, tt := range []struct {
		name    string
		gate    *applicationAuth
		request func() *http.Request
		refused string
	}{
		{"oidc", oidcGate, oidcCallback, oidcRefused},
		{"saml", samlGate, samlCallback, samlRefused},
	} {
		if body := serveLoginStateAtHold(tt.gate, now.Add(time.Minute), tt.request()); !strings.Contains(body, tt.refused) {
			t.Errorf("%s login from an earlier hold: %s", tt.name, body)
		}
		if body := serveLoginStateAtHold(tt.gate, now.Add(-time.Minute), tt.request()); strings.Contains(body, tt.refused) {
			t.Errorf("%s login from this hold was refused: %s", tt.name, body)
		}
	}
}

func postSIWEChallengeRequest(t *testing.T, handler http.Handler, alias, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "https://"+alias+path, bytes.NewReader(raw))
	req.Header.Set("Origin", "https://"+alias)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func seedSIWEStaleHoldGate(t *testing.T, hosts *atomic.Value, allow string) http.Handler {
	t.Helper()
	handler, err := New(http.NotFoundHandler(), applicationAuthTestIdentity(), Config{
		Provider:    ProviderSIWE,
		Allow:       []string{allow},
		PublicHosts: func() []PublicHost { return hosts.Load().([]PublicHost) },
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func buildSIWEVerifyRequest(t *testing.T, handler http.Handler, wallet identity.LocalAuthority, alias string) applicationAuthVerifyRequest {
	t.Helper()
	asked := postSIWEChallengeRequest(t, handler, alias, types.PathApplicationAuthChallenge, applicationAuthChallengeRequest{Address: wallet.Identity().Address})
	var challenge applicationAuthChallengeResponse
	if err := json.NewDecoder(asked.Body).Decode(&challenge); err != nil {
		t.Fatal(err)
	}
	signature, err := wallet.SignEthereumPersonalMessage(challenge.Message)
	if err != nil {
		t.Fatal(err)
	}
	return applicationAuthVerifyRequest{ChallengeID: challenge.ChallengeID, Message: challenge.Message, Signature: signature}
}

type staleSIWEHold struct {
	handler http.Handler
	hosts   *atomic.Value
	alias   string
	since   time.Time
}

func checkStaleSIWEHoldRefused(t *testing.T, hold staleSIWEHold, verify applicationAuthVerifyRequest) {
	t.Helper()
	hold.hosts.Store([]PublicHost{{URL: "https://" + hold.alias, Since: time.Now().UTC().Add(time.Minute)}})
	if rec := postSIWEChallengeRequest(t, hold.handler, hold.alias, types.PathApplicationAuthVerify, verify); rec.Code == http.StatusOK {
		t.Fatalf("a challenge from an earlier hold signed in: %s", rec.Body)
	}
}

func checkCurrentSIWEHoldAccepted(t *testing.T, hold staleSIWEHold, verify applicationAuthVerifyRequest) {
	t.Helper()
	hold.hosts.Store([]PublicHost{{URL: "https://" + hold.alias, Since: hold.since}})
	if rec := postSIWEChallengeRequest(t, hold.handler, hold.alias, types.PathApplicationAuthVerify, verify); rec.Code != http.StatusOK {
		t.Fatalf("a challenge from this hold = %d: %s", rec.Code, rec.Body)
	}
}

func TestSIWEChallengeFromAnEarlierHoldIsRefused(t *testing.T) {
	t.Parallel()

	const alias = "alias.example"
	wallet := applicationAuthTestWallet(t, "1")
	since := time.Now().UTC().Add(-time.Minute)
	var hosts atomic.Value
	hosts.Store([]PublicHost{{URL: "https://" + alias, Since: since}})
	handler := seedSIWEStaleHoldGate(t, &hosts, wallet.Identity().Address)
	verify := buildSIWEVerifyRequest(t, handler, wallet, alias)
	hold := staleSIWEHold{handler: handler, hosts: &hosts, alias: alias, since: since}
	checkStaleSIWEHoldRefused(t, hold, verify)
	checkCurrentSIWEHoldAccepted(t, hold, verify)
}

func TestApplicationCredentialHeaderPassesFromAnyOrigin(t *testing.T) {
	t.Parallel()

	tunnelIdentity := applicationAuthTestIdentity()
	handler, err := New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), tunnelIdentity, Config{Provider: ProviderCredential})
	if err != nil {
		t.Fatal(err)
	}
	credential, err := IssueCredential(tunnelIdentity, "app.example", "alice", time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "https://app.example/private", nil)
	req.Header.Set("Origin", "https://other.example")
	req.Header.Set(types.HeaderAccessCredential, credential)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d; want %d", rec.Code, http.StatusNoContent)
	}
}

func TestApplicationAuthWithoutSessionIgnoresOrigin(t *testing.T) {
	t.Parallel()

	handler, err := New(http.NotFoundHandler(), applicationAuthTestIdentity(), Config{Provider: ProviderCredential})
	if err != nil {
		t.Fatal(err)
	}
	upgrade := httptest.NewRequest(http.MethodGet, "https://app.example/private", nil)
	upgrade.Header = http.Header{"Connection": {"Upgrade"}, "Upgrade": {"websocket"}, "Origin": {"https://other.example"}}
	upgradeRec := httptest.NewRecorder()
	handler.ServeHTTP(upgradeRec, upgrade)
	if upgradeRec.Code != http.StatusSeeOther {
		t.Fatalf("upgrade status = %d; want %d", upgradeRec.Code, http.StatusSeeOther)
	}
	post := httptest.NewRequest(http.MethodPost, "https://app.example/private", nil)
	post.Header.Set("Origin", "https://other.example")
	postRec := httptest.NewRecorder()
	handler.ServeHTTP(postRec, post)
	if postRec.Code != http.StatusUnauthorized {
		t.Fatalf("post status = %d; want %d", postRec.Code, http.StatusUnauthorized)
	}
}
func TestSameApplicationHost(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		a, b string
		want bool
	}{
		{"app.example", "app.example", true},
		{"app.example", "App.Example", true},
		{"app.example", "app.example.", true},
		{"app.example:443", "app.example", true},
		{"App.Example.:443", "app.example", true},
		{"app.example:8443", "app.example:8443", true},
		{"app.example:8443", "app.example", false},
		{"app.example:1443", "app.example", false},
		{"app.example", "other.example", false},
		{"", "", false},
		{"app.example", "", false},
		{"app.example", "app example", false},
		{"app example", "app example", false},
		{"https://app.example/", "app.example", false},
		{"app.example", "https://app.example", false},
		{"app.example/", "app.example", false},
		{"https://app.example/", "https://app.example/", false},
	} {
		if got := sameApplicationHost(tt.a, tt.b); got != tt.want {
			t.Errorf("sameApplicationHost(%q, %q) = %v; want %v", tt.a, tt.b, got, tt.want)
		}
	}
}

func seedHostSpellingGate(t *testing.T, tunnelIdentity types.Identity) http.Handler {
	t.Helper()
	handler, err := New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), tunnelIdentity, Config{Provider: ProviderCredential})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func redeemHostSpellingSession(t *testing.T, handler http.Handler, tunnelIdentity types.Identity, host string) *http.Cookie {
	t.Helper()
	credential, err := IssueCredential(tunnelIdentity, "app.example", "alice", time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(applicationAuthRedeemRequest{Credential: credential})
	req := httptest.NewRequest(http.MethodPost, "https://"+host+types.PathApplicationAuthRedeem, bytes.NewReader(body))
	req.Header.Set("Origin", "https://"+host)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	cookies := rec.Result().Cookies()
	if rec.Code != http.StatusOK || len(cookies) != 1 {
		t.Fatalf("redeem at %q: status = %d, cookies = %v", host, rec.Code, cookies)
	}
	return cookies[0]
}

func fetchHostSpellingStatus(handler http.Handler, cookie *http.Cookie, host string) int {
	req := httptest.NewRequest(http.MethodGet, "https://"+host+"/private", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec.Code
}

func checkHostSpellingAccepted(t *testing.T, handler http.Handler, cookie *http.Cookie, issuedAt string) {
	t.Helper()
	for _, usedAt := range []string{"app.example", "app.example:443", "App.Example", "app.example."} {
		if got := fetchHostSpellingStatus(handler, cookie, usedAt); got != http.StatusNoContent {
			t.Errorf("a session issued at %q, used at %q: status = %d; want %d", issuedAt, usedAt, got, http.StatusNoContent)
		}
	}
}

func checkHostSpellingRejected(t *testing.T, handler http.Handler, cookie *http.Cookie, issuedAt string) {
	t.Helper()
	for _, usedAt := range []string{"app.example:8443", "other.example"} {
		if got := fetchHostSpellingStatus(handler, cookie, usedAt); got == http.StatusNoContent {
			t.Errorf("a session issued at %q was accepted at %q", issuedAt, usedAt)
		}
	}
}

func TestApplicationSessionFollowsTheHostNotItsSpelling(t *testing.T) {
	t.Parallel()

	tunnelIdentity := applicationAuthTestIdentity()
	handler := seedHostSpellingGate(t, tunnelIdentity)
	for _, issuedAt := range []string{"app.example", "app.example:443"} {
		cookie := redeemHostSpellingSession(t, handler, tunnelIdentity, issuedAt)
		checkHostSpellingAccepted(t, handler, cookie, issuedAt)
		checkHostSpellingRejected(t, handler, cookie, issuedAt)
	}
}

type identityProofGate struct {
	handler  http.Handler
	reached  *bool
	gotProof *[]string
}

func seedIdentityProofGate(t *testing.T, tunnelIdentity types.Identity, cfg Config) identityProofGate {
	t.Helper()
	reached := false
	var gotProof []string
	handler, err := New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		gotProof = r.Header.Values(types.HeaderPortalProof)
		w.WriteHeader(http.StatusNoContent)
	}), tunnelIdentity, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return identityProofGate{handler: handler, reached: &reached, gotProof: &gotProof}
}

func checkIdentityProofAuthenticated(t *testing.T, gate identityProofGate, credential string, wantProof []string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "https://app.example/api", nil)
	req.Header.Set(types.HeaderAccessCredential, credential)
	req.Header.Set(types.HeaderPortalProof, "forged-proof-value")
	rec := httptest.NewRecorder()
	gate.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent || !slices.Equal(*gate.gotProof, wantProof) {
		t.Fatalf("authenticated request: status = %d, upstream %s = %q; want %q", rec.Code, types.HeaderPortalProof, *gate.gotProof, wantProof)
	}
}

func checkIdentityProofRedirected(t *testing.T, gate identityProofGate) {
	t.Helper()
	*gate.reached = false
	req := httptest.NewRequest(http.MethodGet, "https://app.example/api", nil)
	req.Header.Set(types.HeaderPortalProof, identityProofTestValue)
	rec := httptest.NewRecorder()
	gate.handler.ServeHTTP(rec, req)
	if *gate.reached || rec.Code != http.StatusSeeOther {
		t.Fatalf("unauthenticated request: reached upstream = %v, status = %d; want a login redirect", *gate.reached, rec.Code)
	}
}

func TestApplicationAuthIdentityProof(t *testing.T) {
	t.Parallel()

	tunnelIdentity := applicationAuthTestIdentity()
	credential, err := IssueCredential(tunnelIdentity, "app.example", "alice", time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name      string
		cfg       Config
		wantProof []string
	}{
		{"configured", Config{IdentityHeaders: true, IdentityProof: identityProofTestValue}, []string{identityProofTestValue}},
		{"not configured", Config{IdentityHeaders: true}, nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tt.cfg.Provider = ProviderCredential
			gate := seedIdentityProofGate(t, tunnelIdentity, tt.cfg)
			checkIdentityProofAuthenticated(t, gate, credential, tt.wantProof)
			checkIdentityProofRedirected(t, gate)
		})
	}
}

func issueAllowlistCredential(t *testing.T, tunnelIdentity types.Identity, subject string) string {
	t.Helper()
	credential, err := IssueCredential(tunnelIdentity, "app.example", subject, time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return credential
}

func seedAllowlistInitialGate(t *testing.T, tunnelIdentity types.Identity) http.Handler {
	t.Helper()
	initialGate, err := New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), tunnelIdentity, Config{
		Provider:        ProviderCredential,
		Allow:           []string{"alice", "bob"},
		IdentityHeaders: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return initialGate
}

func redeemAllowlistAliceCookie(t *testing.T, initialGate http.Handler, redeemBody []byte) *http.Cookie {
	t.Helper()
	redeemReq := httptest.NewRequest(http.MethodPost, "https://app.example"+types.PathApplicationAuthRedeem, bytes.NewReader(redeemBody))
	redeemReq.Header.Set("Origin", "https://app.example")
	redeemRec := httptest.NewRecorder()
	initialGate.ServeHTTP(redeemRec, redeemReq)
	if redeemRec.Code != http.StatusOK {
		t.Fatalf("alice redeem status = %d", redeemRec.Code)
	}
	return redeemRec.Result().Cookies()[0]
}

func seedAllowlistRevokedGate(t *testing.T, tunnelIdentity types.Identity) http.Handler {
	t.Helper()
	revokedGate, err := New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), tunnelIdentity, Config{
		Provider:        ProviderCredential,
		Allow:           []string{"bob"},
		IdentityHeaders: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return revokedGate
}

func checkRevokedAllowlistRedeem(t *testing.T, revokedGate http.Handler, redeemBody []byte) {
	t.Helper()
	revokedRedeemReq := httptest.NewRequest(http.MethodPost, "https://app.example"+types.PathApplicationAuthRedeem, bytes.NewReader(redeemBody))
	revokedRedeemReq.Header.Set("Origin", "https://app.example")
	revokedRedeemRec := httptest.NewRecorder()
	revokedGate.ServeHTTP(revokedRedeemRec, revokedRedeemReq)
	if revokedRedeemRec.Code != http.StatusUnauthorized {
		t.Fatalf("revoked redeem status = %d; want 401", revokedRedeemRec.Code)
	}
}

func checkRevokedAllowlistCookie(t *testing.T, revokedGate http.Handler, aliceCookie *http.Cookie) {
	t.Helper()
	revokedCookieReq := httptest.NewRequest(http.MethodGet, "https://app.example/private", nil)
	revokedCookieReq.AddCookie(aliceCookie)
	revokedCookieRec := httptest.NewRecorder()
	revokedGate.ServeHTTP(revokedCookieRec, revokedCookieReq)
	if revokedCookieRec.Code != http.StatusSeeOther {
		t.Fatalf("revoked session status = %d; want 303", revokedCookieRec.Code)
	}
}

func checkRevokedAllowlistHeader(t *testing.T, revokedGate http.Handler, aliceCredential string) {
	t.Helper()
	revokedHeaderReq := httptest.NewRequest(http.MethodGet, "https://app.example/api", nil)
	revokedHeaderReq.Header.Set(types.HeaderAccessCredential, aliceCredential)
	revokedHeaderRec := httptest.NewRecorder()
	revokedGate.ServeHTTP(revokedHeaderRec, revokedHeaderReq)
	if revokedHeaderRec.Code != http.StatusSeeOther {
		t.Fatalf("revoked header status = %d; want 303", revokedHeaderRec.Code)
	}
}

func checkAllowlistBobAccepted(t *testing.T, revokedGate http.Handler, bobCredential string) {
	t.Helper()
	bobHeaderReq := httptest.NewRequest(http.MethodGet, "https://app.example/api", nil)
	bobHeaderReq.Header.Set(types.HeaderAccessCredential, bobCredential)
	bobHeaderRec := httptest.NewRecorder()
	revokedGate.ServeHTTP(bobHeaderRec, bobHeaderReq)
	if bobHeaderRec.Code != http.StatusNoContent {
		t.Fatalf("allowed bob header status = %d; want 204", bobHeaderRec.Code)
	}
}

func TestApplicationAuthCredentialAllowlistAndRevocation(t *testing.T) {
	tunnelIdentity := applicationAuthTestIdentity()
	aliceCredential := issueAllowlistCredential(t, tunnelIdentity, "alice")
	bobCredential := issueAllowlistCredential(t, tunnelIdentity, "bob")
	initialGate := seedAllowlistInitialGate(t, tunnelIdentity)
	redeemBody, _ := json.Marshal(applicationAuthRedeemRequest{Credential: aliceCredential})
	aliceCookie := redeemAllowlistAliceCookie(t, initialGate, redeemBody)
	revokedGate := seedAllowlistRevokedGate(t, tunnelIdentity)
	checkRevokedAllowlistRedeem(t, revokedGate, redeemBody)
	checkRevokedAllowlistCookie(t, revokedGate, aliceCookie)
	checkRevokedAllowlistHeader(t, revokedGate, aliceCredential)
	checkAllowlistBobAccepted(t, revokedGate, bobCredential)
}
