package appauth

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestApplicationAuthRequiresLogin(t *testing.T) {
	handler := newApplicationAuthTestHandler(t, nil, false, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("unauthenticated request reached upstream")
	}))
	req := httptest.NewRequest(http.MethodGet, "https://app.example/private?q=1", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d; want %d", rec.Code, http.StatusSeeOther)
	}
	if location := rec.Header().Get("Location"); location != types.PathApplicationAuthLogin+"?next=%2Fprivate%3Fq%3D1" {
		t.Fatalf("Location = %q", location)
	}

	req = httptest.NewRequest(http.MethodPost, "https://app.example/private", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("POST status = %d; want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestApplicationAuthSIWEAndIdentityHeaders(t *testing.T) {
	wallet := applicationAuthTestWallet(t, "1")
	var upstreamUser, upstreamAuth string
	var upstreamPortalNames []string
	handler := newApplicationAuthTestHandler(t, []string{wallet.Identity().Address}, true, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamUser = r.Header.Get(types.HeaderPortalUser)
		upstreamAuth = r.Header.Get(types.HeaderPortalAuth)
		upstreamPortalNames = portalHeaderNames(r.Header)
		w.WriteHeader(http.StatusNoContent)
	}))

	challenge := fetchApplicationAuthSIWEChallenge(t, handler, wallet.Identity().Address)
	cookies, verifyBody := redeemApplicationAuthSIWEChallenge(t, handler, wallet, challenge)
	protectedRec := serveApplicationAuthSIWEProtected(t, handler, cookies[0])
	if protectedRec.Code != http.StatusNoContent {
		t.Fatalf("protected status = %d", protectedRec.Code)
	}
	if upstreamUser != wallet.Identity().Address || upstreamAuth != "siwe" {
		t.Fatalf("identity headers = %q, %q", upstreamUser, upstreamAuth)
	}
	if want := []string{types.HeaderPortalAuth, types.HeaderPortalUser}; !slices.Equal(upstreamPortalNames, want) {
		t.Fatalf("portal headers at the upstream = %q; want only %q", upstreamPortalNames, want)
	}

	replayRec := serveApplicationAuthSIWEReplay(t, handler, verifyBody)
	if replayRec.Code != http.StatusOK {
		t.Fatalf("challenge replay status = %d; want %d", replayRec.Code, http.StatusOK)
	}
	if len(replayRec.Result().Cookies()) != 1 {
		t.Fatalf("challenge replay session cookie missing")
	}
}

func fetchApplicationAuthSIWEChallenge(t *testing.T, handler http.Handler, address string) applicationAuthChallengeResponse {
	t.Helper()
	challengeBody, _ := json.Marshal(applicationAuthChallengeRequest{Address: address})
	challengeReq := httptest.NewRequest(http.MethodPost, "https://app.example"+types.PathApplicationAuthChallenge, bytes.NewReader(challengeBody))
	challengeReq.Header.Set("Origin", "https://app.example")
	challengeRec := httptest.NewRecorder()
	handler.ServeHTTP(challengeRec, challengeReq)
	if challengeRec.Code != http.StatusOK {
		t.Fatalf("challenge status = %d, body = %s", challengeRec.Code, challengeRec.Body.String())
	}
	var challenge applicationAuthChallengeResponse
	if err := json.NewDecoder(challengeRec.Body).Decode(&challenge); err != nil {
		t.Fatal(err)
	}
	return challenge
}

func redeemApplicationAuthSIWEChallenge(t *testing.T, handler http.Handler, wallet identity.LocalAuthority, challenge applicationAuthChallengeResponse) ([]*http.Cookie, []byte) {
	t.Helper()
	signature, err := wallet.SignEthereumPersonalMessage(challenge.Message)
	if err != nil {
		t.Fatal(err)
	}
	verifyBody, _ := json.Marshal(applicationAuthVerifyRequest{ChallengeID: challenge.ChallengeID, Message: challenge.Message, Signature: signature})
	verifyReq := httptest.NewRequest(http.MethodPost, "https://app.example"+types.PathApplicationAuthVerify, bytes.NewReader(verifyBody))
	verifyReq.Header.Set("Origin", "https://app.example")
	verifyRec := httptest.NewRecorder()
	handler.ServeHTTP(verifyRec, verifyReq)
	if verifyRec.Code != http.StatusOK {
		t.Fatalf("verify status = %d, body = %s", verifyRec.Code, verifyRec.Body.String())
	}
	cookies := verifyRec.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteLaxMode {
		t.Fatalf("session cookie = %#v", cookies)
	}
	return cookies, verifyBody
}

func serveApplicationAuthSIWEProtected(t *testing.T, handler http.Handler, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	protectedReq := httptest.NewRequest(http.MethodGet, "https://app.example/private", nil)
	protectedReq.AddCookie(cookie)
	protectedReq.Header.Set(types.HeaderPortalUser, "attacker")
	protectedReq.Header.Set(types.HeaderPortalAuth, "attacker")
	protectedReq.Header["X_Portal_User"] = []string{"attacker"}
	protectedReq.Header["X_portal_auth"] = []string{"attacker"}
	protectedRec := httptest.NewRecorder()
	handler.ServeHTTP(protectedRec, protectedReq)
	return protectedRec
}

func serveApplicationAuthSIWEReplay(t *testing.T, handler http.Handler, verifyBody []byte) *httptest.ResponseRecorder {
	t.Helper()
	replayReq := httptest.NewRequest(http.MethodPost, "https://app.example"+types.PathApplicationAuthVerify, bytes.NewReader(verifyBody))
	replayReq.Header.Set("Origin", "https://app.example")
	replayRec := httptest.NewRecorder()
	handler.ServeHTTP(replayRec, replayReq)
	return replayRec
}

func TestApplicationAuthStripsPortalCredentials(t *testing.T) {
	var user, auth, proof, cookies string
	requests := 0
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		user, auth = r.Header.Get(types.HeaderPortalUser), r.Header.Get(types.HeaderPortalAuth)
		proof = r.Header.Get(types.HeaderPortalProof)
		cookies = r.Header.Get("Cookie")
	})
	handler := newApplicationAuthTestHandler(t, nil, false, next)
	gate := handler.(*applicationAuth)
	token := issueStrippedHeaderSession(t, gate)
	providerlessToken := issueProviderlessSession(t, gate)
	req := httptest.NewRequest(http.MethodGet, "https://app.example/", nil)
	req.AddCookie(&http.Cookie{Name: "app_session", Value: "abc"})
	req.AddCookie(&http.Cookie{Name: applicationAuthCookieName, Value: token})
	req.Header.Set(types.HeaderPortalUser, "attacker")
	req.Header.Set(types.HeaderPortalAuth, "attacker")
	req.Header.Set(types.HeaderPortalProof, "attacker")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if user != "" || auth != "" || proof != "" {
		t.Fatalf("untrusted identity headers reached upstream: %q, %q, %q", user, auth, proof)
	}
	if cookies != "app_session=abc" {
		t.Fatalf("upstream Cookie = %q; want only application cookie", cookies)
	}
	for name, requestToken := range map[string]string{
		"other host":       token,
		"tampered":         "x" + token[1:],
		"missing provider": providerlessToken,
	} {
		t.Run(name, func(t *testing.T) {
			checkRejectedSessionRedirects(t, handler, name, requestToken)
		})
	}
	if requests != 1 {
		t.Fatalf("upstream requests = %d; want 1", requests)
	}
}

func issueStrippedHeaderSession(t *testing.T, gate *applicationAuth) string {
	t.Helper()
	token, err := gate.issueSession(Principal{Provider: ProviderSIWE, Subject: applicationAuthTestWallet(t, "2").Identity().Address}, "app.example", time.Now(), applicationAuthTestTime().Add(applicationAuthSessionTTL))
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func issueProviderlessSession(t *testing.T, gate *applicationAuth) string {
	t.Helper()
	providerlessToken, err := encodeSignedApplicationAuthJSON(gate.signingKey, applicationAuthClaims{Subject: applicationAuthTestWallet(t, "2").Identity().Address, Host: "app.example", ExpiresAt: applicationAuthTestTime().Add(applicationAuthSessionTTL).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	return providerlessToken
}

func checkRejectedSessionRedirects(t *testing.T, handler http.Handler, name, requestToken string) {
	t.Helper()
	host := "app.example"
	if name == "other host" {
		host = "other.example"
	}
	req := httptest.NewRequest(http.MethodGet, "https://"+host+"/", nil)
	req.AddCookie(&http.Cookie{Name: applicationAuthCookieName, Value: requestToken})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d; want %d", rec.Code, http.StatusSeeOther)
	}
}

func issueAppCredential(t *testing.T, tunnelIdentity types.Identity, subject string) string {
	t.Helper()
	credential, err := IssueCredential(tunnelIdentity, "app.example", subject, time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return credential
}

func TestApplicationAuthCredential(t *testing.T) {
	tunnelIdentity := applicationAuthTestIdentity()
	var upstreamUser, upstreamAuth, upstreamCredential string
	upstreamRequests := 0
	handler, err := New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamRequests++
		upstreamUser, upstreamAuth = r.Header.Get(types.HeaderPortalUser), r.Header.Get(types.HeaderPortalAuth)
		upstreamCredential = r.Header.Get(types.HeaderAccessCredential)
		w.WriteHeader(http.StatusNoContent)
	}), tunnelIdentity, Config{Provider: ProviderCredential, IdentityHeaders: true})
	if err != nil {
		t.Fatal(err)
	}
	credential := issueAppCredential(t, tunnelIdentity, "alice")
	cookies := redeemCredentialForCookies(t, handler, credential)
	protectedRec := serveProtectedWithCookie(t, handler, cookies[0])
	if protectedRec.Code != http.StatusNoContent || upstreamUser != "alice" || upstreamAuth != ProviderCredential {
		t.Fatalf("protected status = %d, identity = %q/%q", protectedRec.Code, upstreamUser, upstreamAuth)
	}
	directRec := serveProtectedWithCredential(t, handler, credential)
	if directRec.Code != http.StatusNoContent || upstreamUser != "alice" || upstreamAuth != ProviderCredential || upstreamCredential != "" {
		t.Fatalf("credential header status = %d, identity = %q/%q, upstream credential = %q", directRec.Code, upstreamUser, upstreamAuth, upstreamCredential)
	}
	bobCredential := issueAppCredential(t, tunnelIdentity, "bob")
	credentialAndCookieRec := serveCookiePlusCredential(t, handler, cookies[0], bobCredential)
	if credentialAndCookieRec.Code != http.StatusNoContent || upstreamUser != "bob" {
		t.Fatalf("credential with cookie status = %d, user = %q; want bob", credentialAndCookieRec.Code, upstreamUser)
	}
	invalidRec := serveCookiePlusCredential(t, handler, cookies[0], "invalid")
	if invalidRec.Code == http.StatusNoContent || upstreamRequests != 3 {
		t.Fatalf("invalid credential with cookie status = %d, upstream requests = %d; want rejection", invalidRec.Code, upstreamRequests)
	}
}

func redeemCredentialForCookies(t *testing.T, handler http.Handler, credential string) []*http.Cookie {
	t.Helper()
	body, _ := json.Marshal(applicationAuthRedeemRequest{Credential: credential})
	req := httptest.NewRequest(http.MethodPost, "https://app.example"+types.PathApplicationAuthRedeem, bytes.NewReader(body))
	req.Header.Set("Origin", "https://app.example")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("redeem status = %d, body = %s", rec.Code, rec.Body.String())
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies = %#v", cookies)
	}
	return cookies
}

func serveProtectedWithCookie(t *testing.T, handler http.Handler, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	protected := httptest.NewRequest(http.MethodGet, "https://app.example/private", nil)
	protected.AddCookie(cookie)
	protectedRec := httptest.NewRecorder()
	handler.ServeHTTP(protectedRec, protected)
	return protectedRec
}

func serveProtectedWithCredential(t *testing.T, handler http.Handler, credential string) *httptest.ResponseRecorder {
	t.Helper()
	direct := httptest.NewRequest(http.MethodGet, "https://app.example/api", nil)
	direct.Header.Set(types.HeaderAccessCredential, credential)
	directRec := httptest.NewRecorder()
	handler.ServeHTTP(directRec, direct)
	return directRec
}

func serveCookiePlusCredential(t *testing.T, handler http.Handler, cookie *http.Cookie, credential string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "https://app.example/api", nil)
	req.AddCookie(cookie)
	req.Header.Set(types.HeaderAccessCredential, credential)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}
