package agent

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
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
	if location := rec.Header().Get("Location"); location != applicationAuthLoginPath+"?next=%2Fprivate%3Fq%3D1" {
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
	handler := newApplicationAuthTestHandler(t, []string{wallet.Identity().Address}, true, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamUser = r.Header.Get("X-Portal-User")
		upstreamAuth = r.Header.Get("X-Portal-Auth")
		w.WriteHeader(http.StatusNoContent)
	}))

	challengeBody, _ := json.Marshal(applicationAuthChallengeRequest{Address: wallet.Identity().Address})
	challengeReq := httptest.NewRequest(http.MethodPost, "https://app.example"+applicationAuthChallengePath, bytes.NewReader(challengeBody))
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
	signature, err := wallet.SignEthereumPersonalMessage(challenge.Message)
	if err != nil {
		t.Fatal(err)
	}
	verifyBody, _ := json.Marshal(applicationAuthVerifyRequest{ChallengeID: challenge.ChallengeID, Message: challenge.Message, Signature: signature})
	verifyReq := httptest.NewRequest(http.MethodPost, "https://app.example"+applicationAuthVerifyPath, bytes.NewReader(verifyBody))
	verifyReq.Header.Set("Origin", "https://app.example")
	verifyRec := httptest.NewRecorder()
	handler.ServeHTTP(verifyRec, verifyReq)
	if verifyRec.Code != http.StatusOK {
		t.Fatalf("verify status = %d, body = %s", verifyRec.Code, verifyRec.Body.String())
	}
	response := verifyRec.Result()
	cookies := response.Cookies()
	if len(cookies) != 1 || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteLaxMode {
		t.Fatalf("session cookie = %#v", cookies)
	}

	protectedReq := httptest.NewRequest(http.MethodGet, "https://app.example/private", nil)
	protectedReq.AddCookie(cookies[0])
	protectedReq.Header.Set("X-Portal-User", "attacker")
	protectedReq.Header.Set("X-Portal-Auth", "attacker")
	protectedRec := httptest.NewRecorder()
	handler.ServeHTTP(protectedRec, protectedReq)
	if protectedRec.Code != http.StatusNoContent {
		t.Fatalf("protected status = %d", protectedRec.Code)
	}
	if upstreamUser != wallet.Identity().Address || upstreamAuth != "siwe" {
		t.Fatalf("identity headers = %q, %q", upstreamUser, upstreamAuth)
	}

	replayReq := httptest.NewRequest(http.MethodPost, "https://app.example"+applicationAuthVerifyPath, bytes.NewReader(verifyBody))
	replayReq.Header.Set("Origin", "https://app.example")
	replayRec := httptest.NewRecorder()
	handler.ServeHTTP(replayRec, replayReq)
	if replayRec.Code != http.StatusUnauthorized {
		t.Fatalf("challenge replay status = %d; want %d", replayRec.Code, http.StatusUnauthorized)
	}
}

func TestApplicationAuthStripsPortalCredentials(t *testing.T) {
	var user, auth, cookies string
	requests := 0
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		user, auth = r.Header.Get("X-Portal-User"), r.Header.Get("X-Portal-Auth")
		cookies = r.Header.Get("Cookie")
	})
	handler := newApplicationAuthTestHandler(t, nil, false, next)
	gate := handler.(*applicationAuth)
	token, err := gate.issueSession(applicationAuthTestWallet(t, "2").Identity().Address, "app.example", applicationAuthTestTime())
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "https://app.example/", nil)
	req.AddCookie(&http.Cookie{Name: "app_session", Value: "abc"})
	req.AddCookie(&http.Cookie{Name: applicationAuthCookieName, Value: token})
	req.Header.Set("X-Portal-User", "attacker")
	req.Header.Set("X-Portal-Auth", "attacker")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if user != "" || auth != "" {
		t.Fatalf("untrusted identity headers reached upstream: %q, %q", user, auth)
	}
	if cookies != "app_session=abc" {
		t.Fatalf("upstream Cookie = %q; want only application cookie", cookies)
	}
	for name, requestToken := range map[string]string{
		"other host": token,
		"tampered":   "x" + token[1:],
	} {
		t.Run(name, func(t *testing.T) {
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
		})
	}
	if requests != 1 {
		t.Fatalf("upstream requests = %d; want 1", requests)
	}
}

func newApplicationAuthTestHandler(t *testing.T, allowed []string, identityHeaders bool, next http.Handler) http.Handler {
	t.Helper()
	handler, err := NewApplicationAuth(next, ApplicationAuthConfig{SigningKey: []byte(strings.Repeat("k", 32)), AllowedWallets: allowed, IdentityHeaders: identityHeaders})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func applicationAuthTestWallet(t *testing.T, digit string) identity.LocalAuthority {
	t.Helper()
	resolved, err := identity.ResolveSecp256k1Identity(strings.Repeat("0", 63) + digit)
	if err != nil {
		t.Fatal(err)
	}
	resolved.Name = "application-auth-test"
	return identity.NewLocalAuthority(resolved)
}

func applicationAuthTestTime() time.Time {
	return time.Now().UTC()
}
