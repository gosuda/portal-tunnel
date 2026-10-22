package gateway

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

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
		upstreamUser = r.Header.Get(types.HeaderPortalUser)
		upstreamAuth = r.Header.Get(types.HeaderPortalAuth)
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
	protectedReq.Header.Set(types.HeaderPortalUser, "attacker")
	protectedReq.Header.Set(types.HeaderPortalAuth, "attacker")
	protectedRec := httptest.NewRecorder()
	handler.ServeHTTP(protectedRec, protectedReq)
	if protectedRec.Code != http.StatusNoContent {
		t.Fatalf("protected status = %d", protectedRec.Code)
	}
	if upstreamUser != wallet.Identity().Address || upstreamAuth != "siwe" {
		t.Fatalf("identity headers = %q, %q", upstreamUser, upstreamAuth)
	}

	// A verified challenge is a short-lived proof: replaying it
	// re-authenticates the same wallet and issues a fresh session
	// (siweauth keeps no replay state, issue #530).
	replayReq := httptest.NewRequest(http.MethodPost, "https://app.example"+applicationAuthVerifyPath, bytes.NewReader(verifyBody))
	replayReq.Header.Set("Origin", "https://app.example")
	replayRec := httptest.NewRecorder()
	handler.ServeHTTP(replayRec, replayReq)
	if replayRec.Code != http.StatusOK {
		t.Fatalf("challenge replay status = %d; want %d", replayRec.Code, http.StatusOK)
	}
	if len(replayRec.Result().Cookies()) != 1 {
		t.Fatalf("challenge replay session cookie missing")
	}
}

func TestApplicationAuthStripsPortalCredentials(t *testing.T) {
	var user, auth, cookies string
	requests := 0
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		user, auth = r.Header.Get(types.HeaderPortalUser), r.Header.Get(types.HeaderPortalAuth)
		cookies = r.Header.Get("Cookie")
	})
	handler := newApplicationAuthTestHandler(t, nil, false, next)
	gate := handler.(*applicationAuth)
	token, err := gate.issueSession(applicationAuthTestWallet(t, "2").Identity().Address, ApplicationAuthProviderSIWE, "app.example", applicationAuthTestTime().Add(applicationAuthSessionTTL))
	if err != nil {
		t.Fatal(err)
	}
	providerlessToken, err := encodeSignedApplicationAuthJSON(gate.signingKey, applicationAuthClaims{Subject: applicationAuthTestWallet(t, "2").Identity().Address, Host: "app.example", ExpiresAt: applicationAuthTestTime().Add(applicationAuthSessionTTL).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "https://app.example/", nil)
	req.AddCookie(&http.Cookie{Name: "app_session", Value: "abc"})
	req.AddCookie(&http.Cookie{Name: applicationAuthCookieName, Value: token})
	req.Header.Set(types.HeaderPortalUser, "attacker")
	req.Header.Set(types.HeaderPortalAuth, "attacker")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if user != "" || auth != "" {
		t.Fatalf("untrusted identity headers reached upstream: %q, %q", user, auth)
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

func TestApplicationAuthCredential(t *testing.T) {
	tunnelIdentity := applicationAuthTestIdentity()
	var upstreamUser, upstreamAuth, upstreamCredential string
	upstreamRequests := 0
	handler, err := NewApplicationAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamRequests++
		upstreamUser, upstreamAuth = r.Header.Get(types.HeaderPortalUser), r.Header.Get(types.HeaderPortalAuth)
		upstreamCredential = r.Header.Get(types.HeaderAccessCredential)
		w.WriteHeader(http.StatusNoContent)
	}), tunnelIdentity, ApplicationAuthConfig{Provider: ApplicationAuthProviderCredential, IdentityHeaders: true})
	if err != nil {
		t.Fatal(err)
	}
	credential, err := IssueApplicationCredential(tunnelIdentity, "app.example", "alice", time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(applicationAuthRedeemRequest{Credential: credential})
	req := httptest.NewRequest(http.MethodPost, "https://app.example"+applicationAuthRedeemPath, bytes.NewReader(body))
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
	protected := httptest.NewRequest(http.MethodGet, "https://app.example/private", nil)
	protected.AddCookie(cookies[0])
	protectedRec := httptest.NewRecorder()
	handler.ServeHTTP(protectedRec, protected)
	if protectedRec.Code != http.StatusNoContent || upstreamUser != "alice" || upstreamAuth != ApplicationAuthProviderCredential {
		t.Fatalf("protected status = %d, identity = %q/%q", protectedRec.Code, upstreamUser, upstreamAuth)
	}
	direct := httptest.NewRequest(http.MethodGet, "https://app.example/api", nil)
	direct.Header.Set(types.HeaderAccessCredential, credential)
	directRec := httptest.NewRecorder()
	handler.ServeHTTP(directRec, direct)
	if directRec.Code != http.StatusNoContent || upstreamUser != "alice" || upstreamAuth != ApplicationAuthProviderCredential || upstreamCredential != "" {
		t.Fatalf("credential header status = %d, identity = %q/%q, upstream credential = %q", directRec.Code, upstreamUser, upstreamAuth, upstreamCredential)
	}
	bobCredential, err := IssueApplicationCredential(tunnelIdentity, "app.example", "bob", time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	credentialAndCookie := httptest.NewRequest(http.MethodGet, "https://app.example/api", nil)
	credentialAndCookie.AddCookie(cookies[0])
	credentialAndCookie.Header.Set(types.HeaderAccessCredential, bobCredential)
	credentialAndCookieRec := httptest.NewRecorder()
	handler.ServeHTTP(credentialAndCookieRec, credentialAndCookie)
	if credentialAndCookieRec.Code != http.StatusNoContent || upstreamUser != "bob" {
		t.Fatalf("credential with cookie status = %d, user = %q; want bob", credentialAndCookieRec.Code, upstreamUser)
	}
	invalidCredential := httptest.NewRequest(http.MethodGet, "https://app.example/api", nil)
	invalidCredential.AddCookie(cookies[0])
	invalidCredential.Header.Set(types.HeaderAccessCredential, "invalid")
	invalidCredentialRec := httptest.NewRecorder()
	handler.ServeHTTP(invalidCredentialRec, invalidCredential)
	if invalidCredentialRec.Code == http.StatusNoContent || upstreamRequests != 3 {
		t.Fatalf("invalid credential with cookie status = %d, upstream requests = %d; want rejection", invalidCredentialRec.Code, upstreamRequests)
	}
}

func TestApplicationAuthCredentialAllowlistAndRevocation(t *testing.T) {
	tunnelIdentity := applicationAuthTestIdentity()
	aliceCredential, err := IssueApplicationCredential(tunnelIdentity, "app.example", "alice", time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	bobCredential, err := IssueApplicationCredential(tunnelIdentity, "app.example", "bob", time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}

	// Step 1: Both alice and bob are allowed; alice redeems a browser session cookie.
	initialGate, err := NewApplicationAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), tunnelIdentity, ApplicationAuthConfig{
		Provider:        ApplicationAuthProviderCredential,
		AllowedWallets:  []string{"alice", "bob"},
		IdentityHeaders: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	redeemBody, _ := json.Marshal(applicationAuthRedeemRequest{Credential: aliceCredential})
	redeemReq := httptest.NewRequest(http.MethodPost, "https://app.example"+applicationAuthRedeemPath, bytes.NewReader(redeemBody))
	redeemReq.Header.Set("Origin", "https://app.example")
	redeemRec := httptest.NewRecorder()
	initialGate.ServeHTTP(redeemRec, redeemReq)
	if redeemRec.Code != http.StatusOK {
		t.Fatalf("alice redeem status = %d", redeemRec.Code)
	}
	aliceCookie := redeemRec.Result().Cookies()[0]

	// Step 2: Revoke alice by restricting AllowedWallets to bob only.
	revokedGate, err := NewApplicationAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), tunnelIdentity, ApplicationAuthConfig{
		Provider:        ApplicationAuthProviderCredential,
		AllowedWallets:  []string{"bob"},
		IdentityHeaders: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Revoked subject cannot redeem a credential.
	revokedRedeemReq := httptest.NewRequest(http.MethodPost, "https://app.example"+applicationAuthRedeemPath, bytes.NewReader(redeemBody))
	revokedRedeemReq.Header.Set("Origin", "https://app.example")
	revokedRedeemRec := httptest.NewRecorder()
	revokedGate.ServeHTTP(revokedRedeemRec, revokedRedeemReq)
	if revokedRedeemRec.Code != http.StatusUnauthorized {
		t.Fatalf("revoked redeem status = %d; want 401", revokedRedeemRec.Code)
	}

	// Revoked subject's existing session cookie is rejected on the next request.
	revokedCookieReq := httptest.NewRequest(http.MethodGet, "https://app.example/private", nil)
	revokedCookieReq.AddCookie(aliceCookie)
	revokedCookieRec := httptest.NewRecorder()
	revokedGate.ServeHTTP(revokedCookieRec, revokedCookieReq)
	if revokedCookieRec.Code != http.StatusSeeOther {
		t.Fatalf("revoked session status = %d; want 303", revokedCookieRec.Code)
	}

	// Revoked subject's direct credential header is also rejected.
	revokedHeaderReq := httptest.NewRequest(http.MethodGet, "https://app.example/api", nil)
	revokedHeaderReq.Header.Set(types.HeaderAccessCredential, aliceCredential)
	revokedHeaderRec := httptest.NewRecorder()
	revokedGate.ServeHTTP(revokedHeaderRec, revokedHeaderReq)
	if revokedHeaderRec.Code != http.StatusSeeOther {
		t.Fatalf("revoked header status = %d; want 303", revokedHeaderRec.Code)
	}

	// Allowed subject (bob) continues to succeed.
	bobHeaderReq := httptest.NewRequest(http.MethodGet, "https://app.example/api", nil)
	bobHeaderReq.Header.Set(types.HeaderAccessCredential, bobCredential)
	bobHeaderRec := httptest.NewRecorder()
	revokedGate.ServeHTTP(bobHeaderRec, bobHeaderReq)
	if bobHeaderRec.Code != http.StatusNoContent {
		t.Fatalf("allowed bob header status = %d; want 204", bobHeaderRec.Code)
	}
}

func TestApplicationAuthOIDCPKCEAndRevocation(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwk := jose.JSONWebKey{Key: &privateKey.PublicKey, KeyID: "k1", Algorithm: string(jose.ES256), Use: "sig"}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: privateKey}, (&jose.SignerOptions{}).WithHeader("kid", "k1").WithType("JWT"))
	if err != nil {
		t.Fatal(err)
	}

	var (
		issuerURL         string
		capturedChallenge string
		capturedNonce     string
	)
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(oidcDiscoveryDocument{
				Issuer:                issuerURL,
				AuthorizationEndpoint: issuerURL + "/authorize",
				TokenEndpoint:         issuerURL + "/token",
				JWKSURI:               issuerURL + "/jwks",
			})
		case "/jwks":
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}})
		case "/token":
			if err := r.ParseForm(); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			verifier := r.FormValue("code_verifier")
			sum := sha256.Sum256([]byte(verifier))
			if got := base64.RawURLEncoding.EncodeToString(sum[:]); got != capturedChallenge {
				http.Error(w, "pkce mismatch", http.StatusBadRequest)
				return
			}
			now := time.Now().UTC()
			idToken, err := jwt.Signed(signer).Claims(oidcIDTokenClaims{
				Claims: jwt.Claims{
					Issuer:   issuerURL,
					Subject:  "user-123",
					Audience: jwt.Audience{"portal-client"},
					IssuedAt: jwt.NewNumericDate(now),
					Expiry:   jwt.NewNumericDate(now.Add(time.Hour)),
				},
				Nonce:         capturedNonce,
				Email:         "Alice@Example.com",
				EmailVerified: true,
			}).Serialize()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "at_123",
				"token_type":   "Bearer",
				"expires_in":   3600,
				"id_token":     idToken,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer idp.Close()
	issuerURL = idp.URL

	tunnelIdentity := applicationAuthTestIdentity()
	var upstreamUser, upstreamAuth string
	gate, err := NewApplicationAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamUser = r.Header.Get(types.HeaderPortalUser)
		upstreamAuth = r.Header.Get(types.HeaderPortalAuth)
		w.WriteHeader(http.StatusNoContent)
	}), tunnelIdentity, ApplicationAuthConfig{
		Provider:         ApplicationAuthProviderOIDC,
		AllowedWallets:   []string{"alice@example.com"},
		IdentityHeaders:  true,
		OIDCIssuerURL:    issuerURL,
		OIDCClientID:     "portal-client",
		OIDCClientSecret: "portal-secret",
	})
	if err != nil {
		t.Fatal(err)
	}

	// 1. Login redirects to the OIDC provider with S256 PKCE challenge and sets state cookie.
	loginReq := httptest.NewRequest(http.MethodGet, "https://app.example"+applicationAuthLoginPath+"?next=%2Fdashboard", nil)
	loginRec := httptest.NewRecorder()
	gate.ServeHTTP(loginRec, loginReq)
	if loginRec.Code != http.StatusSeeOther {
		t.Fatalf("login status = %d; want 303", loginRec.Code)
	}
	authRedirect, err := url.Parse(loginRec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if got := authRedirect.Query().Get("code_challenge_method"); got != "S256" {
		t.Fatalf("code_challenge_method = %q; want S256", got)
	}
	capturedChallenge = authRedirect.Query().Get("code_challenge")
	capturedNonce = authRedirect.Query().Get("nonce")
	state := authRedirect.Query().Get("state")
	stateCookies := loginRec.Result().Cookies()
	if len(stateCookies) != 1 || stateCookies[0].Name != applicationAuthOIDCStateCookie {
		t.Fatalf("state cookies = %#v", stateCookies)
	}
	// Browsers drop __Host- cookies unless they are Secure, Path=/ and Domain-less.
	if c := stateCookies[0]; c.Path != "/" || !c.Secure || c.Domain != "" {
		t.Fatalf("state cookie attributes = path %q, secure %v, domain %q; want Path=/, Secure, no Domain", c.Path, c.Secure, c.Domain)
	}

	// 2. Callback exchanges code + PKCE verifier, verifies ID token, and issues session cookie.
	cbReq := httptest.NewRequest(http.MethodGet, "https://app.example"+applicationAuthCallbackPath+"?code=authcode&state="+url.QueryEscape(state), nil)
	cbReq.AddCookie(stateCookies[0])
	cbRec := httptest.NewRecorder()
	gate.ServeHTTP(cbRec, cbReq)
	if cbRec.Code != http.StatusSeeOther || cbRec.Header().Get("Location") != "/dashboard" {
		t.Fatalf("callback status = %d, location = %q", cbRec.Code, cbRec.Header().Get("Location"))
	}
	var sessionCookie *http.Cookie
	for _, c := range cbRec.Result().Cookies() {
		switch c.Name {
		case applicationAuthCookieName:
			sessionCookie = c
		case applicationAuthOIDCStateCookie:
			if c.Path != "/" || c.MaxAge >= 0 {
				t.Fatalf("state cookie expiry = path %q, max-age %d; want Path=/ and deletion", c.Path, c.MaxAge)
			}
		}
	}
	if sessionCookie == nil {
		t.Fatal("missing session cookie from OIDC callback")
	}

	// 3. Authenticated request succeeds and injects normalized email principal.
	protectedReq := httptest.NewRequest(http.MethodGet, "https://app.example/dashboard", nil)
	protectedReq.AddCookie(sessionCookie)
	protectedRec := httptest.NewRecorder()
	gate.ServeHTTP(protectedRec, protectedReq)
	if protectedRec.Code != http.StatusNoContent || upstreamUser != "alice@example.com" || upstreamAuth != ApplicationAuthProviderOIDC {
		t.Fatalf("protected status = %d, user = %q, auth = %q", protectedRec.Code, upstreamUser, upstreamAuth)
	}

	// 4. Removing alice@example.com from AllowedWallets immediately revokes the existing OIDC session.
	revokedGate, err := NewApplicationAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), tunnelIdentity, ApplicationAuthConfig{
		Provider:         ApplicationAuthProviderOIDC,
		AllowedWallets:   []string{"bob@example.com"},
		IdentityHeaders:  true,
		OIDCIssuerURL:    issuerURL,
		OIDCClientID:     "portal-client",
		OIDCClientSecret: "portal-secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	revokedReq := httptest.NewRequest(http.MethodGet, "https://app.example/dashboard", nil)
	revokedReq.AddCookie(sessionCookie)
	revokedRec := httptest.NewRecorder()
	revokedGate.ServeHTTP(revokedRec, revokedReq)
	if revokedRec.Code != http.StatusSeeOther {
		t.Fatalf("revoked OIDC session status = %d; want 303", revokedRec.Code)
	}
}

func TestApplicationAuthOIDCPrincipalMatching(t *testing.T) {
	t.Parallel()

	newGate := func(t *testing.T, provider string, allow ...string) *applicationAuth {
		t.Helper()
		cfg := ApplicationAuthConfig{Provider: provider, AllowedWallets: allow}
		if provider == ApplicationAuthProviderOIDC {
			cfg.OIDCIssuerURL = "https://idp.example"
			cfg.OIDCClientID = "portal-client"
		}
		handler, err := NewApplicationAuth(http.NotFoundHandler(), applicationAuthTestIdentity(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		return handler.(*applicationAuth)
	}

	tests := []struct {
		name   string
		allow  []string
		sub    string
		email  string
		status oidcEmailVerified
		want   string
	}{
		{"verified email exact", []string{"alice@example.com"}, "s1", "Alice@Example.com", true, "alice@example.com"},
		{"absent email_verified does not authorize email", []string{"alice@example.com"}, "s1", "alice@example.com", false, ""},
		{"false email_verified does not authorize email", []string{"alice@example.com"}, "s1", "alice@example.com", false, ""},
		{"sub allowlist ignores email_verified", []string{"sub:s1"}, "s1", "alice@example.com", false, "sub:s1"},
		{"subject with leading space cannot impersonate an allowed subject", []string{"sub:s1"}, " s1", "", false, ""},
		{"subject with trailing space cannot impersonate an allowed subject", []string{"sub:s1"}, "s1 ", "", false, ""},
		{"subject with surrounding Unicode space cannot impersonate an allowed subject", []string{"sub:s1"}, "\u00a0s1\u00a0", "", false, ""},
		{"email-shaped sub cannot satisfy an email entry", []string{"alice@example.com"}, "alice@example.com", "", false, ""},
		{"email-shaped sub cannot satisfy an email entry without email_verified", []string{"alice@example.com"}, "alice@example.com", "", false, ""},
		{"email-shaped sub matches a sub: entry", []string{"sub:alice@example.com"}, "alice@example.com", "", false, "sub:alice@example.com"},
		{"sub: entry matches the subject in exactly its case", []string{"sub:Alice@Example.com"}, "Alice@Example.com", "", false, "sub:Alice@Example.com"},
		{"sub: entry rejects a subject that differs only in case", []string{"sub:Alice@Example.com"}, "alice@example.com", "", false, ""},
		{"lowercase sub: entry rejects an uppercase subject", []string{"sub:alice@example.com"}, "Alice@Example.com", "", false, ""},
		{"sub: prefix case does not change the subject case", []string{"SUB:Alice@Example.com"}, "Alice@Example.com", "", false, "sub:Alice@Example.com"},
		{"non-ASCII sub matches only itself", []string{"sub:Kevin"}, "Kevin", "", false, "sub:Kevin"},
		{"ASCII sub: entry rejects a Kelvin-sign lookalike subject", []string{"sub:kevin"}, "Kevin", "", false, ""},
		{"Kelvin-sign email cannot stand in for an ASCII email", []string{"kevin@example.com"}, "s1", "Kevin@example.com", true, ""},
		{"dotted capital I domain cannot stand in for an ASCII domain", []string{"@github.com"}, "s1", "bob@gİthub.com", true, ""},
		{"verified email matches domain", []string{"@Example.com"}, "s1", "bob@example.com", true, "bob@example.com"},
		{"absent email_verified does not match domain", []string{"@example.com"}, "s1", "bob@example.com", false, ""},
		{"domain excludes subdomains", []string{"@example.com"}, "s1", "bob@sub.example.com", true, ""},
		{"domain excludes other domains", []string{"@example.com"}, "s1", "bob@example.org", true, ""},
		{"email-shaped sub never matches a domain", []string{"@example.com"}, "mallory@example.com", "", false, ""},
		{"sub cannot impersonate a domain entry", []string{"@example.com"}, "@example.com", "", false, ""},
		{"verified email claim cannot impersonate a sub: entry", []string{"sub:alice@example.com"}, "s9", "sub:alice@example.com", true, ""},
		{"verified email claim cannot impersonate a sub: entry in another case", []string{"sub:alice@example.com"}, "s9", "SUB:Alice@Example.com", true, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gate := newGate(t, ApplicationAuthProviderOIDC, tt.allow...)
			got, ok := gate.resolveAllowedOIDCSubject(oidcIDTokenClaims{
				Claims:        jwt.Claims{Subject: tt.sub},
				Email:         tt.email,
				EmailVerified: tt.status,
			})
			if got != tt.want || ok != (tt.want != "") {
				t.Fatalf("resolveAllowedOIDCSubject = (%q, %v); want %q", got, ok, tt.want)
			}
		})
	}

	t.Run("domain session remains valid", func(t *testing.T) {
		t.Parallel()
		if !newGate(t, ApplicationAuthProviderOIDC, "@example.com").subjectAllowed("bob@example.com") {
			t.Fatal("domain-authorized subject rejected on session validation")
		}
	})
	t.Run("sub session remains valid", func(t *testing.T) {
		t.Parallel()
		gate := newGate(t, ApplicationAuthProviderOIDC, "sub:alice@example.com")
		if !gate.subjectAllowed("sub:alice@example.com") {
			t.Fatal("sub:-authorized subject rejected on session validation")
		}
		if gate.subjectAllowed("sub:mallory@example.com") {
			t.Fatal("unlisted sub: subject accepted on session validation")
		}
	})
	t.Run("sub session cannot widen to a domain entry", func(t *testing.T) {
		t.Parallel()
		if newGate(t, ApplicationAuthProviderOIDC, "@example.com").subjectAllowed("sub:mallory@example.com") {
			t.Fatal("sub: session subject honored an @domain entry")
		}
	})
	t.Run("credential subjects ignore domain entries", func(t *testing.T) {
		t.Parallel()
		if newGate(t, ApplicationAuthProviderCredential, "@example.com").subjectAllowed("bob@example.com") {
			t.Fatal("credential provider honored an @domain entry")
		}
	})
	t.Run("malformed domain entries are rejected", func(t *testing.T) {
		t.Parallel()
		for _, entry := range []string{"@", "@a@b", "@ex ample.com"} {
			if _, err := NormalizeApplicationAuthOIDCPrincipals([]string{entry}); err == nil {
				t.Fatalf("NormalizeApplicationAuthOIDCPrincipals(%q) = nil error", entry)
			}
		}
	})
	t.Run("untyped or malformed entries are rejected", func(t *testing.T) {
		t.Parallel()
		for _, entry := range []string{"alice", "sub:", "sub: ", "alice@", "alice@a@b", "Kevin@example.com", "@gİthub.com"} {
			if _, err := NormalizeApplicationAuthOIDCPrincipals([]string{entry}); err == nil {
				t.Fatalf("NormalizeApplicationAuthOIDCPrincipals(%q) = nil error", entry)
			}
		}
	})
}

// A session subject is re-normalized on every request, so this rule decides
// whether two provider subjects that differ only in case stay distinct there.
func TestNormalizeOIDCPrincipalKeepsSubjectCase(t *testing.T) {
	t.Parallel()

	tests := []struct {
		raw  string
		want string
	}{
		{"sub:Alice@Example.com", "sub:Alice@Example.com"},
		{"  sub:Alice@Example.com ", "sub:Alice@Example.com"},
		{"SUB:Alice@Example.com", "sub:Alice@Example.com"},
		{"sub:AbC123", "sub:AbC123"},
		{"Alice@Example.com", "alice@example.com"},
	}
	for _, tt := range tests {
		got, err := normalizeOIDCPrincipal(tt.raw)
		if err != nil || got != tt.want {
			t.Errorf("normalizeOIDCPrincipal(%q) = (%q, %v); want %q", tt.raw, got, err, tt.want)
		}
	}
}

func TestApplicationCredentialRejectsOtherHostAndExpiry(t *testing.T) {
	tunnelIdentity := applicationAuthTestIdentity()
	credential, err := IssueApplicationCredential(tunnelIdentity, "app.example", "alice", time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	key, err := identity.DeriveToken(tunnelIdentity, applicationCredentialKeyUse)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyApplicationCredential([]byte(key), tunnelIdentity, "other.example", credential, time.Now().UTC()); err == nil {
		t.Fatal("other host accepted")
	}
	if _, err := verifyApplicationCredential([]byte(key), tunnelIdentity, "app.example", credential, time.Now().UTC().Add(2*time.Hour)); err == nil {
		t.Fatal("expired credential accepted")
	}
}

func newApplicationAuthTestHandler(t *testing.T, allowed []string, identityHeaders bool, next http.Handler) http.Handler {
	t.Helper()
	tunnelIdentity := applicationAuthTestIdentity()
	handler, err := NewApplicationAuth(next, tunnelIdentity, ApplicationAuthConfig{Provider: ApplicationAuthProviderSIWE, AllowedWallets: allowed, IdentityHeaders: identityHeaders})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func applicationAuthTestIdentity() types.Identity {
	return types.Identity{Name: "application-auth-test", Address: "0x0000000000000000000000000000000000000001", TokenSecret: strings.Repeat("k", 32)}
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

// The post-login target comes from a query parameter and a signed cookie, so it
// must never send the browser to another origin.
func TestSanitizeApplicationAuthNext(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		next string
		want string
	}{
		{"plain path", "/dashboard", "/dashboard"},
		{"path with query", "/private?q=1", "/private?q=1"},
		{"root", "/", "/"},
		{"surrounding space is trimmed", "  /dashboard ", "/dashboard"},
		{"empty", "", "/"},
		{"relative path", "dashboard", "/"},
		{"absolute URL", "https://evil.example/", "/"},
		{"scheme-relative URL", "//evil.example/", "/"},
		{"slash then backslash", "/\\evil.example/", "/"},
		{"backslash later in the path", "/a\\b", "/"},
		{"backslash only", "\\evil.example", "/"},
		// Browsers drop tabs and newlines from URLs, so these would become "//evil.example".
		{"tab after the slash", "/\t/evil.example", "/"},
		{"newline after the slash", "/\n/evil.example", "/"},
		{"carriage return after the slash", "/\r/evil.example", "/"},
		{"tab later in the path", "/a\tb", "/"},
		{"delete character", "/a\x7fb", "/"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := sanitizeApplicationAuthNext(tc.next); got != tc.want {
				t.Fatalf("sanitizeApplicationAuthNext(%q) = %q; want %q", tc.next, got, tc.want)
			}
		})
	}
}

// An identity provider authenticates accounts it does not restrict to this
// application, so OIDC must not start without an allowlist.
func TestApplicationAuthOIDCRequiresAllowlist(t *testing.T) {
	t.Parallel()

	cfg := ApplicationAuthConfig{Provider: ApplicationAuthProviderOIDC, OIDCIssuerURL: "https://idp.example", OIDCClientID: oidcTestClientID}
	if err := ValidateApplicationAuthConfig(cfg); err == nil || !strings.Contains(err.Error(), "--auth-allow") {
		t.Fatalf("ValidateApplicationAuthConfig without an allowlist = %v; want an error naming --auth-allow", err)
	}
	if _, err := NewApplicationAuth(http.NotFoundHandler(), applicationAuthTestIdentity(), cfg); err == nil {
		t.Fatal("NewApplicationAuth started OIDC without an allowlist")
	}
	cfg.AllowedWallets = []string{"alice@example.com"}
	if err := ValidateApplicationAuthConfig(cfg); err != nil {
		t.Fatalf("ValidateApplicationAuthConfig with an allowlist: %v", err)
	}
	// siwe and credential keep their open mode: an empty list there still needs a wallet or issued credential.
	if err := ValidateApplicationAuthConfig(ApplicationAuthConfig{Provider: ApplicationAuthProviderCredential}); err != nil {
		t.Fatalf("credential without an allowlist: %v", err)
	}
}

// OIDC allows a sub of up to 255 characters. The session subject gains the
// sub: prefix, so revalidation on later requests must not reject it for length.
func TestApplicationAuthOIDCLongSubSurvivesRevalidation(t *testing.T) {
	t.Parallel()

	sub := strings.Repeat("a", 255)
	handler, err := NewApplicationAuth(http.NotFoundHandler(), applicationAuthTestIdentity(), ApplicationAuthConfig{
		Provider:       ApplicationAuthProviderOIDC,
		AllowedWallets: []string{"sub:" + sub},
		OIDCIssuerURL:  "https://idp.example",
		OIDCClientID:   oidcTestClientID,
	})
	if err != nil {
		t.Fatal(err)
	}
	gate := handler.(*applicationAuth)
	subject, ok := gate.resolveAllowedOIDCSubject(oidcIDTokenClaims{Claims: jwt.Claims{Subject: sub}})
	if !ok {
		t.Fatal("maximum-length sub was not authorized at login")
	}

	rec := httptest.NewRecorder()
	if err := gate.setSession(rec, subject, ApplicationAuthProviderOIDC, "app.example", time.Now(), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "https://app.example/dashboard", nil)
	for _, c := range rec.Result().Cookies() {
		req.AddCookie(c)
	}
	if got, _, ok := gate.authenticateSession(req); !ok || got != subject {
		t.Fatalf("authenticateSession = (%q, %v); want the session to stay valid for %q", got, ok, subject)
	}
}
