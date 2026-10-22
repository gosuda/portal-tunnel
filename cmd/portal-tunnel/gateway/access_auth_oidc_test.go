package gateway

import (
	"cmp"
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
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

const oidcTestClientID = "portal-client"

// oidcTestIdP is a stub identity provider whose ID token can be bent into each
// failure the gateway must refuse.
type oidcTestIdP struct {
	server    *httptest.Server
	issuerURL string
	signer    jose.Signer
	jwk       jose.JSONWebKey
	query     string

	mu          sync.Mutex
	challenge   string
	nonce       string
	mutate      func(*oidcIDTokenClaims)
	signWith    jose.Signer
	rawToken    func(valid string) string
	omitToken   bool
	tokenStatus int
}

func newOIDCTestSigner(t *testing.T, alg jose.SignatureAlgorithm, key any) jose.Signer {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "k1").WithType("JWT"))
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func newOIDCTestIdP(t *testing.T, configure func(*oidcTestIdP)) *oidcTestIdP {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	idp := &oidcTestIdP{
		signer: newOIDCTestSigner(t, jose.ES256, privateKey),
		jwk:    jose.JSONWebKey{Key: &privateKey.PublicKey, KeyID: "k1", Algorithm: string(jose.ES256), Use: "sig"},
	}
	if configure != nil {
		configure(idp)
	}
	idp.server = httptest.NewServer(http.HandlerFunc(idp.serve))
	idp.issuerURL = idp.server.URL
	t.Cleanup(idp.server.Close)
	return idp
}

func (p *oidcTestIdP) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if (r.URL.Path == "/jwks" || r.URL.Path == "/token") && r.URL.RawQuery != strings.TrimPrefix(p.query, "?") {
		http.Error(w, "missing endpoint query", http.StatusBadRequest)
		return
	}
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		_ = json.NewEncoder(w).Encode(oidcDiscoveryDocument{
			Issuer:                p.issuerURL,
			AuthorizationEndpoint: p.issuerURL + "/authorize" + p.query,
			TokenEndpoint:         p.issuerURL + "/token" + p.query,
			JWKSURI:               p.issuerURL + "/jwks" + p.query,
		})
	case "/jwks":
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{p.jwk}})
	case "/token":
		p.serveToken(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (p *oidcTestIdP) serveToken(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.tokenStatus != 0 {
		w.WriteHeader(p.tokenStatus)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	sum := sha256.Sum256([]byte(r.FormValue("code_verifier")))
	if base64.RawURLEncoding.EncodeToString(sum[:]) != p.challenge {
		http.Error(w, "pkce mismatch", http.StatusBadRequest)
		return
	}
	response := map[string]any{"access_token": "at_123", "token_type": "Bearer", "expires_in": 3600}
	if !p.omitToken {
		verified := true
		now := time.Now().UTC()
		claims := oidcIDTokenClaims{
			Claims: jwt.Claims{
				Issuer:   p.issuerURL,
				Subject:  "user-123",
				Audience: jwt.Audience{oidcTestClientID},
				IssuedAt: jwt.NewNumericDate(now),
				Expiry:   jwt.NewNumericDate(now.Add(time.Hour)),
			},
			Nonce:         p.nonce,
			Email:         "alice@example.com",
			EmailVerified: &verified,
		}
		if p.mutate != nil {
			p.mutate(&claims)
		}
		signer := p.signer
		if p.signWith != nil {
			signer = p.signWith
		}
		token, err := jwt.Signed(signer).Claims(claims).Serialize()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if p.rawToken != nil {
			token = p.rawToken(token)
		}
		response["id_token"] = token
	}
	_ = json.NewEncoder(w).Encode(response)
}

func (p *oidcTestIdP) expect(challenge, nonce string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.challenge, p.nonce = challenge, nonce
}

// TestApplicationAuthOIDCCallbackRefusals protects the checks that keep a
// forged or replayed login from becoming a session: each case must answer 401
// without issuing a session cookie, and the one-time state cookie must be
// cleared either way. The control case proves the harness reaches a session.
func TestApplicationAuthOIDCCallbackRefusals(t *testing.T) {
	t.Parallel()

	unverified := false
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	unsigned := func(string) string {
		header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
		payload := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"x","sub":"user-123","aud":"` + oidcTestClientID + `"}`))
		return header + "." + payload + "."
	}

	tests := []struct {
		name      string
		configure func(p *oidcTestIdP)
		tamper    oidcTamper
		loginHost string
		want      int
	}{
		{name: "control: valid login issues a session", want: http.StatusSeeOther},
		{name: "state parameter differs from the state cookie", tamper: withQuery("code=authcode&state=forged"), want: http.StatusUnauthorized},
		{name: "state cookie is missing", tamper: withStateCookie(nil), want: http.StatusUnauthorized},
		{
			name: "state cookie was tampered with",
			tamper: withStateCookie(func(_ *testing.T, _ *applicationAuth, value string) string {
				if value[0] == 'A' {
					return "B" + value[1:]
				}
				return "A" + value[1:]
			}),
			want: http.StatusUnauthorized,
		},
		{name: "state cookie has expired", tamper: withStateCookie(expireOIDCState), want: http.StatusUnauthorized},
		{name: "state cookie was issued for another host", loginHost: "other.example", want: http.StatusUnauthorized},
		{name: "identity provider reports an error", tamper: withQuery("error=access_denied"), want: http.StatusUnauthorized},
		{name: "token endpoint rejects the code", configure: func(p *oidcTestIdP) { p.tokenStatus = http.StatusBadRequest }, want: http.StatusUnauthorized},
		{name: "token response has no id_token", configure: func(p *oidcTestIdP) { p.omitToken = true }, want: http.StatusUnauthorized},
		{name: "nonce does not match", configure: func(p *oidcTestIdP) { p.mutate = func(c *oidcIDTokenClaims) { c.Nonce = "replayed" } }, want: http.StatusUnauthorized},
		{name: "audience is another client", configure: func(p *oidcTestIdP) {
			p.mutate = func(c *oidcIDTokenClaims) { c.Audience = jwt.Audience{"someone-else"} }
		}, want: http.StatusUnauthorized},
		{name: "issuer is another provider", configure: func(p *oidcTestIdP) {
			p.mutate = func(c *oidcIDTokenClaims) { c.Issuer = "https://evil.example" }
		}, want: http.StatusUnauthorized},
		{name: "id token has expired", configure: func(p *oidcTestIdP) {
			p.mutate = func(c *oidcIDTokenClaims) { c.Expiry = jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)) }
		}, want: http.StatusUnauthorized},
		{name: "id token has no expiry", configure: func(p *oidcTestIdP) {
			p.mutate = func(c *oidcIDTokenClaims) { c.Expiry = nil }
		}, want: http.StatusUnauthorized},
		{name: "id token is signed with an unknown key", configure: func(p *oidcTestIdP) {
			p.signWith = newOIDCTestSigner(t, jose.ES256, otherKey)
		}, want: http.StatusUnauthorized},
		{name: "id token uses a symmetric algorithm", configure: func(p *oidcTestIdP) {
			p.signWith = newOIDCTestSigner(t, jose.HS256, []byte("shared-secret-of-sufficient-length"))
		}, want: http.StatusUnauthorized},
		{name: "id token is unsigned", configure: func(p *oidcTestIdP) { p.rawToken = unsigned }, want: http.StatusUnauthorized},
		{name: "id token has no subject", configure: func(p *oidcTestIdP) {
			p.mutate = func(c *oidcIDTokenClaims) { c.Subject = "" }
		}, want: http.StatusUnauthorized},
		{name: "account is not on the allowlist", configure: func(p *oidcTestIdP) {
			p.mutate = func(c *oidcIDTokenClaims) { c.Subject, c.Email = "user-999", "mallory@example.com" }
		}, want: http.StatusUnauthorized},
		{name: "allowed email is not verified", configure: func(p *oidcTestIdP) {
			p.mutate = func(c *oidcIDTokenClaims) { c.EmailVerified = &unverified }
		}, want: http.StatusUnauthorized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			idp := newOIDCTestIdP(t, tt.configure)
			gate := newOIDCTestGate(t, idp)
			login := startOIDCLogin(t, gate, idp, cmp.Or(tt.loginHost, "app.example"))
			rec := httptest.NewRecorder()
			gate.ServeHTTP(rec, login.callbackRequest(t, gate, tt.tamper))
			assertOIDCCallback(t, rec, tt.want)
		})
	}
}

func TestApplicationAuthOIDCEndpointQueries(t *testing.T) {
	t.Parallel()
	idp := newOIDCTestIdP(t, func(p *oidcTestIdP) { p.query = "?tenant=team" })
	gate := newOIDCTestGate(t, idp)
	login := httptest.NewRecorder()
	gate.ServeHTTP(login, httptest.NewRequest(http.MethodGet, "https://app.example"+applicationAuthLoginPath, nil))
	if login.Code != http.StatusSeeOther {
		t.Fatalf("login status = %d, body %q; want 303", login.Code, login.Body.String())
	}
	authURL, err := url.Parse(login.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if got := authURL.Query().Get("tenant"); got != "team" {
		t.Fatalf("authorization endpoint tenant = %q; want team", got)
	}
	idp.expect(authURL.Query().Get("code_challenge"), authURL.Query().Get("nonce"))
	state := oidcLogin{state: authURL.Query().Get("state"), cookie: login.Result().Cookies()[0]}
	callback := httptest.NewRecorder()
	gate.ServeHTTP(callback, state.callbackRequest(t, gate, nil))
	assertOIDCCallback(t, callback, http.StatusSeeOther)
}

func newOIDCTestGate(t *testing.T, idp *oidcTestIdP) *applicationAuth {
	t.Helper()
	handler, err := NewApplicationAuth(http.NotFoundHandler(), applicationAuthTestIdentity(), ApplicationAuthConfig{
		Provider:       ApplicationAuthProviderOIDC,
		AllowedWallets: []string{"alice@example.com"},
		OIDCIssuerURL:  idp.issuerURL,
		OIDCClientID:   oidcTestClientID,
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler.(*applicationAuth)
}

// oidcLogin is the state a browser holds between the login redirect and the callback.
type oidcLogin struct {
	state  string
	cookie *http.Cookie
}

// startOIDCLogin performs the login step and tells the stub IdP which PKCE
// challenge and nonce the callback must carry.
func startOIDCLogin(t *testing.T, gate *applicationAuth, idp *oidcTestIdP, host string) oidcLogin {
	t.Helper()
	rec := httptest.NewRecorder()
	gate.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://"+host+applicationAuthLoginPath, nil))
	authRedirect, err := url.Parse(rec.Header().Get("Location"))
	if err != nil || rec.Code != http.StatusSeeOther {
		t.Fatalf("login = %d, %q, %v", rec.Code, rec.Header().Get("Location"), err)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("login cookies = %#v", cookies)
	}
	idp.expect(authRedirect.Query().Get("code_challenge"), authRedirect.Query().Get("nonce"))
	return oidcLogin{state: authRedirect.Query().Get("state"), cookie: cookies[0]}
}

// callbackRequest is the browser's return from the IdP at app.example, optionally tampered with.
func (l oidcLogin) callbackRequest(t *testing.T, gate *applicationAuth, tamper oidcTamper) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "https://app.example"+applicationAuthCallbackPath+"?code=authcode&state="+url.QueryEscape(l.state), nil)
	req.AddCookie(l.cookie)
	if tamper == nil {
		return req
	}
	return tamper(t, gate, l, req)
}

// assertOIDCCallback checks the status, that a session cookie exists exactly
// when the login succeeded, and that the one-time state cookie is cleared.
func assertOIDCCallback(t *testing.T, rec *httptest.ResponseRecorder, want int) {
	t.Helper()
	if rec.Code != want {
		t.Fatalf("callback status = %d, body %q; want %d", rec.Code, strings.TrimSpace(rec.Body.String()), want)
	}
	var session, clearedState bool
	for _, c := range rec.Result().Cookies() {
		switch c.Name {
		case applicationAuthCookieName:
			session = c.MaxAge >= 0 && c.Value != ""
		case applicationAuthOIDCStateCookie:
			clearedState = c.MaxAge < 0
		}
	}
	if session != (want == http.StatusSeeOther) {
		t.Fatalf("session cookie issued = %v for status %d", session, rec.Code)
	}
	if !clearedState {
		t.Fatal("one-time state cookie was not cleared")
	}
}

// oidcTamper adjusts the callback request after a valid login redirect.
type oidcTamper func(t *testing.T, gate *applicationAuth, login oidcLogin, req *http.Request) *http.Request

func withQuery(query string) oidcTamper {
	return func(_ *testing.T, _ *applicationAuth, _ oidcLogin, req *http.Request) *http.Request {
		req.URL.RawQuery = query
		return req
	}
}

// withStateCookie replaces the state cookie with the rewritten value, or drops
// it when rewrite is nil.
func withStateCookie(rewrite func(t *testing.T, gate *applicationAuth, value string) string) oidcTamper {
	return func(t *testing.T, gate *applicationAuth, login oidcLogin, req *http.Request) *http.Request {
		req.Header.Del("Cookie")
		if rewrite != nil {
			req.AddCookie(&http.Cookie{Name: login.cookie.Name, Value: rewrite(t, gate, login.cookie.Value)})
		}
		return req
	}
}

// expireOIDCState re-signs a state cookie so it has already expired.
func expireOIDCState(t *testing.T, gate *applicationAuth, value string) string {
	t.Helper()
	var claims oidcStateClaims
	if err := decodeSignedApplicationAuthJSON(gate.oidc.stateKey, value, &claims); err != nil {
		t.Fatal(err)
	}
	claims.ExpiresAt = time.Now().Add(-time.Minute).Unix()
	expired, err := encodeSignedApplicationAuthJSON(gate.oidc.stateKey, claims)
	if err != nil {
		t.Fatal(err)
	}
	return expired
}
