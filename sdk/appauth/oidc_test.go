package appauth

import (
	"cmp"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/gosuda/portal-tunnel/v2/types"
)

const oidcTestClientID = "portal-client"

type oidcTestIdP struct {
	server    *httptest.Server
	issuerURL string
	signer    jose.Signer
	key       *ecdsa.PrivateKey
	query     string

	clientSecret string
	authMethods  []string

	discoveryHits atomic.Int32
	jwksHits      atomic.Int32

	discoveryEntered chan struct{}
	discoveryRelease chan struct{}

	mu            sync.Mutex
	jwk           jose.JSONWebKey
	extraJWKs     []jose.JSONWebKey
	challenge     string
	nonce         string
	mutate        func(*oidcIDTokenClaims)
	signWith      jose.Signer
	rawToken      func(valid string) string
	emailVerified json.RawMessage
	omitToken     bool
	tokenStatus   int
	tokenRequests []oidcTokenCredentials
}

type oidcTokenCredentials struct {
	inHeader     bool
	clientID     string
	clientSecret string
}

func (p *oidcTestIdP) tokenCredentials() []oidcTokenCredentials {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.tokenRequests)
}

func newOIDCTestSigner(t *testing.T, alg jose.SignatureAlgorithm, key any, kid string) jose.Signer {
	t.Helper()
	opts := (&jose.SignerOptions{}).WithType("JWT")
	if kid != "" {
		opts = opts.WithHeader("kid", kid)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, opts)
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
		signer: newOIDCTestSigner(t, jose.ES256, privateKey, "k1"),
		key:    privateKey,
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
		p.discoveryHits.Add(1)
		p.holdDiscovery(r)
		_ = json.NewEncoder(w).Encode(oidcDiscoveryDocument{
			Issuer:                   p.issuerURL,
			AuthorizationEndpoint:    p.issuerURL + "/authorize" + p.query,
			TokenEndpoint:            p.issuerURL + "/token" + p.query,
			JWKSURI:                  p.issuerURL + "/jwks" + p.query,
			TokenEndpointAuthMethods: p.authMethods,
		})
	case "/jwks":
		p.jwksHits.Add(1)
		p.mu.Lock()
		keys := jose.JSONWebKeySet{Keys: append([]jose.JSONWebKey{p.jwk}, p.extraJWKs...)}
		p.mu.Unlock()
		_ = json.NewEncoder(w).Encode(keys)
	case "/token":
		p.serveToken(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (p *oidcTestIdP) holdDiscovery(r *http.Request) {
	if p.discoveryRelease == nil {
		return
	}
	select {
	case p.discoveryEntered <- struct{}{}:
	default:
	}
	select {
	case <-p.discoveryRelease:
	case <-r.Context().Done():
	}
}

func (p *oidcTestIdP) update(change func(*oidcTestIdP)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	change(p)
}

func (p *oidcTestIdP) rotate(t *testing.T, kid string) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p.update(func(p *oidcTestIdP) {
		p.key = privateKey
		p.signer = newOIDCTestSigner(t, jose.ES256, privateKey, kid)
		p.jwk = jose.JSONWebKey{Key: &privateKey.PublicKey, KeyID: kid, Algorithm: string(jose.ES256), Use: "sig"}
	})
}

func (p *oidcTestIdP) serveToken(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	credentials := oidcTokenCredentials{clientID: r.PostFormValue("client_id"), clientSecret: r.PostFormValue("client_secret")}
	if id, secret, ok := r.BasicAuth(); ok {
		credentials = oidcTokenCredentials{inHeader: true, clientID: id, clientSecret: secret}
	}
	p.tokenRequests = append(p.tokenRequests, credentials)
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
		token, err := p.serveTokenIDTokenLocked()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		response["id_token"] = token
	}
	_ = json.NewEncoder(w).Encode(response)
}
func (p *oidcTestIdP) serveTokenIDTokenLocked() (string, error) {
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
		EmailVerified: true,
	}
	if p.mutate != nil {
		p.mutate(&claims)
	}
	var payload any = claims
	if p.emailVerified != nil {
		payload = oidcRawEmailVerifiedClaims{oidcIDTokenClaims: claims, EmailVerified: p.emailVerified}
	}
	signer := p.signer
	if p.signWith != nil {
		signer = p.signWith
	}
	token, err := jwt.Signed(signer).Claims(payload).Serialize()
	if err != nil {
		return "", err
	}
	if p.rawToken != nil {
		token = p.rawToken(token)
	}
	return token, nil
}

func (p *oidcTestIdP) expect(challenge, nonce string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.challenge, p.nonce = challenge, nonce
}

func completeOIDCLogin(t *testing.T, gate *applicationAuth, idp *oidcTestIdP) *httptest.ResponseRecorder {
	t.Helper()
	login := startOIDCLogin(t, gate, idp, "app.example", types.PathApplicationAuthLogin)
	rec := httptest.NewRecorder()
	gate.ServeHTTP(rec, login.callbackRequest(t, gate, nil))
	return rec
}

func ageOIDCKeys(gate *applicationAuth) {
	gate.oidc.jwks.mu.Lock()
	defer gate.oidc.jwks.mu.Unlock()
	gate.oidc.jwks.fetchedAt = gate.oidc.jwks.fetchedAt.Add(-2 * oidcJWKSRefreshInterval)
}

func awaitOIDC[T any](t *testing.T, ch <-chan T, what string) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(10 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
	var zero T
	return zero
}

func newOIDCTestGate(t *testing.T, idp *oidcTestIdP, allowed ...string) *applicationAuth {
	t.Helper()
	if len(allowed) == 0 {
		allowed = []string{"alice@example.com"}
	}
	handler, err := New(http.NotFoundHandler(), applicationAuthTestIdentity(), Config{
		Provider:   ProviderOIDC,
		Allow:      allowed,
		OIDCConfig: OIDCConfig{OIDCIssuerURL: idp.issuerURL, OIDCClientID: oidcTestClientID, OIDCClientSecret: idp.clientSecret},
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler.(*applicationAuth)
}

type oidcLogin struct {
	state  string
	cookie *http.Cookie
}

func startOIDCLogin(t *testing.T, gate *applicationAuth, idp *oidcTestIdP, host, path string) oidcLogin {
	t.Helper()
	rec := httptest.NewRecorder()
	gate.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://"+host+path, nil))
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
func startRefusedCallbackLogin(t *testing.T, gate *applicationAuth, idp *oidcTestIdP, loginHost string) oidcLogin {
	t.Helper()
	loginHost = cmp.Or(loginHost, "app.example")
	return startOIDCLogin(t, gate, idp, loginHost, types.PathApplicationAuthLogin)
}

func (l oidcLogin) callbackRequest(t *testing.T, gate *applicationAuth, tamper oidcTamper) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "https://app.example"+types.PathApplicationAuthCallback+"?code=authcode&state="+url.QueryEscape(l.state), nil)
	req.AddCookie(l.cookie)
	if tamper == nil {
		return req
	}
	return tamper(t, gate, l, req)
}

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

type oidcTamper func(t *testing.T, gate *applicationAuth, login oidcLogin, req *http.Request) *http.Request

func withQuery(query string) oidcTamper {
	return func(_ *testing.T, _ *applicationAuth, _ oidcLogin, req *http.Request) *http.Request {
		req.URL.RawQuery = query
		return req
	}
}

func withStateCookie(rewrite func(t *testing.T, gate *applicationAuth, value string) string) oidcTamper {
	return func(t *testing.T, gate *applicationAuth, login oidcLogin, req *http.Request) *http.Request {
		req.Header.Del("Cookie")
		if rewrite != nil {
			req.AddCookie(&http.Cookie{Name: login.cookie.Name, Value: rewrite(t, gate, login.cookie.Value)})
		}
		return req
	}
}

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
func TestApplicationAuthOIDCCallbackRefusals(t *testing.T) {
	t.Parallel()

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
			p.signWith = newOIDCTestSigner(t, jose.ES256, otherKey, "k1")
		}, want: http.StatusUnauthorized},
		{name: "id token uses a symmetric algorithm", configure: func(p *oidcTestIdP) {
			p.signWith = newOIDCTestSigner(t, jose.HS256, []byte("shared-secret-of-sufficient-length"), "k1")
		}, want: http.StatusUnauthorized},
		{name: "id token is unsigned", configure: func(p *oidcTestIdP) { p.rawToken = unsigned }, want: http.StatusUnauthorized},
		{name: "id token has no subject", configure: func(p *oidcTestIdP) {
			p.mutate = func(c *oidcIDTokenClaims) { c.Subject = "" }
		}, want: http.StatusUnauthorized},
		{name: "account is not on the allowlist", configure: func(p *oidcTestIdP) {
			p.mutate = func(c *oidcIDTokenClaims) { c.Subject, c.Email = "user-999", "mallory@example.com" }
		}, want: http.StatusUnauthorized},
		{name: "allowed email is not verified", configure: func(p *oidcTestIdP) {
			p.mutate = func(c *oidcIDTokenClaims) { c.EmailVerified = false }
		}, want: http.StatusUnauthorized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			idp := newOIDCTestIdP(t, tt.configure)
			gate := newOIDCTestGate(t, idp)
			login := startRefusedCallbackLogin(t, gate, idp, tt.loginHost)
			rec := httptest.NewRecorder()
			gate.ServeHTTP(rec, login.callbackRequest(t, gate, tt.tamper))
			assertOIDCCallback(t, rec, tt.want)
		})
	}
}

type TestApplicationAuthOIDCFailureScreensCase struct {
	name      string
	configure func(p *oidcTestIdP)
	tamper    oidcTamper
	title     string
	retry     string
}

func TestApplicationAuthOIDCFailureScreens(t *testing.T) {
	t.Parallel()

	tests := []TestApplicationAuthOIDCFailureScreensCase{
		{name: "visitor canceled at the provider", tamper: withQuery("error=access_denied"), title: "Sign-in was canceled"},
		{name: "provider reported another error", tamper: withQuery("error=server_error"), title: "Sign-in could not be completed"},
		{name: "state cookie is missing", tamper: withStateCookie(nil), title: "Sign-in took too long"},
		{name: "state cookie has expired", tamper: withStateCookie(expireOIDCState), title: "Sign-in took too long"},
		{name: "state belongs to another login", tamper: withQuery("code=authcode&state=other"), title: "Sign-in took too long"},
		{name: "token endpoint rejects the code", configure: func(p *oidcTestIdP) { p.tokenStatus = http.StatusBadRequest }, title: "Sign-in could not be completed"},
		{name: "account is not on the allowlist", configure: func(p *oidcTestIdP) {
			p.mutate = func(c *oidcIDTokenClaims) { c.Subject, c.Email = "user-999", "mallory@example.com" }
		}, title: "This account is not allowed", retry: types.PathApplicationAuthLogin + "?prompt=select_account"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			exerciseFailureScreens(t, tt)
		})
	}
}
func exerciseFailureScreens(t *testing.T, tt TestApplicationAuthOIDCFailureScreensCase) {
	t.Helper()
	for _, browser := range []bool{true, false} {
		idp := newOIDCTestIdP(t, tt.configure)
		gate := newOIDCTestGate(t, idp)
		login := startOIDCLogin(t, gate, idp, "app.example", types.PathApplicationAuthLogin)
		req := login.callbackRequest(t, gate, tt.tamper)
		if browser {
			req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		}
		rec := httptest.NewRecorder()
		gate.ServeHTTP(rec, req)
		assertOIDCCallback(t, rec, http.StatusUnauthorized)
		body := rec.Body.String()
		if !browser {
			checkScriptedFailureScreen(t, rec, body)
			continue
		}
		checkBrowserFailureScreen(t, rec, body, tt.title, tt.retry)
	}
}
func checkScriptedFailureScreen(t *testing.T, rec *httptest.ResponseRecorder, body string) {
	t.Helper()
	var answer map[string]string
	if rec.Header().Get("Content-Type") != "application/json" || json.Unmarshal(rec.Body.Bytes(), &answer) != nil || answer["error"] == "" {
		t.Fatalf("scripted caller got %q: %q", rec.Header().Get("Content-Type"), body)
	}
}

func checkBrowserFailureScreen(t *testing.T, rec *httptest.ResponseRecorder, body string, title string, retry string) {
	t.Helper()
	if rec.Header().Get("Content-Type") != "text/html; charset=utf-8" || rec.Header().Get("Content-Security-Policy") != signinContentSecurityPolicy {
		t.Fatalf("browser got %q under CSP %q", rec.Header().Get("Content-Type"), rec.Header().Get("Content-Security-Policy"))
	}
	retry = cmp.Or(retry, types.PathApplicationAuthLogin)
	for _, want := range []string{"<h1>" + title + "</h1>", "app.example", `href="` + retry + `"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("page is missing %q", want)
		}
	}
}

func TestApplicationAuthOIDCDeniedScreenShowsOnlyTheVisitorsAccount(t *testing.T) {
	t.Parallel()

	allowed := []string{"alice@example.com", "@corp.example", "sub:admin-1"}
	tests := []struct {
		name    string
		mutate  func(c *oidcIDTokenClaims)
		account string
	}{
		{name: "verified email", mutate: func(c *oidcIDTokenClaims) { c.Email = "mallory@example.com" }, account: "mallory@example.com"},
		{name: "unverified email", mutate: func(c *oidcIDTokenClaims) {
			c.Subject, c.Email, c.EmailVerified = "user-999", "mallory@example.com", false
		}, account: "sub:user-999"},
		{name: "subject with markup", mutate: func(c *oidcIDTokenClaims) {
			c.Subject, c.EmailVerified = `<img src=x onerror=alert(1)>`, false
		}, account: "sub:&lt;img src=x onerror=alert(1)&gt;"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			idp := newOIDCTestIdP(t, func(p *oidcTestIdP) { p.mutate = tt.mutate })
			gate := newOIDCTestGate(t, idp, allowed...)
			req := startOIDCLogin(t, gate, idp, "app.example", types.PathApplicationAuthLogin).callbackRequest(t, gate, nil)
			req.Header.Set("Accept", "text/html")
			rec := httptest.NewRecorder()
			gate.ServeHTTP(rec, req)
			assertOIDCCallback(t, rec, http.StatusUnauthorized)

			checkDeniedScreenAccount(t, rec.Body.String(), tt.account, allowed)
		})
	}
}
func checkDeniedScreenAccount(t *testing.T, body string, account string, allowed []string) {
	t.Helper()
	if !strings.Contains(body, "<b>"+account+"</b>") {
		t.Fatalf("page does not show the account %q", account)
	}
	if strings.Contains(body, "<img") {
		t.Fatal("account reached the page unescaped")
	}
	for _, entry := range allowed {
		if strings.Contains(body, entry) {
			t.Fatalf("page reveals the allowlist entry %q", entry)
		}
	}
}

func TestApplicationAuthOIDCRetryAsksForAccountChooser(t *testing.T) {
	t.Parallel()

	idp := newOIDCTestIdP(t, func(p *oidcTestIdP) {
		p.mutate = func(c *oidcIDTokenClaims) { c.Subject, c.Email = "user-999", "mallory@example.com" }
	})
	gate := newOIDCTestGate(t, idp)
	login := startOIDCLogin(t, gate, idp, "app.example", types.PathApplicationAuthLogin+"?next="+url.QueryEscape("/docs?page=2"))
	req := login.callbackRequest(t, gate, nil)
	req.Header.Set("Accept", "text/html")
	denied := httptest.NewRecorder()
	gate.ServeHTTP(denied, req)
	assertOIDCCallback(t, denied, http.StatusUnauthorized)
	retry := `href="` + types.PathApplicationAuthLogin + `?next=%2Fdocs%3Fpage%3D2&amp;prompt=select_account"`
	if !strings.Contains(denied.Body.String(), retry) {
		t.Fatalf("retry link is not the account-chooser login: %q", denied.Body.String())
	}

	verifyRetryAccountChooser(t, gate)
}
func verifyRetryAccountChooser(t *testing.T, gate *applicationAuth) {
	t.Helper()
	for _, tt := range []struct {
		name, path string
		chooser    bool
	}{
		{name: "plain login", path: types.PathApplicationAuthLogin},
		{name: "prompt none", path: types.PathApplicationAuthLogin + "?prompt=none"},
		{name: "prompt login", path: types.PathApplicationAuthLogin + "?prompt=login"},
		{name: "account chooser", path: types.PathApplicationAuthLogin + "?prompt=select_account", chooser: true},
	} {
		rec := httptest.NewRecorder()
		gate.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://app.example"+tt.path, nil))
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("%s: login = %d", tt.name, rec.Code)
		}
		authorize, err := url.Parse(rec.Header().Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		prompt, sent := authorize.Query()["prompt"]
		if sent != tt.chooser {
			t.Fatalf("%s: provider got prompt %q, want account chooser %v", tt.name, prompt, tt.chooser)
		}
		if tt.chooser && strings.Join(prompt, ",") != "select_account" {
			t.Fatalf("%s: provider got prompt %q, want select_account", tt.name, prompt)
		}
	}
}

func TestApplicationAuthOIDCUnreachableProviderScreen(t *testing.T) {
	t.Parallel()

	idp := newOIDCTestIdP(t, nil)
	gate := newOIDCTestGate(t, idp)
	idp.server.Close()

	for accept, contentType := range map[string]string{"text/html": "text/html; charset=utf-8", "": "text/plain; charset=utf-8"} {
		req := httptest.NewRequest(http.MethodGet, "https://app.example"+types.PathApplicationAuthLogin+"?next="+url.QueryEscape("/docs?page=2"), nil)
		req.Header.Set("Accept", accept)
		rec := httptest.NewRecorder()
		gate.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadGateway || rec.Header().Get("Content-Type") != contentType || len(rec.Result().Cookies()) != 0 {
			t.Fatalf("Accept %q: %d %q with cookies %v", accept, rec.Code, rec.Header().Get("Content-Type"), rec.Result().Cookies())
		}
		if accept == "" {
			continue
		}
		body := rec.Body.String()
		for _, want := range []string{"<h1>Sign-in could not be completed</h1>", `href="` + types.PathApplicationAuthLogin + `?next=%2Fdocs%3Fpage%3D2"`} {
			if !strings.Contains(body, want) {
				t.Fatalf("page is missing %q", want)
			}
		}
	}
}

func TestApplicationAuthOIDCEndpointQueries(t *testing.T) {
	t.Parallel()
	idp := newOIDCTestIdP(t, func(p *oidcTestIdP) { p.query = "?tenant=team" })
	gate := newOIDCTestGate(t, idp)
	login := httptest.NewRecorder()
	gate.ServeHTTP(login, httptest.NewRequest(http.MethodGet, "https://app.example"+types.PathApplicationAuthLogin, nil))
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

func TestApplicationAuthOIDCLoginStartsOnlyOnGet(t *testing.T) {
	t.Parallel()
	gate := newOIDCTestGate(t, newOIDCTestIdP(t, nil))
	rec := httptest.NewRecorder()
	gate.ServeHTTP(rec, httptest.NewRequest(http.MethodHead, "https://app.example"+types.PathApplicationAuthLogin, nil))
	if rec.Code != http.StatusMethodNotAllowed || len(rec.Result().Cookies()) != 0 {
		t.Fatalf("HEAD login = %d with cookies %v; want 405 and no state cookie", rec.Code, rec.Result().Cookies())
	}
}

func TestApplicationAuthOIDCStateCookieStaysWithinBrowserLimit(t *testing.T) {
	t.Parallel()

	long := "/" + strings.Repeat("a", 1500)
	tests := []struct {
		name string
		next string
		want string
	}{
		{"short link is kept", "/dashboard?tab=1", "/dashboard?tab=1"},
		{"long link that fits is kept", long, long},
		{"link too long for the cookie", "/" + strings.Repeat("a", 5000), "/"},
		{"link that grows when it is escaped", "/" + strings.Repeat("<", 1000), "/"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			idp := newOIDCTestIdP(t, nil)
			gate := newOIDCTestGate(t, idp)
			rec := httptest.NewRecorder()
			gate.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://app.example"+types.PathApplicationAuthLogin+"?next="+url.QueryEscape(tt.next), nil))
			authURL, err := url.Parse(rec.Header().Get("Location"))
			cookies := rec.Result().Cookies()
			if err != nil || rec.Code != http.StatusSeeOther || len(cookies) != 1 {
				t.Fatalf("login = %d, %q, %v, %d cookies", rec.Code, rec.Header().Get("Location"), err, len(cookies))
			}
			if size := len(cookies[0].String()); size > 4096 {
				t.Fatalf("state cookie is %d bytes; a browser drops one of about 4096", size)
			}
			idp.expect(authURL.Query().Get("code_challenge"), authURL.Query().Get("nonce"))
			login := oidcLogin{state: authURL.Query().Get("state"), cookie: cookies[0]}
			callback := httptest.NewRecorder()
			gate.ServeHTTP(callback, login.callbackRequest(t, gate, nil))
			assertOIDCCallback(t, callback, http.StatusSeeOther)
			if got := callback.Header().Get("Location"); got != tt.want {
				t.Fatalf("login returned to %q; want %q", got, tt.want)
			}
		})
	}
}

func TestApplicationAuthOIDCSessionLifetime(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		tokenLifetime time.Duration
		want          time.Duration
	}{
		{"token already inside the verification leeway", -30 * time.Second, providerMinSessionTTL},
		{"token shorter than the minimum", 5 * time.Minute, providerMinSessionTTL},
		{"token between the bounds", time.Hour, time.Hour},
		{"token longer than the maximum", 72 * time.Hour, applicationAuthSessionTTL},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			idp := newOIDCTestIdP(t, func(p *oidcTestIdP) {
				p.mutate = func(c *oidcIDTokenClaims) { c.Expiry = jwt.NewNumericDate(time.Now().Add(tt.tokenLifetime)) }
			})
			gate := newOIDCTestGate(t, idp)
			start := time.Now()
			login := startOIDCLogin(t, gate, idp, "app.example", types.PathApplicationAuthLogin)
			callback := httptest.NewRecorder()
			gate.ServeHTTP(callback, login.callbackRequest(t, gate, nil))
			assertOIDCCallback(t, callback, http.StatusSeeOther)
			if got := oidcSessionExpiry(t, gate, callback).Sub(start); got < tt.want-5*time.Second || got > tt.want+5*time.Second {
				t.Fatalf("session lasts %v; want about %v", got, tt.want)
			}
		})
	}
}

func oidcSessionExpiry(t *testing.T, gate *applicationAuth, rec *httptest.ResponseRecorder) time.Time {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name != applicationAuthCookieName {
			continue
		}
		var claims applicationAuthClaims
		if err := decodeSignedApplicationAuthJSON(gate.signingKey, c.Value, &claims); err != nil {
			t.Fatal(err)
		}
		return time.Unix(claims.ExpiresAt, 0)
	}
	t.Fatal("no session cookie")
	return time.Time{}
}

func TestCheckApplicationAuthProvider(t *testing.T) {
	t.Parallel()

	t.Run("reachable provider", func(t *testing.T) {
		t.Parallel()
		checkReachableProvider(t)
	})
	t.Run("issuer that publishes no discovery document", func(t *testing.T) {
		t.Parallel()
		checkProviderWithoutDiscovery(t)
	})
	t.Run("provider that is down", func(t *testing.T) {
		t.Parallel()
		checkProviderDown(t)
	})
	t.Run("configuration the resolver rejects", func(t *testing.T) {
		t.Parallel()
		checkAllowlistRejection(t)
	})
	t.Run("providers with nothing outside the tunnel", func(t *testing.T) {
		t.Parallel()
		checkLocalProviders(t)
	})
}
func newProviderCheckConfig(issuer string) Config {
	return Config{
		Provider:   ProviderOIDC,
		Allow:      []string{"alice@example.com"},
		OIDCConfig: OIDCConfig{OIDCIssuerURL: issuer, OIDCClientID: oidcTestClientID},
	}
}
func checkReachableProvider(t *testing.T) {
	t.Helper()
	idp := newOIDCTestIdP(t, nil)
	if err := Check(t.Context(), newProviderCheckConfig(idp.issuerURL)); err != nil {
		t.Fatalf("Check() = %v; want nil", err)
	}
}

func checkProviderWithoutDiscovery(t *testing.T) {
	t.Helper()
	idp := newOIDCTestIdP(t, nil)
	if err := Check(t.Context(), newProviderCheckConfig(idp.issuerURL+"/missing")); err == nil {
		t.Fatal("Check() = nil for an issuer without a discovery document")
	}
}

func checkProviderDown(t *testing.T) {
	t.Helper()
	idp := newOIDCTestIdP(t, nil)
	idp.server.Close()
	if err := Check(t.Context(), newProviderCheckConfig(idp.issuerURL)); err == nil {
		t.Fatal("Check() = nil for a provider that is down")
	}
}

func checkAllowlistRejection(t *testing.T) {
	t.Helper()
	cfg := Config{Provider: ProviderOIDC, OIDCConfig: OIDCConfig{OIDCIssuerURL: "https://idp.example", OIDCClientID: oidcTestClientID}}
	if err := Check(t.Context(), cfg); err == nil || !strings.Contains(err.Error(), "--auth-email-list") {
		t.Fatalf("Check() = %v; want the resolver's error about the missing allowlist", err)
	}
}

func checkLocalProviders(t *testing.T) {
	t.Helper()
	for _, provider := range []string{ProviderSIWE, ProviderCredential} {
		if err := Check(t.Context(), Config{Provider: provider}); err != nil {
			t.Errorf("Check(%s) = %v; want nil", provider, err)
		}
	}
}

func TestOIDCPrincipalCarriesTheVouchedEmail(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name     string
		allow    string
		verified oidcEmailVerified
		want     Principal
	}{
		{"email entry", "alice@example.com", true, Principal{ProviderOIDC, "alice@example.com", "alice@example.com"}},
		{"sub entry with a verified email", "sub:user-123", true, Principal{ProviderOIDC, "sub:user-123", "alice@example.com"}},
		{"sub entry with an unverified email", "sub:user-123", false, Principal{ProviderOIDC, "sub:user-123", ""}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			idp := newOIDCTestIdP(t, func(p *oidcTestIdP) {
				p.mutate = func(c *oidcIDTokenClaims) { c.EmailVerified = tt.verified }
			})
			gate := newOIDCTestGate(t, idp, tt.allow)
			rec := completeOIDCLogin(t, gate, idp)
			assertOIDCCallback(t, rec, http.StatusSeeOther)
			req := httptest.NewRequest(http.MethodGet, "https://app.example/", nil)
			for _, cookie := range rec.Result().Cookies() {
				req.AddCookie(cookie)
			}
			if got, ok := gate.authenticateSession(req); !ok || got != tt.want {
				t.Fatalf("principal = (%+v, %v); want %+v", got, ok, tt.want)
			}
		})
	}
}
func TestApplicationAuthOIDCDiscoveryIsShared(t *testing.T) {
	t.Parallel()

	entered, release := make(chan struct{}, 8), make(chan struct{})
	idp := newOIDCTestIdP(t, func(p *oidcTestIdP) { p.discoveryEntered, p.discoveryRelease = entered, release })
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseSharedDiscovery(release, &releaseOnce) })
	oidc := newOIDCTestGate(t, idp).oidc

	abandoned, abandon := context.WithCancel(t.Context())
	defer abandon()
	abandonedDone := make(chan error, 2)
	go fetchSharedDiscovery(abandoned, oidc, abandonedDone)
	awaitOIDC(t, entered, "the discovery request")
	go fetchSharedDiscovery(abandoned, oidc, abandonedDone)

	const waiters = 3
	waitersDone := make(chan error, waiters)
	for range waiters {
		go fetchSharedDiscovery(t.Context(), oidc, waitersDone)
	}

	abandon()
	awaitCancelledDiscovery(t, abandonedDone)
	select {
	case err := <-waitersDone:
		t.Fatalf("a caller returned before the provider answered: %v", err)
	default:
	}

	releaseSharedDiscovery(release, &releaseOnce)
	awaitWaitingDiscovery(t, waitersDone, waiters)
	assertSharedDiscoveryHits(t, idp)
}
func fetchSharedDiscovery(ctx context.Context, oidc *oidcAuthenticator, done chan<- error) {
	_, err := oidc.discoveryDocument(ctx)
	done <- err
}

func releaseSharedDiscovery(release chan struct{}, once *sync.Once) {
	once.Do(func() { close(release) })
}

func awaitCancelledDiscovery(t *testing.T, abandonedDone <-chan error) {
	t.Helper()
	for range 2 {
		if err := awaitOIDC(t, abandonedDone, "a cancelled caller to return"); !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled caller error = %v; want context.Canceled", err)
		}
	}
}

func awaitWaitingDiscovery(t *testing.T, waitersDone <-chan error, waiters int) {
	t.Helper()
	for range waiters {
		if err := awaitOIDC(t, waitersDone, "a waiting caller to return"); err != nil {
			t.Fatalf("waiting caller error = %v; want success", err)
		}
	}
}

func assertSharedDiscoveryHits(t *testing.T, idp *oidcTestIdP) {
	t.Helper()
	if got := idp.discoveryHits.Load(); got != 1 {
		t.Fatalf("discovery requests = %d; want 1 shared fetch", got)
	}
}

func TestApplicationAuthOIDCKeysAreFetchedForVerificationOnly(t *testing.T) {
	t.Parallel()
	idp := newOIDCTestIdP(t, nil)
	gate := newOIDCTestGate(t, idp)
	login := startOIDCLogin(t, gate, idp, "app.example", types.PathApplicationAuthLogin)
	if got := idp.jwksHits.Load(); got != 0 {
		t.Fatalf("starting a login requested the signing keys %d times; want 0", got)
	}
	rec := httptest.NewRecorder()
	gate.ServeHTTP(rec, login.callbackRequest(t, gate, nil))
	assertOIDCCallback(t, rec, http.StatusSeeOther)
	if got := idp.jwksHits.Load(); got != 1 {
		t.Fatalf("signing key requests after the callback = %d; want 1", got)
	}
}

func TestApplicationAuthOIDCRefreshesKeysOnlyForKeyErrors(t *testing.T) {
	t.Parallel()

	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	nonKeyFailures := []struct {
		name   string
		mutate func(*oidcIDTokenClaims)
	}{
		{"nonce mismatch", func(c *oidcIDTokenClaims) { c.Nonce = "replayed" }},
		{"audience mismatch", func(c *oidcIDTokenClaims) { c.Audience = jwt.Audience{"someone-else"} }},
		{"issuer mismatch", func(c *oidcIDTokenClaims) { c.Issuer = "https://evil.example" }},
		{"expired token", func(c *oidcIDTokenClaims) { c.Expiry = jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)) }},
		{"missing subject", func(c *oidcIDTokenClaims) { c.Subject = "" }},
	}
	for _, tt := range nonKeyFailures {
		t.Run(tt.name+" makes no request", func(t *testing.T) {
			t.Parallel()
			exerciseNonKeyFailure(t, tt.mutate)
		})
	}

	keyFailures := []struct {
		name string
		sign func(t *testing.T, p *oidcTestIdP) jose.Signer
	}{
		{"unknown key id", func(t *testing.T, p *oidcTestIdP) jose.Signer {
			return newOIDCTestSigner(t, jose.ES256, p.key, "unlisted")
		}},
		{"signature from another key", func(t *testing.T, _ *oidcTestIdP) jose.Signer {
			return newOIDCTestSigner(t, jose.ES256, otherKey, "k1")
		}},
	}
	for _, tt := range keyFailures {
		t.Run(tt.name+" refetches the keys once per interval", func(t *testing.T) {
			t.Parallel()
			exerciseKeyFailure(t, tt.sign)
		})
	}

	t.Run("a rotated provider key is picked up", func(t *testing.T) {
		t.Parallel()
		idp, gate := warmSigningKeyIdP(t)
		idp.rotate(t, "k2")
		assertOIDCCallback(t, completeOIDCLogin(t, gate, idp), http.StatusSeeOther)
		assertDiscoveryKeyHits(t, idp, 1, 2)
	})
}
func exerciseNonKeyFailure(t *testing.T, mutate func(*oidcIDTokenClaims)) {
	t.Helper()
	idp, gate := warmSigningKeyIdP(t)
	idp.update(func(p *oidcTestIdP) { p.mutate = mutate })
	assertOIDCCallback(t, completeOIDCLogin(t, gate, idp), http.StatusUnauthorized)
	assertDiscoveryKeyHits(t, idp, 1, 1)
}

func exerciseKeyFailure(t *testing.T, sign func(t *testing.T, p *oidcTestIdP) jose.Signer) {
	t.Helper()
	idp, gate := warmSigningKeyIdP(t)
	idp.update(func(p *oidcTestIdP) { p.signWith = sign(t, p) })
	assertOIDCCallback(t, completeOIDCLogin(t, gate, idp), http.StatusUnauthorized)
	assertDiscoveryKeyHits(t, idp, 1, 2)
	assertOIDCCallback(t, completeOIDCLogin(t, gate, idp), http.StatusUnauthorized)
	assertDiscoveryKeyHits(t, idp, 1, 2)
	ageOIDCKeys(gate)
	assertOIDCCallback(t, completeOIDCLogin(t, gate, idp), http.StatusUnauthorized)
	assertDiscoveryKeyHits(t, idp, 1, 3)
}
func warmSigningKeyIdP(t *testing.T) (*oidcTestIdP, *applicationAuth) {
	t.Helper()
	idp := newOIDCTestIdP(t, nil)
	gate := newOIDCTestGate(t, idp)
	assertOIDCCallback(t, completeOIDCLogin(t, gate, idp), http.StatusSeeOther)
	ageOIDCKeys(gate)
	return idp, gate
}

func assertDiscoveryKeyHits(t *testing.T, idp *oidcTestIdP, discovery, jwks int32) {
	t.Helper()
	if gotDiscovery, gotJWKS := idp.discoveryHits.Load(), idp.jwksHits.Load(); gotDiscovery != discovery || gotJWKS != jwks {
		t.Fatalf("requests = %d discovery, %d jwks; want %d, %d", gotDiscovery, gotJWKS, discovery, jwks)
	}
}

func TestApplicationAuthOIDCTokenWithoutKeyID(t *testing.T) {
	t.Parallel()

	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	withoutKID := func(t *testing.T, p *oidcTestIdP) {
		p.signer = newOIDCTestSigner(t, jose.ES256, p.key, "")
	}
	tests := []struct {
		name      string
		configure func(t *testing.T, p *oidcTestIdP)
		want      int
	}{
		{"one key listed with its kid", withoutKID, http.StatusSeeOther},
		{"one key listed without a kid", func(t *testing.T, p *oidcTestIdP) {
			withoutKID(t, p)
			p.jwk.KeyID = ""
		}, http.StatusSeeOther},
		{"one key reserved for encryption", func(t *testing.T, p *oidcTestIdP) {
			withoutKID(t, p)
			p.jwk.Use = "enc"
		}, http.StatusUnauthorized},
		{"two keys listed", func(t *testing.T, p *oidcTestIdP) {
			withoutKID(t, p)
			p.extraJWKs = []jose.JSONWebKey{{Key: &otherKey.PublicKey, KeyID: "k2", Algorithm: string(jose.ES256), Use: "sig"}}
		}, http.StatusUnauthorized},
		{"symmetric algorithm", func(t *testing.T, p *oidcTestIdP) {
			p.signWith = newOIDCTestSigner(t, jose.HS256, []byte("shared-secret-of-sufficient-length"), "")
		}, http.StatusUnauthorized},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			idp := newOIDCTestIdP(t, func(p *oidcTestIdP) { tt.configure(t, p) })
			assertOIDCCallback(t, completeOIDCLogin(t, newOIDCTestGate(t, idp), idp), tt.want)
		})
	}
}

func TestApplicationAuthOIDCTokenRequestAuthentication(t *testing.T) {
	t.Parallel()

	const secret = "portal-secret"
	inHeader := oidcTokenCredentials{inHeader: true, clientID: oidcTestClientID, clientSecret: secret}
	inBody := oidcTokenCredentials{clientID: oidcTestClientID, clientSecret: secret}
	tests := []struct {
		name    string
		secret  string
		methods []string
		want    oidcTokenCredentials
	}{
		{"public client sends only its id in the body", "", nil, oidcTokenCredentials{clientID: oidcTestClientID}},
		{"public client ignores the advertised methods", "", []string{"client_secret_basic"}, oidcTokenCredentials{clientID: oidcTestClientID}},
		{"no advertised methods means client_secret_basic", secret, nil, inHeader},
		{"client_secret_basic only", secret, []string{"client_secret_basic"}, inHeader},
		{"client_secret_post only", secret, []string{"client_secret_post"}, inBody},
		{"both prefer client_secret_basic", secret, []string{"client_secret_post", "client_secret_basic"}, inHeader},
		{"unrelated methods keep the default", secret, []string{"private_key_jwt"}, inHeader},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			idp := newOIDCTestIdP(t, func(p *oidcTestIdP) { p.clientSecret, p.authMethods = tt.secret, tt.methods })
			assertOIDCCallback(t, completeOIDCLogin(t, newOIDCTestGate(t, idp), idp), http.StatusSeeOther)
			if got := idp.tokenCredentials(); !slices.Equal(got, []oidcTokenCredentials{tt.want}) {
				t.Fatalf("token request credentials = %+v; want exactly one: %+v", got, tt.want)
			}
		})
	}

	for _, methods := range [][]string{nil, {"client_secret_post"}} {
		t.Run("rejected code is sent once with methods "+strings.Join(methods, ","), func(t *testing.T) {
			t.Parallel()
			idp := newOIDCTestIdP(t, func(p *oidcTestIdP) {
				p.clientSecret, p.authMethods, p.tokenStatus = secret, methods, http.StatusUnauthorized
			})
			assertOIDCCallback(t, completeOIDCLogin(t, newOIDCTestGate(t, idp), idp), http.StatusUnauthorized)
			if got := idp.tokenCredentials(); len(got) != 1 {
				t.Fatalf("token requests = %+v; want the authorization code sent exactly once", got)
			}
		})
	}
}

func newSecureDiscoveryDocument(issuer, _ string) oidcDiscoveryDocument {
	return oidcDiscoveryDocument{
		Issuer:                issuer,
		AuthorizationEndpoint: issuer + "/authorize",
		TokenEndpoint:         issuer + "/token",
		JWKSURI:               issuer + "/jwks",
	}
}

func TestApplicationAuthOIDCRefusesCleartextProviderURLs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		document func(issuer, cleartext string) oidcDiscoveryDocument
		redirect bool
		want     int
	}{
		{"control: https endpoints", newSecureDiscoveryDocument, false, http.StatusSeeOther},
		{"cleartext authorization endpoint", func(issuer, cleartext string) oidcDiscoveryDocument {
			doc := newSecureDiscoveryDocument(issuer, cleartext)
			doc.AuthorizationEndpoint = cleartext + "/authorize"
			return doc
		}, false, http.StatusBadGateway},
		{"cleartext token endpoint", func(issuer, cleartext string) oidcDiscoveryDocument {
			doc := newSecureDiscoveryDocument(issuer, cleartext)
			doc.TokenEndpoint = cleartext + "/token"
			return doc
		}, false, http.StatusBadGateway},
		{"cleartext jwks uri", func(issuer, cleartext string) oidcDiscoveryDocument {
			doc := newSecureDiscoveryDocument(issuer, cleartext)
			doc.JWKSURI = cleartext + "/jwks"
			return doc
		}, false, http.StatusBadGateway},
		{"redirect from https to cleartext", newSecureDiscoveryDocument, true, http.StatusBadGateway},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var cleartextHits atomic.Int32
			var cleartext *httptest.Server
			var gate *applicationAuth
			cleartext = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				cleartextHits.Add(1)
				_ = json.NewEncoder(w).Encode(tt.document(gate.oidc.issuerURL, cleartext.URL))
			}))
			t.Cleanup(cleartext.Close)
			gate = newOIDCTLSGate(t, func(w http.ResponseWriter, r *http.Request, issuer string) {
				if tt.redirect {
					http.Redirect(w, r, cleartext.URL+r.URL.Path, http.StatusFound)
					return
				}
				_ = json.NewEncoder(w).Encode(tt.document(issuer, cleartext.URL))
			})

			assertCleartextLoginBlocked(t, gate, tt.want, &cleartextHits)
		})
	}
}
func assertCleartextLoginBlocked(t *testing.T, gate *applicationAuth, want int, cleartextHits *atomic.Int32) {
	t.Helper()
	rec := httptest.NewRecorder()
	gate.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://app.example"+types.PathApplicationAuthLogin, nil))
	if rec.Code != want {
		t.Fatalf("login status = %d, body %q; want %d", rec.Code, strings.TrimSpace(rec.Body.String()), want)
	}
	if got := cleartextHits.Load(); got != 0 {
		t.Fatalf("cleartext server received %d requests; want none", got)
	}
}

func TestApplicationAuthOIDCStopsRedirectLoops(t *testing.T) {
	t.Parallel()
	var hits atomic.Int32
	gate := newOIDCTLSGate(t, func(w http.ResponseWriter, r *http.Request, _ string) {
		hits.Add(1)
		http.Redirect(w, r, r.URL.Path, http.StatusFound)
	})
	rec := httptest.NewRecorder()
	gate.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://app.example"+types.PathApplicationAuthLogin, nil))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("login status = %d; want 502", rec.Code)
	}
	if got := hits.Load(); got > providerMaxRedirects {
		t.Fatalf("provider received %d requests; want at most %d", got, providerMaxRedirects)
	}
}

func newOIDCTLSGate(t *testing.T, serve func(w http.ResponseWriter, r *http.Request, issuer string)) *applicationAuth {
	t.Helper()
	provider := httptest.NewUnstartedServer(nil)
	provider.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { serve(w, r, provider.URL) })
	provider.StartTLS()
	t.Cleanup(provider.Close)
	handler, err := New(http.NotFoundHandler(), applicationAuthTestIdentity(), Config{
		Provider:   ProviderOIDC,
		Allow:      []string{"alice@example.com"},
		OIDCConfig: OIDCConfig{OIDCIssuerURL: provider.URL, OIDCClientID: oidcTestClientID},
	})
	if err != nil {
		t.Fatal(err)
	}
	gate := handler.(*applicationAuth)
	gate.oidc.httpClient.Transport = provider.Client().Transport
	return gate
}

type oidcRawEmailVerifiedClaims struct {
	oidcIDTokenClaims
	EmailVerified json.RawMessage `json:"email_verified,omitempty"`
}

func TestApplicationAuthOIDCEmailVerifiedDecoding(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		claim    json.RawMessage
		verified bool
	}{
		{"boolean true", json.RawMessage(`true`), true},
		{"string true", json.RawMessage(`"true"`), true},
		{"boolean false", json.RawMessage(`false`), false},
		{"string false", json.RawMessage(`"false"`), false},
		{"absent", json.RawMessage{}, false},
		{"null", json.RawMessage(`null`), false},
		{"other string", json.RawMessage(`"yes"`), false},
		{"string in another case", json.RawMessage(`"TRUE"`), false},
		{"number", json.RawMessage(`1`), false},
		{"array", json.RawMessage(`[true]`), false},
		{"object", json.RawMessage(`{"verified":true}`), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			idp := newOIDCTestIdP(t, func(p *oidcTestIdP) { p.emailVerified = tt.claim })
			wantEmailLogin := http.StatusUnauthorized
			if tt.verified {
				wantEmailLogin = http.StatusSeeOther
			}
			assertOIDCCallback(t, completeOIDCLogin(t, newOIDCTestGate(t, idp), idp), wantEmailLogin)
			assertOIDCCallback(t, completeOIDCLogin(t, newOIDCTestGate(t, idp, "sub:user-123"), idp), http.StatusSeeOther)
		})
	}
}
func TestApplicationAuthOIDCPKCEAndRevocation(t *testing.T) {
	signer, jwk := newApplicationAuthOIDCPKCESigner(t)
	var issuerURL, capturedChallenge, capturedNonce string
	idp := newApplicationAuthOIDCPKCEIdP(t, jwk, signer, &issuerURL, &capturedChallenge, &capturedNonce)
	defer idp.Close()
	issuerURL = idp.URL

	tunnelIdentity := applicationAuthTestIdentity()
	var upstreamUser, upstreamAuth string
	gate := newApplicationAuthOIDCPKCEGate(t, tunnelIdentity, issuerURL, &upstreamUser, &upstreamAuth)
	state, stateCookies := loginApplicationAuthOIDCPKCE(t, gate, &capturedChallenge, &capturedNonce)
	sessionCookie := callbackApplicationAuthOIDCPKCE(t, gate, state, stateCookies)
	protectedRec := servePKCEProtected(t, gate, sessionCookie)
	if protectedRec.Code != http.StatusNoContent || upstreamUser != "alice@example.com" || upstreamAuth != ProviderOIDC {
		t.Fatalf("protected status = %d, user = %q, auth = %q", protectedRec.Code, upstreamUser, upstreamAuth)
	}
	checkRevokedPKCESession(t, tunnelIdentity, issuerURL, sessionCookie)
}

func newApplicationAuthOIDCPKCESigner(t *testing.T) (jose.Signer, jose.JSONWebKey) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwk := jose.JSONWebKey{Key: &privateKey.PublicKey, KeyID: "k1", Algorithm: string(jose.ES256), Use: "sig"}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: privateKey}, (&jose.SignerOptions{}).WithHeader("kid", "k1").WithType("JWT"))
	if err != nil {
		t.Fatal(err)
	}
	return signer, jwk
}

func mintOIDCIDToken(signer jose.Signer, issuerURL, capturedNonce string, now time.Time) (string, error) {
	return jwt.Signed(signer).Claims(oidcIDTokenClaims{
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
}

func newApplicationAuthOIDCPKCEIdP(t *testing.T, jwk jose.JSONWebKey, signer jose.Signer, issuerURL, capturedChallenge, capturedNonce *string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(oidcDiscoveryDocument{
				Issuer:                *issuerURL,
				AuthorizationEndpoint: *issuerURL + "/authorize",
				TokenEndpoint:         *issuerURL + "/token",
				JWKSURI:               *issuerURL + "/jwks",
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
			if got := base64.RawURLEncoding.EncodeToString(sum[:]); got != *capturedChallenge {
				http.Error(w, "pkce mismatch", http.StatusBadRequest)
				return
			}
			now := time.Now().UTC()
			idToken, err := mintOIDCIDToken(signer, *issuerURL, *capturedNonce, now)
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
}

func newApplicationAuthOIDCPKCEGate(t *testing.T, tunnelIdentity types.Identity, issuerURL string, upstreamUser, upstreamAuth *string) *applicationAuth {
	t.Helper()
	gate, err := New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*upstreamUser = r.Header.Get(types.HeaderPortalUser)
		*upstreamAuth = r.Header.Get(types.HeaderPortalAuth)
		w.WriteHeader(http.StatusNoContent)
	}), tunnelIdentity, Config{
		Provider:        ProviderOIDC,
		Allow:           []string{"alice@example.com"},
		IdentityHeaders: true,
		OIDCConfig:      OIDCConfig{OIDCIssuerURL: issuerURL, OIDCClientID: "portal-client", OIDCClientSecret: "portal-secret"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return gate.(*applicationAuth)
}

func loginApplicationAuthOIDCPKCE(t *testing.T, gate *applicationAuth, capturedChallenge, capturedNonce *string) (string, []*http.Cookie) {
	t.Helper()
	loginReq := httptest.NewRequest(http.MethodGet, "https://app.example"+types.PathApplicationAuthLogin+"?next=%2Fdashboard", nil)
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
	*capturedChallenge = authRedirect.Query().Get("code_challenge")
	*capturedNonce = authRedirect.Query().Get("nonce")
	state := authRedirect.Query().Get("state")
	stateCookies := loginRec.Result().Cookies()
	if len(stateCookies) != 1 || stateCookies[0].Name != applicationAuthOIDCStateCookie {
		t.Fatalf("state cookies = %#v", stateCookies)
	}
	if c := stateCookies[0]; c.Path != "/" || !c.Secure || c.Domain != "" {
		t.Fatalf("state cookie attributes = path %q, secure %v, domain %q; want Path=/, Secure, no Domain", c.Path, c.Secure, c.Domain)
	}
	return state, stateCookies
}

func callbackApplicationAuthOIDCPKCE(t *testing.T, gate *applicationAuth, state string, stateCookies []*http.Cookie) *http.Cookie {
	t.Helper()
	cbReq := httptest.NewRequest(http.MethodGet, "https://app.example"+types.PathApplicationAuthCallback+"?code=authcode&state="+url.QueryEscape(state), nil)
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
	return sessionCookie
}

func servePKCEProtected(t *testing.T, gate *applicationAuth, sessionCookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	protectedReq := httptest.NewRequest(http.MethodGet, "https://app.example/dashboard", nil)
	protectedReq.AddCookie(sessionCookie)
	protectedRec := httptest.NewRecorder()
	gate.ServeHTTP(protectedRec, protectedReq)
	return protectedRec
}

func checkRevokedPKCESession(t *testing.T, tunnelIdentity types.Identity, issuerURL string, sessionCookie *http.Cookie) {
	t.Helper()
	revokedGate, err := New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), tunnelIdentity, Config{
		Provider:        ProviderOIDC,
		Allow:           []string{"bob@example.com"},
		IdentityHeaders: true,
		OIDCConfig:      OIDCConfig{OIDCIssuerURL: issuerURL, OIDCClientID: "portal-client", OIDCClientSecret: "portal-secret"},
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
		{"subject with surrounding Unicode space cannot impersonate an allowed subject", []string{"sub:s1"}, " s1 ", "", false, ""},
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
			checkPrincipalResolution(t, tt.allow, tt.sub, tt.email, tt.status, tt.want)
		})
	}

	t.Run("domain session remains valid", func(t *testing.T) {
		t.Parallel()
		checkDomainSessionSubject(t)
	})
	t.Run("sub session remains valid", func(t *testing.T) {
		t.Parallel()
		checkSubSessionSubjects(t)
	})
	t.Run("sub session cannot widen to a domain entry", func(t *testing.T) {
		t.Parallel()
		checkSubIgnoresDomain(t)
	})
	t.Run("credential subjects ignore domain entries", func(t *testing.T) {
		t.Parallel()
		checkCredentialIgnoresDomain(t)
	})
	t.Run("malformed domain entries are rejected", func(t *testing.T) {
		t.Parallel()
		rejectMalformedPrincipals(t)
	})
	t.Run("untyped or malformed entries are rejected", func(t *testing.T) {
		t.Parallel()
		rejectUntypedPrincipals(t)
	})
}

func newPrincipalGate(t *testing.T, provider string, allow ...string) *applicationAuth {
	t.Helper()
	cfg := Config{Provider: provider, Allow: allow}
	if provider == ProviderOIDC {
		cfg.OIDCIssuerURL = "https://idp.example"
		cfg.OIDCClientID = "portal-client"
	}
	handler, err := New(http.NotFoundHandler(), applicationAuthTestIdentity(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	return handler.(*applicationAuth)
}

func checkPrincipalResolution(t *testing.T, allow []string, sub, email string, status oidcEmailVerified, want string) {
	t.Helper()
	gate := newPrincipalGate(t, ProviderOIDC, allow...)
	claims := oidcIDTokenClaims{
		Claims:        jwt.Claims{Subject: sub},
		Email:         email,
		EmailVerified: status,
	}
	got, ok := gate.resolveAllowedPrincipal(claims.vouchedEmail(), claims.Subject)
	if got != want || ok != (want != "") {
		t.Fatalf("resolveAllowedPrincipal = (%q, %v); want %q", got, ok, want)
	}
}

func checkDomainSessionSubject(t *testing.T) {
	t.Helper()
	if !newPrincipalGate(t, ProviderOIDC, "@example.com").subjectAllowed("bob@example.com") {
		t.Fatal("domain-authorized subject rejected on session validation")
	}
}

func checkSubSessionSubjects(t *testing.T) {
	t.Helper()
	gate := newPrincipalGate(t, ProviderOIDC, "sub:alice@example.com")
	if !gate.subjectAllowed("sub:alice@example.com") {
		t.Fatal("sub:-authorized subject rejected on session validation")
	}
	if gate.subjectAllowed("sub:mallory@example.com") {
		t.Fatal("unlisted sub: subject accepted on session validation")
	}
}

func checkSubIgnoresDomain(t *testing.T) {
	t.Helper()
	if newPrincipalGate(t, ProviderOIDC, "@example.com").subjectAllowed("sub:mallory@example.com") {
		t.Fatal("sub: session subject honored an @domain entry")
	}
}

func checkCredentialIgnoresDomain(t *testing.T) {
	t.Helper()
	if newPrincipalGate(t, ProviderCredential, "@example.com").subjectAllowed("bob@example.com") {
		t.Fatal("credential provider honored an @domain entry")
	}
}

func rejectMalformedPrincipals(t *testing.T) {
	t.Helper()
	for _, entry := range []string{"@", "@a@b", "@ex ample.com"} {
		if _, err := normalizeProviderPrincipals([]string{entry}); err == nil {
			t.Fatalf("normalizeProviderPrincipals(%q) = nil error", entry)
		}
	}
}

func rejectUntypedPrincipals(t *testing.T) {
	t.Helper()
	for _, entry := range []string{"alice", "sub:", "sub: ", "alice@", "alice@a@b", "Kevin@example.com", "@gİthub.com"} {
		if _, err := normalizeProviderPrincipals([]string{entry}); err == nil {
			t.Fatalf("normalizeProviderPrincipals(%q) = nil error", entry)
		}
	}
}

func TestNormalizeProviderPrincipalKeepsSubjectCase(t *testing.T) {
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
		got, err := normalizeProviderPrincipal(tt.raw)
		if err != nil || got != tt.want {
			t.Errorf("normalizeProviderPrincipal(%q) = (%q, %v); want %q", tt.raw, got, err, tt.want)
		}
	}
}

func TestApplicationAuthOIDCLongSubSurvivesRevalidation(t *testing.T) {
	t.Parallel()

	sub := strings.Repeat("a", 255)
	handler, err := New(http.NotFoundHandler(), applicationAuthTestIdentity(), Config{
		Provider:   ProviderOIDC,
		Allow:      []string{"sub:" + sub},
		OIDCConfig: OIDCConfig{OIDCIssuerURL: "https://idp.example", OIDCClientID: oidcTestClientID},
	})
	if err != nil {
		t.Fatal(err)
	}
	gate := handler.(*applicationAuth)
	subject, ok := gate.resolveAllowedPrincipal("", sub)
	if !ok {
		t.Fatal("maximum-length sub was not authorized at login")
	}

	rec := httptest.NewRecorder()
	if err := gate.setSession(rec, Principal{Provider: ProviderOIDC, Subject: subject}, "app.example", time.Now(), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "https://app.example/dashboard", nil)
	for _, c := range rec.Result().Cookies() {
		req.AddCookie(c)
	}
	if got, ok := gate.authenticateSession(req); !ok || got.Subject != subject {
		t.Fatalf("authenticateSession = (%q, %v); want the session to stay valid for %q", got, ok, subject)
	}
}

func TestApplicationAuthOIDCSessionIsBoundToIssuerAndClient(t *testing.T) {
	t.Parallel()

	issuer := newSessionBindingGate(t, "https://idp.example", "portal-client", "secret")
	cookies := issueSessionCookies(t, issuer)
	for _, tt := range []struct {
		name         string
		issuer       string
		clientID     string
		clientSecret string
		want         bool
	}{
		{"same configuration after a restart", "https://idp.example", "portal-client", "secret", true},
		{"issuer written with a trailing slash", "https://idp.example/", "portal-client", "secret", true},
		{"rotated client secret", "https://idp.example", "portal-client", "rotated", true},
		{"different issuer", "https://other-idp.example", "portal-client", "secret", false},
		{"different client id", "https://idp.example", "other-client", "secret", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			checkSessionBindingCase(t, cookies, tt.issuer, tt.clientID, tt.clientSecret, tt.want)
		})
	}

	t.Run("session carrying no binding", func(t *testing.T) {
		t.Parallel()
		checkSessionWithoutBinding(t, issuer)
	})
}

func newSessionBindingGate(t *testing.T, issuer, clientID, clientSecret string) *applicationAuth {
	t.Helper()
	handler, err := New(http.NotFoundHandler(), applicationAuthTestIdentity(), Config{
		Provider:   ProviderOIDC,
		Allow:      []string{"alice@example.com"},
		OIDCConfig: OIDCConfig{OIDCIssuerURL: issuer, OIDCClientID: clientID, OIDCClientSecret: clientSecret},
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler.(*applicationAuth)
}

func newSessionCookieRequest(cookies []*http.Cookie) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "https://app.example/dashboard", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	return req
}

func issueSessionCookies(t *testing.T, issuer *applicationAuth) []*http.Cookie {
	t.Helper()
	rec := httptest.NewRecorder()
	if err := issuer.setSession(rec, Principal{Provider: ProviderOIDC, Subject: "alice@example.com"}, "app.example", time.Now(), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	return rec.Result().Cookies()
}

func checkSessionBindingCase(t *testing.T, cookies []*http.Cookie, issuer, clientID, clientSecret string, want bool) {
	t.Helper()
	gate := newSessionBindingGate(t, issuer, clientID, clientSecret)
	if _, ok := gate.authenticateSession(newSessionCookieRequest(cookies)); ok != want {
		t.Fatalf("authenticateSession ok = %v; want %v", ok, want)
	}
}

func checkSessionWithoutBinding(t *testing.T, issuer *applicationAuth) {
	t.Helper()
	token, err := encodeSignedApplicationAuthJSON(issuer.signingKey, applicationAuthClaims{
		Subject:   "alice@example.com",
		Provider:  ProviderOIDC,
		Host:      "app.example",
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	cookie := &http.Cookie{Name: applicationAuthCookieName, Value: token}
	if _, ok := issuer.authenticateSession(newSessionCookieRequest([]*http.Cookie{cookie})); ok {
		t.Fatal("an OIDC session without an issuer and client binding was accepted")
	}
}
