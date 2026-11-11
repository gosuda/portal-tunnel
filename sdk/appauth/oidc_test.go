package appauth

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
