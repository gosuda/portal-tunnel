package gateway

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
	"strings"
	"sync"
	"sync/atomic"
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
	key       *ecdsa.PrivateKey
	query     string

	// Request counters for the endpoints the gateway must not hit needlessly.
	discoveryHits atomic.Int32
	jwksHits      atomic.Int32

	// When discoveryRelease is set, discovery requests answer only after it is
	// closed; discoveryEntered learns that a request has arrived.
	discoveryEntered chan struct{}
	discoveryRelease chan struct{}

	mu          sync.Mutex
	jwk         jose.JSONWebKey
	extraJWKs   []jose.JSONWebKey
	challenge   string
	nonce       string
	mutate      func(*oidcIDTokenClaims)
	signWith    jose.Signer
	rawToken    func(valid string) string
	omitToken   bool
	tokenStatus int
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
			Issuer:                p.issuerURL,
			AuthorizationEndpoint: p.issuerURL + "/authorize" + p.query,
			TokenEndpoint:         p.issuerURL + "/token" + p.query,
			JWKSURI:               p.issuerURL + "/jwks" + p.query,
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

// update changes the provider's behavior between logins.
func (p *oidcTestIdP) update(change func(*oidcTestIdP)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	change(p)
}

// rotate replaces the signing key, as a provider does on key rotation.
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

// TestApplicationAuthOIDCDiscoveryIsShared protects login availability while the
// provider is slow: concurrent logins share one discovery fetch, a caller that
// gives up stops waiting at once without cancelling the fetch for the others.
func TestApplicationAuthOIDCDiscoveryIsShared(t *testing.T) {
	t.Parallel()

	entered, release := make(chan struct{}, 8), make(chan struct{})
	idp := newOIDCTestIdP(t, func(p *oidcTestIdP) { p.discoveryEntered, p.discoveryRelease = entered, release })
	var releaseOnce sync.Once
	releaseDiscovery := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseDiscovery)
	oidc := newOIDCTestGate(t, idp).oidc

	// One caller starts the fetch and another joins it; both then give up.
	abandoned, abandon := context.WithCancel(t.Context())
	defer abandon()
	abandonedDone := make(chan error, 2)
	discover := func(ctx context.Context, done chan<- error) {
		_, err := oidc.discoveryDocument(ctx)
		done <- err
	}
	go discover(abandoned, abandonedDone)
	awaitOIDC(t, entered, "the discovery request")
	go discover(abandoned, abandonedDone)

	const waiters = 3
	waitersDone := make(chan error, waiters)
	for range waiters {
		go discover(t.Context(), waitersDone)
	}

	abandon()
	for range 2 {
		if err := awaitOIDC(t, abandonedDone, "a cancelled caller to return"); !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled caller error = %v; want context.Canceled", err)
		}
	}
	select {
	case err := <-waitersDone:
		t.Fatalf("a caller returned before the provider answered: %v", err)
	default:
	}

	releaseDiscovery()
	for range waiters {
		if err := awaitOIDC(t, waitersDone, "a waiting caller to return"); err != nil {
			t.Fatalf("waiting caller error = %v; want success", err)
		}
	}
	if got := idp.discoveryHits.Load(); got != 1 {
		t.Fatalf("discovery requests = %d; want 1 shared fetch", got)
	}
}

// TestApplicationAuthOIDCKeysAreFetchedForVerificationOnly protects login
// availability: starting a login needs only the discovery document, so it must
// not depend on the provider's key endpoint.
func TestApplicationAuthOIDCKeysAreFetchedForVerificationOnly(t *testing.T) {
	t.Parallel()
	idp := newOIDCTestIdP(t, nil)
	gate := newOIDCTestGate(t, idp)
	login := startOIDCLogin(t, gate, idp, "app.example")
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

// TestApplicationAuthOIDCRefreshesKeysOnlyForKeyErrors protects the provider
// from refetch storms: only a failure that new keys can fix refetches the key
// set, and at most once per refresh interval. Discovery is never refetched.
func TestApplicationAuthOIDCRefreshesKeysOnlyForKeyErrors(t *testing.T) {
	t.Parallel()

	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// warmedIdP completes one login so the key set is cached, then makes the
	// cache old enough that only the failure's cause can hold back a refetch.
	warmedIdP := func(t *testing.T) (*oidcTestIdP, *applicationAuth) {
		t.Helper()
		idp := newOIDCTestIdP(t, nil)
		gate := newOIDCTestGate(t, idp)
		assertOIDCCallback(t, completeOIDCLogin(t, gate, idp), http.StatusSeeOther)
		ageOIDCKeys(gate)
		return idp, gate
	}
	assertHits := func(t *testing.T, idp *oidcTestIdP, discovery, jwks int32) {
		t.Helper()
		if gotDiscovery, gotJWKS := idp.discoveryHits.Load(), idp.jwksHits.Load(); gotDiscovery != discovery || gotJWKS != jwks {
			t.Fatalf("requests = %d discovery, %d jwks; want %d, %d", gotDiscovery, gotJWKS, discovery, jwks)
		}
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
			idp, gate := warmedIdP(t)
			idp.update(func(p *oidcTestIdP) { p.mutate = tt.mutate })
			assertOIDCCallback(t, completeOIDCLogin(t, gate, idp), http.StatusUnauthorized)
			assertHits(t, idp, 1, 1)
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
			idp, gate := warmedIdP(t)
			idp.update(func(p *oidcTestIdP) { p.signWith = tt.sign(t, p) })
			assertOIDCCallback(t, completeOIDCLogin(t, gate, idp), http.StatusUnauthorized)
			assertHits(t, idp, 1, 2)
			assertOIDCCallback(t, completeOIDCLogin(t, gate, idp), http.StatusUnauthorized)
			assertHits(t, idp, 1, 2)
			ageOIDCKeys(gate)
			assertOIDCCallback(t, completeOIDCLogin(t, gate, idp), http.StatusUnauthorized)
			assertHits(t, idp, 1, 3)
		})
	}

	t.Run("a rotated provider key is picked up", func(t *testing.T) {
		t.Parallel()
		idp, gate := warmedIdP(t)
		idp.rotate(t, "k2")
		assertOIDCCallback(t, completeOIDCLogin(t, gate, idp), http.StatusSeeOther)
		assertHits(t, idp, 1, 2)
	})
}

// TestApplicationAuthOIDCTokenWithoutKeyID protects logins at providers that
// omit the kid while signing with a single key, without letting a token pick
// among several keys or weakening the algorithm allowlist.
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

// completeOIDCLogin runs the login and the callback at app.example.
func completeOIDCLogin(t *testing.T, gate *applicationAuth, idp *oidcTestIdP) *httptest.ResponseRecorder {
	t.Helper()
	login := startOIDCLogin(t, gate, idp, "app.example")
	rec := httptest.NewRecorder()
	gate.ServeHTTP(rec, login.callbackRequest(t, gate, nil))
	return rec
}

// ageOIDCKeys makes the cached key set look two refresh intervals old.
func ageOIDCKeys(gate *applicationAuth) {
	gate.oidc.jwks.mu.Lock()
	defer gate.oidc.jwks.mu.Unlock()
	gate.oidc.jwks.fetchedAt = gate.oidc.jwks.fetchedAt.Add(-2 * oidcJWKSRefreshInterval)
}

// awaitOIDC receives from ch, failing the test instead of hanging when the
// awaited event never happens.
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
