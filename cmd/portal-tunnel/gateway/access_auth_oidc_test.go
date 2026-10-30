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
	"slices"
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

	// clientSecret is what the gateway is configured with, authMethods what
	// discovery advertises for client authentication at the token endpoint.
	clientSecret string
	authMethods  []string

	// Request counters for the endpoints the gateway must not hit needlessly.
	discoveryHits atomic.Int32
	jwksHits      atomic.Int32

	// When discoveryRelease is set, discovery requests answer only after it is
	// closed; discoveryEntered learns that a request has arrived.
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
	emailVerified json.RawMessage // sent verbatim as the email_verified claim when non-nil
	omitToken     bool
	tokenStatus   int
	tokenRequests []oidcTokenCredentials
}

// oidcTokenCredentials is how one token request authenticated the client.
type oidcTokenCredentials struct {
	inHeader     bool
	clientID     string
	clientSecret string
}

// tokenCredentials lists the client credentials of every token request so far.
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
			login := startOIDCLogin(t, gate, idp, cmp.Or(tt.loginHost, "app.example"))
			rec := httptest.NewRecorder()
			gate.ServeHTTP(rec, login.callbackRequest(t, gate, tt.tamper))
			assertOIDCCallback(t, rec, tt.want)
		})
	}
}

// A browser that returns from the provider without a session sees a page that
// says why, while any other caller keeps the JSON error. The status is the same
// for both, and neither gets a session.
func TestApplicationAuthOIDCFailureScreens(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		configure func(p *oidcTestIdP)
		tamper    oidcTamper
		title     string
		retry     string
	}{
		{name: "visitor canceled at the provider", tamper: withQuery("error=access_denied"), title: "Sign-in was canceled"},
		{name: "provider reported another error", tamper: withQuery("error=server_error"), title: "Sign-in could not be completed"},
		{name: "state cookie is missing", tamper: withStateCookie(nil), title: "Sign-in took too long"},
		{name: "state cookie has expired", tamper: withStateCookie(expireOIDCState), title: "Sign-in took too long"},
		{name: "state belongs to another login", tamper: withQuery("code=authcode&state=other"), title: "Sign-in took too long"},
		{name: "token endpoint rejects the code", configure: func(p *oidcTestIdP) { p.tokenStatus = http.StatusBadRequest }, title: "Sign-in could not be completed"},
		{name: "account is not on the allowlist", configure: func(p *oidcTestIdP) {
			p.mutate = func(c *oidcIDTokenClaims) { c.Subject, c.Email = "user-999", "mallory@example.com" }
		}, title: "This account is not allowed", retry: applicationAuthLoginPath + "?prompt=select_account"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			for _, browser := range []bool{true, false} {
				idp := newOIDCTestIdP(t, tt.configure)
				gate := newOIDCTestGate(t, idp)
				login := startOIDCLogin(t, gate, idp, "app.example")
				req := login.callbackRequest(t, gate, tt.tamper)
				if browser {
					req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
				}
				rec := httptest.NewRecorder()
				gate.ServeHTTP(rec, req)
				assertOIDCCallback(t, rec, http.StatusUnauthorized)

				body := rec.Body.String()
				if !browser {
					var answer map[string]string
					if rec.Header().Get("Content-Type") != "application/json" || json.Unmarshal(rec.Body.Bytes(), &answer) != nil || answer["error"] == "" {
						t.Fatalf("scripted caller got %q: %q", rec.Header().Get("Content-Type"), body)
					}
					continue
				}
				if rec.Header().Get("Content-Type") != "text/html; charset=utf-8" || rec.Header().Get("Content-Security-Policy") != signinContentSecurityPolicy {
					t.Fatalf("browser got %q under CSP %q", rec.Header().Get("Content-Type"), rec.Header().Get("Content-Security-Policy"))
				}
				retry := applicationAuthLoginPath
				if tt.retry != "" {
					retry = tt.retry
				}
				for _, want := range []string{"<h1>" + tt.title + "</h1>", "app.example", `href="` + retry + `"`} {
					if !strings.Contains(body, want) {
						t.Fatalf("page is missing %q", want)
					}
				}
			}
		})
	}
}

// The not-allowed screen tells the visitor which account to have added, in the
// form an allowlist entry takes, and never what the allowlist holds.
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
			req := startOIDCLogin(t, gate, idp, "app.example").callbackRequest(t, gate, nil)
			req.Header.Set("Accept", "text/html")
			rec := httptest.NewRecorder()
			gate.ServeHTTP(rec, req)
			assertOIDCCallback(t, rec, http.StatusUnauthorized)

			body := rec.Body.String()
			if !strings.Contains(body, "<b>"+tt.account+"</b>") {
				t.Fatalf("page does not show the account %q", tt.account)
			}
			if strings.Contains(body, "<img") {
				t.Fatal("account reached the page unescaped")
			}
			for _, entry := range allowed {
				if strings.Contains(body, entry) {
					t.Fatalf("page reveals the allowlist entry %q", entry)
				}
			}
		})
	}
}

// The not-allowed page's retry carries prompt=select_account, so a browser still
// signed in to the refused account gets the provider's account chooser, and the
// retry keeps the deep link. No other login sends the prompt.
func TestApplicationAuthOIDCRetryAsksForAccountChooser(t *testing.T) {
	t.Parallel()

	idp := newOIDCTestIdP(t, func(p *oidcTestIdP) {
		p.mutate = func(c *oidcIDTokenClaims) { c.Subject, c.Email = "user-999", "mallory@example.com" }
	})
	gate := newOIDCTestGate(t, idp)
	login := startOIDCLoginAt(t, gate, idp, "app.example", applicationAuthLoginPath+"?next="+url.QueryEscape("/docs?page=2"))
	req := login.callbackRequest(t, gate, nil)
	req.Header.Set("Accept", "text/html")
	denied := httptest.NewRecorder()
	gate.ServeHTTP(denied, req)
	assertOIDCCallback(t, denied, http.StatusUnauthorized)
	// the page escapes the attribute, so the & between the query's parameters is written &amp;
	retry := `href="` + applicationAuthLoginPath + `?next=%2Fdocs%3Fpage%3D2&amp;prompt=select_account"`
	if !strings.Contains(denied.Body.String(), retry) {
		t.Fatalf("retry link is not the account-chooser login: %q", denied.Body.String())
	}

	for _, tt := range []struct {
		name, path string
		chooser    bool
	}{
		{name: "plain login", path: applicationAuthLoginPath},
		{name: "prompt none", path: applicationAuthLoginPath + "?prompt=none"},
		{name: "prompt login", path: applicationAuthLoginPath + "?prompt=login"},
		{name: "account chooser", path: applicationAuthLoginPath + "?prompt=select_account", chooser: true},
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

// A provider that cannot be reached when the login starts gives a browser a
// page that offers to try again and keeps its target, and any other caller the
// plain-text error. Neither starts a login.
func TestApplicationAuthOIDCUnreachableProviderScreen(t *testing.T) {
	t.Parallel()

	idp := newOIDCTestIdP(t, nil)
	gate := newOIDCTestGate(t, idp)
	idp.server.Close()

	for accept, contentType := range map[string]string{"text/html": "text/html; charset=utf-8", "": "text/plain; charset=utf-8"} {
		req := httptest.NewRequest(http.MethodGet, "https://app.example"+applicationAuthLoginPath+"?next="+url.QueryEscape("/docs?page=2"), nil)
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
		for _, want := range []string{"<h1>Sign-in could not be completed</h1>", `href="` + applicationAuthLoginPath + `?next=%2Fdocs%3Fpage%3D2"`} {
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

// TestApplicationAuthOIDCTokenRequestAuthentication protects the one-time
// authorization code: the token request names how the client authenticates, as
// the provider advertises, and is never sent a second time to probe another style.
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

// TestApplicationAuthOIDCRefusesCleartextProviderURLs protects the
// authorization code, PKCE verifier and client secret: an https issuer must not
// send the gateway to a cleartext endpoint, whether discovery names one or the
// provider redirects to one. Loopback http is accepted only under a loopback
// http issuer, which every other test in this file relies on.
func TestApplicationAuthOIDCRefusesCleartextProviderURLs(t *testing.T) {
	t.Parallel()

	secure := func(issuer, _ string) oidcDiscoveryDocument {
		return oidcDiscoveryDocument{
			Issuer:                issuer,
			AuthorizationEndpoint: issuer + "/authorize",
			TokenEndpoint:         issuer + "/token",
			JWKSURI:               issuer + "/jwks",
		}
	}
	tests := []struct {
		name string
		// document is what discovery publishes, given the https issuer and a
		// loopback http URL.
		document func(issuer, cleartext string) oidcDiscoveryDocument
		redirect bool // the https discovery URL redirects to the cleartext server
		want     int
	}{
		{"control: https endpoints", secure, false, http.StatusSeeOther},
		{"cleartext authorization endpoint", func(issuer, cleartext string) oidcDiscoveryDocument {
			doc := secure(issuer, cleartext)
			doc.AuthorizationEndpoint = cleartext + "/authorize"
			return doc
		}, false, http.StatusBadGateway},
		{"cleartext token endpoint", func(issuer, cleartext string) oidcDiscoveryDocument {
			doc := secure(issuer, cleartext)
			doc.TokenEndpoint = cleartext + "/token"
			return doc
		}, false, http.StatusBadGateway},
		{"cleartext jwks uri", func(issuer, cleartext string) oidcDiscoveryDocument {
			doc := secure(issuer, cleartext)
			doc.JWKSURI = cleartext + "/jwks"
			return doc
		}, false, http.StatusBadGateway},
		{"redirect from https to cleartext", secure, true, http.StatusBadGateway},
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

			rec := httptest.NewRecorder()
			gate.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://app.example"+applicationAuthLoginPath, nil))
			if rec.Code != tt.want {
				t.Fatalf("login status = %d, body %q; want %d", rec.Code, strings.TrimSpace(rec.Body.String()), tt.want)
			}
			if got := cleartextHits.Load(); got != 0 {
				t.Fatalf("cleartext server received %d requests; want none", got)
			}
		})
	}
}

// TestApplicationAuthOIDCStopsRedirectLoops keeps a misbehaving provider from
// holding a login on an endless redirect chain.
func TestApplicationAuthOIDCStopsRedirectLoops(t *testing.T) {
	t.Parallel()
	var hits atomic.Int32
	gate := newOIDCTLSGate(t, func(w http.ResponseWriter, r *http.Request, _ string) {
		hits.Add(1)
		http.Redirect(w, r, r.URL.Path, http.StatusFound)
	})
	rec := httptest.NewRecorder()
	gate.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://app.example"+applicationAuthLoginPath, nil))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("login status = %d; want 502", rec.Code)
	}
	if got := hits.Load(); got > oidcMaxRedirects {
		t.Fatalf("provider received %d requests; want at most %d", got, oidcMaxRedirects)
	}
}

// newOIDCTLSGate gates an application behind an https provider that answers
// every request with serve. It keeps the gateway's own HTTP client, with its
// timeout and redirect policy, and only makes it trust the test certificate.
func newOIDCTLSGate(t *testing.T, serve func(w http.ResponseWriter, r *http.Request, issuer string)) *applicationAuth {
	t.Helper()
	provider := httptest.NewUnstartedServer(nil)
	provider.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { serve(w, r, provider.URL) })
	provider.StartTLS()
	t.Cleanup(provider.Close)
	handler, err := NewApplicationAuth(http.NotFoundHandler(), applicationAuthTestIdentity(), ApplicationAuthConfig{
		Provider:       ApplicationAuthProviderOIDC,
		AllowedWallets: []string{"alice@example.com"},
		OIDCIssuerURL:  provider.URL,
		OIDCClientID:   oidcTestClientID,
	})
	if err != nil {
		t.Fatal(err)
	}
	gate := handler.(*applicationAuth)
	gate.oidc.httpClient.Transport = provider.Client().Transport
	return gate
}

// oidcRawEmailVerifiedClaims signs an arbitrary JSON value as email_verified:
// the outer field shadows the embedded claim of the same JSON name, and omitting
// it leaves the claim absent.
type oidcRawEmailVerifiedClaims struct {
	oidcIDTokenClaims
	EmailVerified json.RawMessage `json:"email_verified,omitempty"`
}

// TestApplicationAuthOIDCEmailVerifiedDecoding protects logins at providers
// that send email_verified as a string, and fails closed on anything else: an
// unrecognized value never verifies the email, yet it must not break the claims
// decode, or even sub: allowlists would lock out.
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

// newOIDCTestGate gates a stub application behind idp. It admits only the
// verified email alice@example.com unless allowed lists other principals.
func newOIDCTestGate(t *testing.T, idp *oidcTestIdP, allowed ...string) *applicationAuth {
	t.Helper()
	if len(allowed) == 0 {
		allowed = []string{"alice@example.com"}
	}
	handler, err := NewApplicationAuth(http.NotFoundHandler(), applicationAuthTestIdentity(), ApplicationAuthConfig{
		Provider:         ApplicationAuthProviderOIDC,
		AllowedWallets:   allowed,
		OIDCIssuerURL:    idp.issuerURL,
		OIDCClientID:     oidcTestClientID,
		OIDCClientSecret: idp.clientSecret,
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
	return startOIDCLoginAt(t, gate, idp, host, applicationAuthLoginPath)
}

// startOIDCLoginAt is startOIDCLogin for a login request that carries its own query.
func startOIDCLoginAt(t *testing.T, gate *applicationAuth, idp *oidcTestIdP, host, path string) oidcLogin {
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

// A login keeps its state in one cookie. A HEAD request never completes a
// login, so it must not start one and overwrite the state of a login in progress.
func TestApplicationAuthOIDCLoginStartsOnlyOnGet(t *testing.T) {
	t.Parallel()
	gate := newOIDCTestGate(t, newOIDCTestIdP(t, nil))
	rec := httptest.NewRecorder()
	gate.ServeHTTP(rec, httptest.NewRequest(http.MethodHead, "https://app.example"+applicationAuthLoginPath, nil))
	if rec.Code != http.StatusMethodNotAllowed || len(rec.Result().Cookies()) != 0 {
		t.Fatalf("HEAD login = %d with cookies %v; want 405 and no state cookie", rec.Code, rec.Result().Cookies())
	}
}

// The deep link travels in the state cookie, which a browser drops silently
// once it nears 4 KB, failing the login at the callback. A link that does not
// fit is replaced by / so the login still completes.
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
			gate.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://app.example"+applicationAuthLoginPath+"?next="+url.QueryEscape(tt.next), nil))
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

// The session follows the ID token's lifetime, but lasts at least
// oidcMinSessionTTL, so a token about to expire cannot produce a session that
// is invalid on arrival and sends the visitor through the provider again, and
// at most applicationAuthSessionTTL.
func TestApplicationAuthOIDCSessionLifetime(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		tokenLifetime time.Duration
		want          time.Duration
	}{
		{"token already inside the verification leeway", -30 * time.Second, oidcMinSessionTTL},
		{"token shorter than the minimum", 5 * time.Minute, oidcMinSessionTTL},
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
			login := startOIDCLogin(t, gate, idp, "app.example")
			callback := httptest.NewRecorder()
			gate.ServeHTTP(callback, login.callbackRequest(t, gate, nil))
			assertOIDCCallback(t, callback, http.StatusSeeOther)
			if got := oidcSessionExpiry(t, gate, callback).Sub(start); got < tt.want-5*time.Second || got > tt.want+5*time.Second {
				t.Fatalf("session lasts %v; want about %v", got, tt.want)
			}
		})
	}
}

// oidcSessionExpiry returns when the session cookie in rec expires.
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

// CheckApplicationAuthProvider lets the tunnel report at startup a provider
// that visitors could not sign in with, instead of leaving the first login to
// find out.
func TestCheckApplicationAuthProvider(t *testing.T) {
	t.Parallel()

	oidcConfig := func(issuer string) ApplicationAuthConfig {
		return ApplicationAuthConfig{
			Provider:       ApplicationAuthProviderOIDC,
			AllowedWallets: []string{"alice@example.com"},
			OIDCIssuerURL:  issuer,
			OIDCClientID:   oidcTestClientID,
		}
	}

	t.Run("reachable provider", func(t *testing.T) {
		t.Parallel()
		idp := newOIDCTestIdP(t, nil)
		if err := CheckApplicationAuthProvider(t.Context(), oidcConfig(idp.issuerURL)); err != nil {
			t.Fatalf("CheckApplicationAuthProvider() = %v; want nil", err)
		}
	})
	t.Run("issuer that publishes no discovery document", func(t *testing.T) {
		t.Parallel()
		idp := newOIDCTestIdP(t, nil)
		if err := CheckApplicationAuthProvider(t.Context(), oidcConfig(idp.issuerURL+"/missing")); err == nil {
			t.Fatal("CheckApplicationAuthProvider() = nil for an issuer without a discovery document")
		}
	})
	t.Run("provider that is down", func(t *testing.T) {
		t.Parallel()
		idp := newOIDCTestIdP(t, nil)
		idp.server.Close()
		if err := CheckApplicationAuthProvider(t.Context(), oidcConfig(idp.issuerURL)); err == nil {
			t.Fatal("CheckApplicationAuthProvider() = nil for a provider that is down")
		}
	})
	t.Run("configuration the resolver rejects", func(t *testing.T) {
		t.Parallel()
		cfg := ApplicationAuthConfig{Provider: ApplicationAuthProviderOIDC, OIDCIssuerURL: "https://idp.example", OIDCClientID: oidcTestClientID}
		if err := CheckApplicationAuthProvider(t.Context(), cfg); err == nil || !strings.Contains(err.Error(), "--auth-allow") {
			t.Fatalf("CheckApplicationAuthProvider() = %v; want the resolver's error about the missing allowlist", err)
		}
	})
	t.Run("providers with nothing outside the tunnel", func(t *testing.T) {
		t.Parallel()
		for _, provider := range []string{ApplicationAuthProviderSIWE, ApplicationAuthProviderCredential} {
			if err := CheckApplicationAuthProvider(t.Context(), ApplicationAuthConfig{Provider: provider}); err != nil {
				t.Errorf("CheckApplicationAuthProvider(%s) = %v; want nil", provider, err)
			}
		}
	})
}
