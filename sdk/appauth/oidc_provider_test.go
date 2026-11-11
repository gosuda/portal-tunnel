package appauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
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
