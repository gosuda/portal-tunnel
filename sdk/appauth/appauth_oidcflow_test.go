package appauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/gosuda/portal-tunnel/v2/types"
)

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
