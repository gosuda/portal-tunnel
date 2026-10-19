package gateway

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"golang.org/x/oauth2"

	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/siweauth"
	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

const (
	applicationAuthLoginPath       = "/_portal/auth/login"
	applicationAuthChallengePath   = "/_portal/auth/challenge"
	applicationAuthVerifyPath      = "/_portal/auth/verify"
	applicationAuthRedeemPath      = "/_portal/auth/redeem"
	applicationAuthCallbackPath    = "/_portal/auth/callback"
	applicationAuthLogoutPath      = "/_portal/auth/logout"
	applicationAuthCookieName      = "__Host-portal_access"
	applicationAuthOIDCStateCookie = "__Host-portal_oidc_state"
	applicationAuthSessionTTL      = 24 * time.Hour
	applicationAuthOIDCStateTTL    = 10 * time.Minute
	applicationAuthBodyLimit       = 64 << 10
	oidcDiscoveryCacheTTL          = 15 * time.Minute
	oidcHTTPTimeout                = 10 * time.Second
	oidcMetadataBodyLimit          = 256 << 10
)

var oidcSupportedSignatureAlgorithms = []jose.SignatureAlgorithm{
	jose.RS256,
	jose.RS384,
	jose.RS512,
	jose.ES256,
	jose.ES384,
	jose.ES512,
	jose.EdDSA,
	jose.PS256,
	jose.PS384,
	jose.PS512,
}

type verifiedIdentityHeadersContextKey struct{}

const applicationAuthSIWELoginPage = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign in to Portal</title><style>
:root{color-scheme:dark}body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0b1020;color:#eef2ff;font:16px/1.5 system-ui,sans-serif}.card{width:min(30rem,calc(100% - 3rem));padding:2rem;border:1px solid #334155;border-radius:1rem;background:#111827;box-shadow:0 1.5rem 4rem #0008}h1{margin:0 0 .5rem;font-size:1.6rem}p{color:#cbd5e1}button{width:100%;padding:.8rem 1rem;border:0;border-radius:.6rem;background:#6366f1;color:white;font:inherit;font-weight:700;cursor:pointer}button:disabled{opacity:.6;cursor:wait}#status{min-height:1.5rem;color:#fca5a5;font-size:.9rem}
</style></head><body><main class="card"><h1>Sign in to continue</h1><p>This application is protected by Portal. Connect an Ethereum wallet and sign the one-time message.</p><button id="signin">Connect wallet</button><p id="status" role="alert"></p></main>
<script>
const button=document.querySelector('#signin'),status=document.querySelector('#status');
const next=()=>{const value=new URLSearchParams(location.search).get('next')||'/';return value.startsWith('/')&&!value.startsWith('//')&&!value.includes('\\')?value:'/'};
button.addEventListener('click',async()=>{button.disabled=true;status.textContent='';try{
if(!window.ethereum)throw new Error('No Ethereum wallet was found in this browser.');
const accounts=await window.ethereum.request({method:'eth_requestAccounts'});const address=accounts&&accounts[0];if(!address)throw new Error('The wallet did not provide an account.');
const challengeResponse=await fetch('/_portal/auth/challenge',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({address})});const challenge=await challengeResponse.json();if(!challengeResponse.ok)throw new Error(challenge.error||'Could not create a sign-in challenge.');
const signature=await window.ethereum.request({method:'personal_sign',params:[challenge.message,address]});
const verifyResponse=await fetch('/_portal/auth/verify',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({challenge_id:challenge.challenge_id,message:challenge.message,signature})});const result=await verifyResponse.json();if(!verifyResponse.ok)throw new Error(result.error||'The signature could not be verified.');location.assign(next());
}catch(error){status.textContent=error&&error.message?error.message:String(error);button.disabled=false;}});
</script></body></html>`

const applicationAuthCredentialLoginPage = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign in to Portal</title><style>
:root{color-scheme:dark}body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0b1020;color:#eef2ff;font:16px/1.5 system-ui,sans-serif}.card{width:min(30rem,calc(100% - 3rem));padding:2rem;border:1px solid #334155;border-radius:1rem;background:#111827;box-shadow:0 1.5rem 4rem #0008}h1{margin:0 0 .5rem;font-size:1.6rem}p{color:#cbd5e1}textarea,button{box-sizing:border-box;width:100%;padding:.8rem 1rem;border-radius:.6rem;font:inherit}textarea{min-height:7rem;background:#0b1020;color:#eef2ff;border:1px solid #475569;resize:vertical}button{margin-top:.75rem;border:0;background:#6366f1;color:white;font-weight:700;cursor:pointer}button:disabled{opacity:.6;cursor:wait}#status{min-height:1.5rem;color:#fca5a5;font-size:.9rem}
</style></head><body><main class="card"><h1>Sign in to continue</h1><p>This application is protected by Portal. Paste the access credential provided by its owner.</p><textarea id="credential" aria-label="Access credential" placeholder="pcred_..."></textarea><button id="signin">Sign in</button><p id="status" role="alert"></p></main>
<script>
const button=document.querySelector('#signin'),input=document.querySelector('#credential'),status=document.querySelector('#status');
const next=()=>{const value=new URLSearchParams(location.search).get('next')||'/';return value.startsWith('/')&&!value.startsWith('//')&&!value.includes('\\')?value:'/'};
const redeem=async()=>{button.disabled=true;status.textContent='';try{const credential=input.value.trim();if(!credential)throw new Error('An access credential is required.');const response=await fetch('/_portal/auth/redeem',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({credential})});const result=await response.json();if(!response.ok)throw new Error(result.error||'The credential could not be verified.');location.assign(next());}catch(error){status.textContent=error&&error.message?error.message:String(error);button.disabled=false;}};
button.addEventListener('click',redeem);const fragment=new URLSearchParams(location.hash.slice(1));if(fragment.has('credential')){input.value=fragment.get('credential');history.replaceState(null,'',location.pathname+location.search);redeem();}
</script></body></html>`

// ApplicationAuthConfig configures the tunnel-local application access gate.
// AllowedWallets holds the provider-scoped principal allowlist (Ethereum
// wallet addresses for siwe, credential subjects for credential, or email/sub
// principals for oidc).
type ApplicationAuthConfig struct {
	Provider         string
	AllowedWallets   []string
	IdentityHeaders  bool
	OIDCIssuerURL    string
	OIDCClientID     string
	OIDCClientSecret string
}

type applicationAuth struct {
	next            http.Handler
	provider        string
	tunnelIdentity  types.Identity
	signingKey      []byte
	credentialKey   []byte
	siwe            *siweauth.Authenticator
	oidc            *oidcAuthenticator
	allowedSubjects map[string]struct{}
	allowAnySubject bool
	identityHeaders bool
}

type applicationAuthClaims struct {
	Subject   string `json:"sub"`
	Provider  string `json:"auth,omitempty"`
	Host      string `json:"host"`
	ExpiresAt int64  `json:"exp"`
}

type applicationAuthChallengeRequest struct {
	Address string `json:"address"`
}

type applicationAuthChallengeResponse struct {
	ChallengeID string    `json:"challenge_id"`
	Message     string    `json:"message"`
	ExpiresAt   time.Time `json:"expires_at"`
}

type applicationAuthVerifyRequest struct {
	ChallengeID string `json:"challenge_id"`
	Message     string `json:"message"`
	Signature   string `json:"signature"`
}

type applicationAuthRedeemRequest struct {
	Credential string `json:"credential"`
}

type oidcDiscoveryDocument struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

type oidcStateClaims struct {
	State        string `json:"state"`
	Nonce        string `json:"nonce"`
	CodeVerifier string `json:"cv"`
	Host         string `json:"host"`
	Next         string `json:"next"`
	ExpiresAt    int64  `json:"exp"`
}

type oidcIDTokenClaims struct {
	jwt.Claims
	Nonce         string `json:"nonce,omitempty"`
	Email         string `json:"email,omitempty"`
	EmailVerified *bool  `json:"email_verified,omitempty"`
}

type oidcAuthenticator struct {
	issuerURL    string
	clientID     string
	clientSecret string
	stateKey     []byte
	httpClient   *http.Client

	mu          sync.Mutex
	discovery   oidcDiscoveryDocument
	jwks        jose.JSONWebKeySet
	refreshedAt time.Time
}

func newOIDCAuthenticator(cfg ApplicationAuthConfig, stateKey []byte) (*oidcAuthenticator, error) {
	issuerURL, err := normalizeOIDCIssuerURL(cfg.OIDCIssuerURL)
	if err != nil {
		return nil, err
	}
	clientID := strings.TrimSpace(cfg.OIDCClientID)
	if clientID == "" {
		return nil, errors.New("oidc client id is required")
	}
	return &oidcAuthenticator{
		issuerURL:    issuerURL,
		clientID:     clientID,
		clientSecret: strings.TrimSpace(cfg.OIDCClientSecret),
		stateKey:     stateKey,
		httpClient:   utils.NewHTTPClient(utils.WithHTTPTimeout(oidcHTTPTimeout)),
	}, nil
}

func normalizeOIDCIssuerURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("oidc issuer url is required")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("oidc issuer url must be a valid URL without query or fragment")
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "https" && !(scheme == "http" && isLoopbackHost(parsed.Hostname())) {
		return "", errors.New("oidc issuer url must use https (or http on a loopback host)")
	}
	return strings.TrimRight(raw, "/"), nil
}

// NormalizeApplicationAuthOIDCPrincipals canonicalizes OIDC allowed principals
// (`--auth-allow` / `auth_allowed_wallets`): email addresses (containing '@')
// are lowercased, while opaque subject identifiers keep their case.
func NormalizeApplicationAuthOIDCPrincipals(values []string) ([]string, error) {
	if len(values) == 0 {
		return nil, nil
	}
	normalized := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, raw := range values {
		principal, err := normalizeOIDCPrincipal(raw)
		if err != nil {
			return nil, err
		}
		if domain, isDomain := strings.CutPrefix(principal, "@"); isDomain && (domain == "" || strings.ContainsAny(domain, "@ ")) {
			return nil, fmt.Errorf("oidc domain principal %q must look like @example.com", raw)
		}
		if _, ok := seen[principal]; ok {
			continue
		}
		seen[principal] = struct{}{}
		normalized = append(normalized, principal)
	}
	return normalized, nil
}

func normalizeOIDCPrincipal(raw string) (string, error) {
	subject, err := normalizeApplicationAuthSubject(raw)
	if err != nil {
		return "", err
	}
	if strings.Contains(subject, "@") {
		return strings.ToLower(subject), nil
	}
	return subject, nil
}

// oidcClaimPrincipal normalizes an ID token claim value, or returns "" when it
// is unusable. A leading '@' is reserved for @domain allowlist entries, so a
// claim can never impersonate one.
func oidcClaimPrincipal(raw string) string {
	principal, err := normalizeOIDCPrincipal(raw)
	if err != nil || strings.HasPrefix(principal, "@") {
		return ""
	}
	return principal
}

func sanitizeApplicationAuthNext(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") || strings.Contains(raw, "\\") {
		return "/"
	}
	return raw
}

// NewApplicationAuth protects the complete HTTP gateway with tunnel-local
// authentication. Its reserved login endpoints are the only bypass paths.
func NewApplicationAuth(next http.Handler, tunnelIdentity types.Identity, cfg ApplicationAuthConfig) (http.Handler, error) {
	if next == nil {
		return nil, errors.New("application auth handler is required")
	}
	if err := ValidateApplicationAuthConfig(cfg); err != nil {
		return nil, err
	}
	signingKey, err := identity.DeriveToken(tunnelIdentity, "application-access-auth")
	if err != nil {
		return nil, fmt.Errorf("derive application auth signing key: %w", err)
	}
	provider, err := NormalizeApplicationAuthProvider(cfg.Provider)
	if err != nil {
		return nil, err
	}
	var (
		siwe            *siweauth.Authenticator
		oidc            *oidcAuthenticator
		allowedSubjects map[string]struct{}
		allowAnySubject = true
	)
	switch provider {
	case ApplicationAuthProviderSIWE:
		siwe, err = siweauth.New(siweauth.Config{
			AllowedAddresses: cfg.AllowedWallets,
			AllowAnyAddress:  len(cfg.AllowedWallets) == 0,
			Statement:        "Sign in to this Portal application",
			ChallengePrefix:  "pac_",
		})
		if err != nil {
			return nil, err
		}
	case ApplicationAuthProviderCredential:
		subjects, err := NormalizeApplicationAuthSubjects(cfg.AllowedWallets)
		if err != nil {
			return nil, err
		}
		if len(subjects) > 0 {
			allowAnySubject = false
			allowedSubjects = make(map[string]struct{}, len(subjects))
			for _, subject := range subjects {
				allowedSubjects[subject] = struct{}{}
			}
		}
	case ApplicationAuthProviderOIDC:
		principals, err := NormalizeApplicationAuthOIDCPrincipals(cfg.AllowedWallets)
		if err != nil {
			return nil, err
		}
		if len(principals) > 0 {
			allowAnySubject = false
			allowedSubjects = make(map[string]struct{}, len(principals))
			for _, principal := range principals {
				allowedSubjects[principal] = struct{}{}
			}
		}
		oidcStateKey, err := identity.DeriveToken(tunnelIdentity, "application-access-oidc-state")
		if err != nil {
			return nil, fmt.Errorf("derive oidc state signing key: %w", err)
		}
		oidc, err = newOIDCAuthenticator(cfg, []byte(oidcStateKey))
		if err != nil {
			return nil, err
		}
	}
	credentialKey, err := identity.DeriveToken(tunnelIdentity, applicationCredentialKeyUse)
	if err != nil {
		return nil, fmt.Errorf("derive application credential key: %w", err)
	}
	return &applicationAuth{
		next:            next,
		provider:        provider,
		tunnelIdentity:  tunnelIdentity,
		signingKey:      []byte(signingKey),
		credentialKey:   []byte(credentialKey),
		siwe:            siwe,
		oidc:            oidc,
		allowedSubjects: allowedSubjects,
		allowAnySubject: allowAnySubject,
		identityHeaders: cfg.IdentityHeaders,
	}, nil
}

func (a *applicationAuth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	credential := strings.TrimSpace(r.Header.Get(types.HeaderAccessCredential))
	r.Header.Del(types.HeaderAccessCredential)
	r.Header.Del(types.HeaderPortalUser)
	r.Header.Del(types.HeaderPortalAuth)

	switch r.URL.Path {
	case applicationAuthLoginPath:
		a.serveLogin(w, r)
	case applicationAuthChallengePath:
		a.serveChallenge(w, r)
	case applicationAuthVerifyPath:
		a.serveVerify(w, r)
	case applicationAuthRedeemPath:
		a.serveRedeem(w, r)
	case applicationAuthCallbackPath:
		a.serveOIDCCallback(w, r)
	case applicationAuthLogoutPath:
		a.serveLogout(w, r)
	default:
		subject, provider, ok := a.authenticate(r, credential)
		if !ok {
			a.requireLogin(w, r)
			return
		}
		stripApplicationAuthCookie(r)
		if a.identityHeaders {
			r.Header.Set(types.HeaderPortalUser, subject)
			r.Header.Set(types.HeaderPortalAuth, provider)
			r = r.WithContext(context.WithValue(r.Context(), verifiedIdentityHeadersContextKey{}, true))
		}
		a.next.ServeHTTP(w, r)
	}
}

func hasVerifiedIdentityHeaders(r *http.Request) bool {
	if r == nil {
		return false
	}
	verified, _ := r.Context().Value(verifiedIdentityHeadersContextKey{}).(bool)
	return verified
}

func stripApplicationAuthCookie(r *http.Request) {
	cookies := r.Cookies()
	r.Header.Del("Cookie")
	for _, cookie := range cookies {
		if cookie.Name != applicationAuthCookieName && cookie.Name != applicationAuthOIDCStateCookie {
			r.AddCookie(cookie)
		}
	}
}

func (a *applicationAuth) serveLogin(w http.ResponseWriter, r *http.Request) {
	if a.provider == ApplicationAuthProviderOIDC && a.oidc != nil {
		a.oidc.serveLogin(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.Method == http.MethodHead {
		return
	}
	page := applicationAuthSIWELoginPage
	if a.provider == ApplicationAuthProviderCredential {
		page = applicationAuthCredentialLoginPage
	}
	_, _ = io.WriteString(w, page)
}

func (o *oidcAuthenticator) serveLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	doc, _, err := o.metadata(r.Context(), false)
	if err != nil {
		http.Error(w, "oidc discovery failed", http.StatusBadGateway)
		return
	}
	host, err := NormalizeApplicationAuthHost(r.Host)
	if err != nil {
		http.Error(w, "invalid request host", http.StatusBadRequest)
		return
	}
	state := rand.Text()
	nonce := rand.Text()
	codeVerifier := oauth2.GenerateVerifier()
	now := time.Now().UTC()
	expiresAt := now.Add(applicationAuthOIDCStateTTL)
	next := sanitizeApplicationAuthNext(r.URL.Query().Get("next"))

	stateToken, err := encodeSignedApplicationAuthJSON(o.stateKey, oidcStateClaims{
		State:        state,
		Nonce:        nonce,
		CodeVerifier: codeVerifier,
		Host:         host,
		Next:         next,
		ExpiresAt:    expiresAt.Unix(),
	})
	if err != nil {
		http.Error(w, "could not create login state", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     applicationAuthOIDCStateCookie,
		Value:    stateToken,
		Path:     "/",
		MaxAge:   int(applicationAuthOIDCStateTTL.Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	oauthCfg := o.oauth2Config(doc, host)
	authURL := oauthCfg.AuthCodeURL(
		state,
		oauth2.S256ChallengeOption(codeVerifier),
		oauth2.SetAuthURLParam("nonce", nonce),
	)
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, authURL, http.StatusSeeOther)
}

func (a *applicationAuth) serveOIDCCallback(w http.ResponseWriter, r *http.Request) {
	if a.provider != ApplicationAuthProviderOIDC || a.oidc == nil {
		a.writeJSONError(w, http.StatusNotFound, "not found")
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		a.writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	stateCookie, err := r.Cookie(applicationAuthOIDCStateCookie)
	http.SetCookie(w, &http.Cookie{
		Name:     applicationAuthOIDCStateCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	if err != nil {
		a.writeJSONError(w, http.StatusUnauthorized, "missing oidc login state")
		return
	}

	now := time.Now().UTC()
	host, err := NormalizeApplicationAuthHost(r.Host)
	if err != nil {
		a.writeJSONError(w, http.StatusBadRequest, "invalid request host")
		return
	}
	var stateClaims oidcStateClaims
	if err := decodeSignedApplicationAuthJSON(a.oidc.stateKey, stateCookie.Value, &stateClaims); err != nil ||
		!strings.EqualFold(stateClaims.Host, host) ||
		now.Unix() >= stateClaims.ExpiresAt {
		a.writeJSONError(w, http.StatusUnauthorized, "invalid or expired oidc login state")
		return
	}
	if errParam := strings.TrimSpace(r.URL.Query().Get("error")); errParam != "" {
		a.writeJSONError(w, http.StatusUnauthorized, "oidc login failed")
		return
	}
	queryState := strings.TrimSpace(r.URL.Query().Get("state"))
	code := strings.TrimSpace(r.URL.Query().Get("code"))
	if queryState == "" || code == "" || subtle.ConstantTimeCompare([]byte(queryState), []byte(stateClaims.State)) != 1 {
		a.writeJSONError(w, http.StatusUnauthorized, "invalid oidc callback state")
		return
	}

	claims, err := a.oidc.exchangeAndVerify(r.Context(), code, stateClaims, now)
	if err != nil {
		a.writeJSONError(w, http.StatusUnauthorized, "oidc token verification failed")
		return
	}

	subject, ok := a.resolveAllowedOIDCSubject(claims)
	if !ok {
		a.writeJSONError(w, http.StatusUnauthorized, "oidc principal is not allowed")
		return
	}

	expiresAt := now.Add(applicationAuthSessionTTL)
	if claims.Expiry != nil {
		if tokenExpiry := claims.Expiry.Time(); tokenExpiry.Before(expiresAt) {
			expiresAt = tokenExpiry
		}
	}
	if err := a.setSession(w, subject, ApplicationAuthProviderOIDC, strings.TrimSpace(r.Host), now, expiresAt); err != nil {
		a.writeJSONError(w, http.StatusInternalServerError, "could not create session")
		return
	}
	http.Redirect(w, r, sanitizeApplicationAuthNext(stateClaims.Next), http.StatusSeeOther)
}

// resolveAllowedOIDCSubject maps ID token claims to the session subject. Only an
// explicitly verified email can match an email or @domain allowlist entry; the
// provider-assigned sub claim only matches an allowlist entry exactly.
func (a *applicationAuth) resolveAllowedOIDCSubject(claims oidcIDTokenClaims) (string, bool) {
	var email string
	if claims.EmailVerified != nil && *claims.EmailVerified {
		email = oidcClaimPrincipal(claims.Email)
	}
	sub := oidcClaimPrincipal(claims.Subject)
	if a.allowAnySubject {
		if email != "" {
			return email, true
		}
		return sub, sub != ""
	}
	if email != "" && a.subjectAllowed(email) {
		return email, true
	}
	if _, ok := a.allowedSubjects[sub]; ok {
		return sub, true
	}
	return "", false
}

func (o *oidcAuthenticator) oauth2Config(doc oidcDiscoveryDocument, host string) oauth2.Config {
	return oauth2.Config{
		ClientID:     o.clientID,
		ClientSecret: o.clientSecret,
		RedirectURL:  "https://" + host + applicationAuthCallbackPath,
		Endpoint: oauth2.Endpoint{
			AuthURL:  doc.AuthorizationEndpoint,
			TokenURL: doc.TokenEndpoint,
		},
		Scopes: []string{"openid", "email", "profile"},
	}
}

func (o *oidcAuthenticator) exchangeAndVerify(ctx context.Context, code string, state oidcStateClaims, now time.Time) (oidcIDTokenClaims, error) {
	doc, jwks, err := o.metadata(ctx, false)
	if err != nil {
		return oidcIDTokenClaims{}, err
	}
	oauthCtx := context.WithValue(ctx, oauth2.HTTPClient, o.httpClient)
	oauthCfg := o.oauth2Config(doc, state.Host)
	token, err := oauthCfg.Exchange(oauthCtx, code, oauth2.VerifierOption(state.CodeVerifier))
	if err != nil {
		return oidcIDTokenClaims{}, err
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || strings.TrimSpace(rawIDToken) == "" {
		return oidcIDTokenClaims{}, errors.New("missing id_token in token response")
	}

	claims, err := o.verifyIDToken(rawIDToken, state.Nonce, doc.Issuer, jwks, now)
	if err != nil {
		doc, jwks, refreshErr := o.metadata(ctx, true)
		if refreshErr != nil {
			return oidcIDTokenClaims{}, err
		}
		claims, err = o.verifyIDToken(rawIDToken, state.Nonce, doc.Issuer, jwks, now)
		if err != nil {
			return oidcIDTokenClaims{}, err
		}
	}
	return claims, nil
}

func (o *oidcAuthenticator) verifyIDToken(rawToken, expectedNonce, issuer string, jwks jose.JSONWebKeySet, now time.Time) (oidcIDTokenClaims, error) {
	parsed, err := jwt.ParseSigned(strings.TrimSpace(rawToken), oidcSupportedSignatureAlgorithms)
	if err != nil {
		return oidcIDTokenClaims{}, err
	}
	var claims oidcIDTokenClaims
	if err := parsed.Claims(&jwks, &claims); err != nil {
		return oidcIDTokenClaims{}, err
	}
	if claims.Expiry == nil {
		return oidcIDTokenClaims{}, errors.New("id_token expiry is required")
	}
	if err := claims.ValidateWithLeeway(jwt.Expected{
		Issuer:      issuer,
		AnyAudience: jwt.Audience{o.clientID},
		Time:        now.UTC(),
	}, time.Minute); err != nil {
		return oidcIDTokenClaims{}, err
	}
	if subtle.ConstantTimeCompare([]byte(claims.Nonce), []byte(expectedNonce)) != 1 {
		return oidcIDTokenClaims{}, errors.New("id_token nonce mismatch")
	}
	if strings.TrimSpace(claims.Subject) == "" {
		return oidcIDTokenClaims{}, errors.New("id_token subject is required")
	}
	return claims, nil
}

func (o *oidcAuthenticator) metadata(ctx context.Context, forceRefresh bool) (oidcDiscoveryDocument, jose.JSONWebKeySet, error) {
	o.mu.Lock()
	defer o.mu.Unlock()

	if !forceRefresh && !o.refreshedAt.IsZero() && time.Since(o.refreshedAt) < oidcDiscoveryCacheTTL {
		return o.discovery, o.jwks, nil
	}

	discoveryURL := o.issuerURL + "/.well-known/openid-configuration"
	var doc oidcDiscoveryDocument
	if err := fetchOIDCJSON(ctx, o.httpClient, discoveryURL, &doc); err != nil {
		return oidcDiscoveryDocument{}, jose.JSONWebKeySet{}, fmt.Errorf("fetch oidc discovery: %w", err)
	}
	doc.Issuer = strings.TrimSpace(doc.Issuer)
	doc.AuthorizationEndpoint = strings.TrimSpace(doc.AuthorizationEndpoint)
	doc.TokenEndpoint = strings.TrimSpace(doc.TokenEndpoint)
	doc.JWKSURI = strings.TrimSpace(doc.JWKSURI)
	if doc.Issuer == "" || doc.AuthorizationEndpoint == "" || doc.TokenEndpoint == "" || doc.JWKSURI == "" {
		return oidcDiscoveryDocument{}, jose.JSONWebKeySet{}, errors.New("incomplete oidc discovery document")
	}
	if strings.TrimRight(doc.Issuer, "/") != o.issuerURL {
		return oidcDiscoveryDocument{}, jose.JSONWebKeySet{}, errors.New("oidc discovery issuer mismatch")
	}
	for _, endpoint := range []string{doc.AuthorizationEndpoint, doc.TokenEndpoint, doc.JWKSURI} {
		if _, err := normalizeOIDCIssuerURL(endpoint); err != nil {
			return oidcDiscoveryDocument{}, jose.JSONWebKeySet{}, fmt.Errorf("invalid oidc discovery endpoint %q: %w", endpoint, err)
		}
	}

	var jwks jose.JSONWebKeySet
	if err := fetchOIDCJSON(ctx, o.httpClient, doc.JWKSURI, &jwks); err != nil {
		return oidcDiscoveryDocument{}, jose.JSONWebKeySet{}, fmt.Errorf("fetch oidc jwks: %w", err)
	}
	if len(jwks.Keys) == 0 {
		return oidcDiscoveryDocument{}, jose.JSONWebKeySet{}, errors.New("oidc jwks contains no keys")
	}

	o.discovery = doc
	o.jwks = jwks
	o.refreshedAt = time.Now().UTC()
	return o.discovery, o.jwks, nil
}

func fetchOIDCJSON(ctx context.Context, client *http.Client, targetURL string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	body := io.LimitReader(resp.Body, oidcMetadataBodyLimit)
	return json.NewDecoder(body).Decode(dst)
}

func (a *applicationAuth) serveChallenge(w http.ResponseWriter, r *http.Request) {
	if a.provider != ApplicationAuthProviderSIWE {
		a.writeJSONError(w, http.StatusNotFound, "not found")
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		a.writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !sameOrigin(r) {
		a.writeJSONError(w, http.StatusForbidden, "request origin is not allowed")
		return
	}
	var req applicationAuthChallengeRequest
	if err := decodeApplicationAuthJSON(w, r, &req); err != nil {
		a.writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	host := strings.TrimSpace(r.Host)
	now := time.Now().UTC()
	// Stateless issuance only fails per-request (address normalization or
	// policy), so every failure is an unauthorized challenge request.
	challenge, err := a.siwe.Issue(req.Address, host, "https://"+host, now)
	if err != nil {
		a.writeJSONError(w, http.StatusUnauthorized, err.Error())
		return
	}
	a.writeJSON(w, http.StatusOK, applicationAuthChallengeResponse{ChallengeID: challenge.ID, Message: challenge.Message, ExpiresAt: challenge.ExpiresAt})
}

func (a *applicationAuth) serveVerify(w http.ResponseWriter, r *http.Request) {
	if a.provider != ApplicationAuthProviderSIWE {
		a.writeJSONError(w, http.StatusNotFound, "not found")
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		a.writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !sameOrigin(r) {
		a.writeJSONError(w, http.StatusForbidden, "request origin is not allowed")
		return
	}
	var req applicationAuthVerifyRequest
	if err := decodeApplicationAuthJSON(w, r, &req); err != nil {
		a.writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	now := time.Now().UTC()
	address, err := a.siwe.Verify(req.ChallengeID, req.Message, req.Signature, r.Host, now)
	if err != nil {
		a.writeJSONError(w, http.StatusUnauthorized, "wallet signature is invalid")
		return
	}
	if err := a.setSession(w, address, ApplicationAuthProviderSIWE, strings.TrimSpace(r.Host), now, now.Add(applicationAuthSessionTTL)); err != nil {
		a.writeJSONError(w, http.StatusInternalServerError, "could not create session")
		return
	}
	a.writeJSON(w, http.StatusOK, map[string]string{"address": address})
}

func (a *applicationAuth) serveRedeem(w http.ResponseWriter, r *http.Request) {
	if a.provider != ApplicationAuthProviderCredential {
		a.writeJSONError(w, http.StatusNotFound, "not found")
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		a.writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !sameOrigin(r) {
		a.writeJSONError(w, http.StatusForbidden, "request origin is not allowed")
		return
	}
	var req applicationAuthRedeemRequest
	if err := decodeApplicationAuthJSON(w, r, &req); err != nil {
		a.writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	now := time.Now().UTC()
	claims, err := verifyApplicationCredential(a.credentialKey, a.tunnelIdentity, r.Host, req.Credential, now)
	if err != nil || !a.subjectAllowed(claims.Subject) {
		a.writeJSONError(w, http.StatusUnauthorized, "application credential is invalid or expired")
		return
	}
	expiresAt := time.Unix(claims.ExpiresAt, 0)
	if sessionExpiry := now.Add(applicationAuthSessionTTL); sessionExpiry.Before(expiresAt) {
		expiresAt = sessionExpiry
	}
	if err := a.setSession(w, claims.Subject, ApplicationAuthProviderCredential, strings.TrimSpace(r.Host), now, expiresAt); err != nil {
		a.writeJSONError(w, http.StatusInternalServerError, "could not create session")
		return
	}
	a.writeJSON(w, http.StatusOK, map[string]string{"subject": claims.Subject})
}

func (a *applicationAuth) serveLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || !sameOrigin(r) {
		a.writeJSONError(w, http.StatusForbidden, "logout requires a same-origin POST")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: applicationAuthCookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	w.WriteHeader(http.StatusNoContent)
}

func (a *applicationAuth) authenticate(r *http.Request, credential string) (string, string, bool) {
	if credential != "" {
		if a.provider != ApplicationAuthProviderCredential {
			return "", "", false
		}
		claims, err := verifyApplicationCredential(a.credentialKey, a.tunnelIdentity, r.Host, credential, time.Now().UTC())
		if err == nil && a.subjectAllowed(claims.Subject) {
			return claims.Subject, ApplicationAuthProviderCredential, true
		}
		return "", "", false
	}
	return a.authenticateSession(r)
}

func (a *applicationAuth) authenticateSession(r *http.Request) (string, string, bool) {
	cookie, err := r.Cookie(applicationAuthCookieName)
	if err != nil {
		return "", "", false
	}
	var claims applicationAuthClaims
	if err := decodeSignedApplicationAuthJSON(a.signingKey, cookie.Value, &claims); err != nil || !strings.EqualFold(claims.Host, strings.TrimSpace(r.Host)) || time.Now().UTC().Unix() >= claims.ExpiresAt {
		return "", "", false
	}
	provider := claims.Provider
	if provider != a.provider {
		return "", "", false
	}
	if provider == ApplicationAuthProviderSIWE {
		address, err := identity.NormalizeEVMAddress(claims.Subject)
		if err != nil || a.siwe == nil || !a.siwe.AddressAllowed(address) {
			return "", "", false
		}
		return address, provider, true
	}
	var subject string
	if provider == ApplicationAuthProviderOIDC {
		subject, err = normalizeOIDCPrincipal(claims.Subject)
	} else {
		subject, err = normalizeApplicationAuthSubject(claims.Subject)
	}
	if err != nil || !a.subjectAllowed(subject) {
		return "", "", false
	}
	return subject, provider, true
}

func (a *applicationAuth) subjectAllowed(subject string) bool {
	if a == nil {
		return false
	}
	if a.allowAnySubject {
		return true
	}
	if _, ok := a.allowedSubjects[subject]; ok {
		return true
	}
	if a.provider != ApplicationAuthProviderOIDC {
		return false
	}
	// An "@example.com" entry authorizes exactly that email domain, never its
	// subdomains. Login only passes a verified email here, and sessions only
	// carry subjects issued after that check.
	if _, domain, ok := strings.Cut(subject, "@"); ok && !strings.Contains(domain, "@") {
		_, ok = a.allowedSubjects["@"+domain]
		return ok
	}
	return false
}

func (a *applicationAuth) issueSession(subject, provider, host string, expiresAt time.Time) (string, error) {
	return encodeSignedApplicationAuthJSON(a.signingKey, applicationAuthClaims{Subject: subject, Provider: provider, Host: host, ExpiresAt: expiresAt.Unix()})
}

func (a *applicationAuth) setSession(w http.ResponseWriter, subject, provider, host string, now, expiresAt time.Time) error {
	token, err := a.issueSession(subject, provider, host, expiresAt)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{Name: applicationAuthCookieName, Value: token, Path: "/", MaxAge: max(1, int(expiresAt.Sub(now).Seconds())), HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	return nil
}

func encodeSignedApplicationAuthJSON(key []byte, value any) (string, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(signApplicationAuthPayload(key, payload)), nil
}

func decodeSignedApplicationAuthJSON(key []byte, token string, dst any) error {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return errors.New("invalid signed value")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return errors.New("invalid signed value")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || !hmac.Equal(signature, signApplicationAuthPayload(key, payload)) {
		return errors.New("invalid signed value")
	}
	return json.Unmarshal(payload, dst)
}

func signApplicationAuthPayload(key, payload []byte) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(payload)
	return mac.Sum(nil)
}

func (a *applicationAuth) requireLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		next := r.URL.RequestURI()
		if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") {
			next = "/"
		}
		http.Redirect(w, r, applicationAuthLoginPath+"?next="+url.QueryEscape(next), http.StatusSeeOther)
		return
	}
	a.writeJSONError(w, http.StatusUnauthorized, "authentication required")
}

func sameOrigin(r *http.Request) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	return strings.EqualFold(origin, "https://"+strings.TrimSpace(r.Host))
}

func decodeApplicationAuthJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, applicationAuthBodyLimit)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return errors.New("invalid JSON request")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("request must contain one JSON value")
	}
	return nil
}

func (a *applicationAuth) writeJSONError(w http.ResponseWriter, status int, message string) {
	a.writeJSON(w, status, map[string]string{"error": message})
}

func (a *applicationAuth) writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
