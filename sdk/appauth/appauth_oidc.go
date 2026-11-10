// Package appauth is the application sign-in gate: an http.Handler that signs
// visitors in with a wallet, an access credential, OpenID Connect, SAML, or an
// email link, and passes only signed-in requests to the application behind it.
package appauth

import (
	"context"
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
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"golang.org/x/oauth2"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func oidcSupportedSignatureAlgorithms() []jose.SignatureAlgorithm {
	return []jose.SignatureAlgorithm{
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
}

type oidcDiscoveryDocument struct {
	Issuer                   string   `json:"issuer"`
	AuthorizationEndpoint    string   `json:"authorization_endpoint"`
	TokenEndpoint            string   `json:"token_endpoint"`
	JWKSURI                  string   `json:"jwks_uri"`
	TokenEndpointAuthMethods []string `json:"token_endpoint_auth_methods_supported"`
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
	Nonce         string            `json:"nonce,omitempty"`
	Email         string            `json:"email,omitempty"`
	EmailVerified oidcEmailVerified `json:"email_verified"`
}

type oidcEmailVerified bool

func (v *oidcEmailVerified) UnmarshalJSON(data []byte) error {
	*v = string(data) == "true" || string(data) == `"true"`
	return nil
}

func (c oidcIDTokenClaims) vouchedEmail() string {
	if c.EmailVerified {
		return c.Email
	}
	return ""
}

type oidcAuthenticator struct {
	issuerURL    string
	clientID     string
	clientSecret string
	binding      string
	stateKey     []byte
	httpClient   *http.Client

	discovery providerCache[oidcDiscoveryDocument]
	jwks      providerCache[jose.JSONWebKeySet]
}

func newOIDCAuthenticator(settings applicationAuthSettings, stateKey []byte) *oidcAuthenticator {
	binding := sha256.Sum256([]byte(settings.issuerURL + "\x00" + settings.clientID))
	return &oidcAuthenticator{
		issuerURL:    settings.issuerURL,
		clientID:     settings.clientID,
		clientSecret: settings.clientSecret,
		binding:      base64.RawURLEncoding.EncodeToString(binding[:]),
		stateKey:     stateKey,
		httpClient:   utils.NewHTTPClient(utils.WithHTTPTimeout(providerHTTPTimeout), utils.WithHTTPCheckRedirect(checkProviderRedirect)),
	}
}

func normalizeOIDCIssuerURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errOIDCIssuerURLIsRequired
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("%w: %w", errOIDCIssuerURLMustValidURL, err)
	}
	if parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errOIDCIssuerURLMustValidURL
	}
	if parsed.Scheme != "https" && !isLoopbackHTTP(parsed) {
		return "", errOIDCIssuerURLMustUseHTTPS
	}
	return strings.TrimRight(raw, "/"), nil
}

func isLoopbackHTTP(u *url.URL) bool {
	return u.Scheme == "http" && utils.IsLoopbackHost(u.Hostname())
}

func validateOIDCEndpoint(issuerURL, endpoint string) error {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return fmt.Errorf("invalid oidc discovery endpoint %q", endpoint)
	}
	if parsed.Scheme == "https" {
		return nil
	}
	if issuer, err := url.Parse(issuerURL); err == nil && isLoopbackHTTP(issuer) && isLoopbackHTTP(parsed) {
		return nil
	}
	return fmt.Errorf("oidc discovery endpoint must use https (http on a loopback host only under a loopback http issuer): %q", endpoint)
}

func checkProviderRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= providerMaxRedirects {
		return errProviderRedirectedTooManyTimes
	}
	if req.URL.Scheme == "https" {
		return nil
	}
	if previous := via[len(via)-1].URL; previous.Scheme == "http" && isLoopbackHTTP(req.URL) {
		return nil
	}
	return fmt.Errorf("identity provider redirected to a non-https url: %s", req.URL.Redacted())
}

const accountChooserPrompt = "select_account"

func (o *oidcAuthenticator) serveLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	doc, err := o.discoveryDocument(r.Context())
	if err != nil {
		if acceptsHTML(r) {
			writeSigninFailurePage(w, r, http.StatusBadGateway, signinProviderFailedPage, urlHost(o.issuerURL), r.URL.Query().Get("next"))
			return
		}
		http.Error(w, "oidc discovery failed", http.StatusBadGateway)
		return
	}
	host, err := normalizeHost(r.Host)
	if err != nil {
		http.Error(w, "invalid request host", http.StatusBadRequest)
		return
	}
	o.issueOIDCServeLoginRedirect(w, r, issueOIDCServeLoginRedirectState{doc: doc, host: host})
}

type issueOIDCServeLoginRedirectState struct {
	doc  oidcDiscoveryDocument
	host string
}

func (o *oidcAuthenticator) issueOIDCServeLoginRedirect(w http.ResponseWriter, r *http.Request, state issueOIDCServeLoginRedirectState) {
	loginState := rand.Text()
	nonce := rand.Text()
	codeVerifier := oauth2.GenerateVerifier()
	now := time.Now().UTC()
	expiresAt := now.Add(applicationAuthLoginStateTTL)
	next := sanitizeApplicationAuthNext(r.URL.Query().Get("next"))
	stateClaims := oidcStateClaims{
		State:        loginState,
		Nonce:        nonce,
		CodeVerifier: codeVerifier,
		Host:         state.host,
		Next:         next,
		ExpiresAt:    expiresAt.Unix(),
	}
	stateToken, err := encodeApplicationAuthLoginState(o.stateKey, &stateClaims, &stateClaims.Next)
	if err != nil {
		http.Error(w, "could not create login state", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     applicationAuthOIDCStateCookie,
		Value:    stateToken,
		Path:     "/",
		MaxAge:   int(applicationAuthLoginStateTTL.Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	oauthCfg := o.oauth2Config(state.doc, state.host)
	authOptions := []oauth2.AuthCodeOption{
		oauth2.S256ChallengeOption(codeVerifier),
		oauth2.SetAuthURLParam("nonce", nonce),
	}
	if r.URL.Query().Get("prompt") == accountChooserPrompt {
		authOptions = append(authOptions, oauth2.SetAuthURLParam("prompt", accountChooserPrompt))
	}
	authURL := oauthCfg.AuthCodeURL(loginState, authOptions...)
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, authURL, http.StatusSeeOther)
}

func (a *applicationAuth) serveOIDCCallback(w http.ResponseWriter, r *http.Request) {
	if a.provider != ProviderOIDC || a.oidc == nil {
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
		a.failServeOIDCCallback(w, r, serveOIDCCallbackFailure{message: "missing oidc login state", page: signinProviderExpiredPage, next: "/"})
		return
	}
	now := time.Now().UTC()
	stateClaims, code, failure, hostInvalid := a.validateServeOIDCCallbackState(r, stateCookie.Value, now)
	if hostInvalid {
		a.writeJSONError(w, http.StatusBadRequest, "invalid request host")
		return
	}
	if failure != nil {
		a.failServeOIDCCallback(w, r, *failure)
		return
	}
	verified, err := a.oidc.exchangeAndVerify(r.Context(), code, stateClaims, now)
	if err != nil {
		a.failServeOIDCCallback(w, r, serveOIDCCallbackFailure{message: "oidc token verification failed", page: signinProviderFailedPage, next: stateClaims.Next})
		return
	}
	a.finishServeOIDCCallbackSession(w, r, serveOIDCCallbackSession{verified: verified, state: stateClaims, now: now})
}

type serveOIDCCallbackFailure struct {
	message string
	page    string
	next    string
	fields  []string
}

func (a *applicationAuth) failServeOIDCCallback(w http.ResponseWriter, r *http.Request, failure serveOIDCCallbackFailure) {
	if acceptsHTML(r) {
		writeSigninFailurePage(w, r, http.StatusUnauthorized, failure.page, urlHost(a.oidc.issuerURL), failure.next, failure.fields...)
		return
	}
	a.writeJSONError(w, http.StatusUnauthorized, failure.message)
}

func (a *applicationAuth) validateServeOIDCCallbackState(r *http.Request, stateCookieValue string, now time.Time) (oidcStateClaims, string, *serveOIDCCallbackFailure, bool) {
	host, err := normalizeHost(r.Host)
	if err != nil {
		return oidcStateClaims{}, "", nil, true
	}
	var stateClaims oidcStateClaims
	if err := decodeSignedApplicationAuthJSON(a.oidc.stateKey, stateCookieValue, &stateClaims); err != nil ||
		!sameApplicationHost(stateClaims.Host, host) ||
		now.Unix() >= stateClaims.ExpiresAt ||
		loginStateIssuedAt(stateClaims.ExpiresAt).Before(a.heldSince(host)) {
		next := "/"
		if err == nil {
			next = stateClaims.Next
		}
		return oidcStateClaims{}, "", &serveOIDCCallbackFailure{message: "invalid or expired oidc login state", page: signinProviderExpiredPage, next: next}, false
	}
	if errParam := strings.TrimSpace(r.URL.Query().Get("error")); errParam != "" {
		page := signinProviderFailedPage
		if errParam == "access_denied" {
			page = signinProviderCanceledPage
		}
		return oidcStateClaims{}, "", &serveOIDCCallbackFailure{message: "oidc login failed", page: page, next: stateClaims.Next}, false
	}
	queryState := strings.TrimSpace(r.URL.Query().Get("state"))
	code := strings.TrimSpace(r.URL.Query().Get("code"))
	if queryState == "" || code == "" || subtle.ConstantTimeCompare([]byte(queryState), []byte(stateClaims.State)) != 1 {
		return oidcStateClaims{}, "", &serveOIDCCallbackFailure{message: "invalid oidc callback state", page: signinProviderExpiredPage, next: stateClaims.Next}, false
	}
	return stateClaims, code, nil, false
}

type serveOIDCCallbackSession struct {
	verified oidcIDTokenClaims
	state    oidcStateClaims
	now      time.Time
}

func (a *applicationAuth) finishServeOIDCCallbackSession(w http.ResponseWriter, r *http.Request, session serveOIDCCallbackSession) {
	email := session.verified.vouchedEmail()
	subject, ok := a.resolveAllowedPrincipal(email, session.verified.Subject)
	if !ok {
		a.failServeOIDCCallback(w, r, serveOIDCCallbackFailure{message: "oidc principal is not allowed", page: signinProviderDeniedPage, next: session.state.Next, fields: []string{"@@ACCOUNT@@", providerAccount(email, session.verified.Subject)}})
		return
	}
	lifetime := min(max(session.verified.Expiry.Time().Sub(session.now), providerMinSessionTTL), applicationAuthSessionTTL)
	if err := a.setSession(w, Principal{Provider: ProviderOIDC, Subject: subject, Email: providerEmail(email)}, strings.TrimSpace(r.Host), session.now, session.now.Add(lifetime)); err != nil {
		a.writeJSONError(w, http.StatusInternalServerError, "could not create session")
		return
	}
	http.Redirect(w, r, sanitizeApplicationAuthNext(session.state.Next), http.StatusSeeOther)
}

func writeSigninFailurePage(w http.ResponseWriter, r *http.Request, status int, page, issuer, next string, fields ...string) {
	query := url.Values{}
	if next = sanitizeApplicationAuthNext(next); next != "/" {
		query.Set("next", next)
	}
	if page == signinProviderDeniedPage {
		query.Set("prompt", accountChooserPrompt)
	}
	retry := types.PathApplicationAuthLogin
	if len(query) > 0 {
		retry += "?" + query.Encode()
	}
	setSigninHeaders(w.Header())
	w.WriteHeader(status)
	writeSigninPage(w, page, r.Host, append([]string{"@@ISSUER@@", issuer, "@@RETRY@@", retry}, fields...)...)
}

func urlHost(raw string) string {
	if parsed, err := url.Parse(raw); err == nil && parsed.Host != "" {
		return parsed.Host
	}
	return raw
}

func acceptsHTML(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

func (o *oidcAuthenticator) oauth2Config(doc oidcDiscoveryDocument, host string) oauth2.Config {
	authStyle := oauth2.AuthStyleInHeader
	methods := doc.TokenEndpointAuthMethods
	switch {
	case o.clientSecret == "":
		authStyle = oauth2.AuthStyleInParams
	case slices.Contains(methods, "client_secret_post") && !slices.Contains(methods, "client_secret_basic"):
		authStyle = oauth2.AuthStyleInParams
	}
	return oauth2.Config{
		ClientID:     o.clientID,
		ClientSecret: o.clientSecret,
		RedirectURL:  "https://" + host + types.PathApplicationAuthCallback,
		Endpoint: oauth2.Endpoint{
			AuthURL:   doc.AuthorizationEndpoint,
			TokenURL:  doc.TokenEndpoint,
			AuthStyle: authStyle,
		},
		Scopes: []string{"openid", "email", "profile"},
	}
}

func (o *oidcAuthenticator) exchangeAndVerify(ctx context.Context, code string, state oidcStateClaims, now time.Time) (oidcIDTokenClaims, error) {
	doc, err := o.discoveryDocument(ctx)
	if err != nil {
		return oidcIDTokenClaims{}, err
	}
	jwks, err := o.jwks.get(ctx, providerMetadataCacheTTL, o.fetchJWKS)
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
		return oidcIDTokenClaims{}, errMissingIDTokenTokenResponse
	}

	claims, err := o.verifyIDToken(rawIDToken, state.Nonce, doc.Issuer, jwks, now)
	if !errors.Is(err, jose.ErrJWKSKidNotFound) && !errors.Is(err, jose.ErrCryptoFailure) {
		return claims, err
	}
	jwks, refreshErr := o.jwks.get(ctx, oidcJWKSRefreshInterval, o.fetchJWKS)
	if refreshErr != nil {
		return oidcIDTokenClaims{}, err
	}
	return o.verifyIDToken(rawIDToken, state.Nonce, doc.Issuer, jwks, now)
}

func (o *oidcAuthenticator) verifyIDToken(rawToken, expectedNonce, issuer string, jwks jose.JSONWebKeySet, now time.Time) (oidcIDTokenClaims, error) {
	parsed, err := jwt.ParseSigned(strings.TrimSpace(rawToken), oidcSupportedSignatureAlgorithms())
	if err != nil {
		return oidcIDTokenClaims{}, err
	}
	var claims oidcIDTokenClaims
	if err := parsed.Claims(oidcVerificationKey(parsed.Headers, &jwks), &claims); err != nil {
		return oidcIDTokenClaims{}, err
	}
	if claims.Expiry == nil {
		return oidcIDTokenClaims{}, errIDTokenExpiryIsRequired
	}
	if err := claims.ValidateWithLeeway(jwt.Expected{
		Issuer:      issuer,
		AnyAudience: jwt.Audience{o.clientID},
		Time:        now.UTC(),
	}, time.Minute); err != nil {
		return oidcIDTokenClaims{}, err
	}
	if subtle.ConstantTimeCompare([]byte(claims.Nonce), []byte(expectedNonce)) != 1 {
		return oidcIDTokenClaims{}, errIDTokenNonceMismatch
	}
	if strings.TrimSpace(claims.Subject) == "" {
		return oidcIDTokenClaims{}, errIDTokenSubjectIsRequired
	}
	return claims, nil
}

func oidcVerificationKey(headers []jose.Header, jwks *jose.JSONWebKeySet) any {
	if len(headers) != 1 || headers[0].KeyID != "" || len(jwks.Keys) != 1 {
		return jwks
	}
	if use := jwks.Keys[0].Use; use != "" && use != "sig" {
		return jwks
	}
	return jwks.Keys[0]
}

func (o *oidcAuthenticator) discoveryDocument(ctx context.Context) (oidcDiscoveryDocument, error) {
	return o.discovery.get(ctx, providerMetadataCacheTTL, o.fetchDiscovery)
}

func (o *oidcAuthenticator) fetchDiscovery(ctx context.Context) (oidcDiscoveryDocument, error) {
	discoveryURL := o.issuerURL + "/.well-known/openid-configuration"
	var doc oidcDiscoveryDocument
	if err := fetchOIDCJSON(ctx, o.httpClient, discoveryURL, &doc); err != nil {
		return oidcDiscoveryDocument{}, fmt.Errorf("fetch oidc discovery: %w", err)
	}
	doc.Issuer = strings.TrimSpace(doc.Issuer)
	doc.AuthorizationEndpoint = strings.TrimSpace(doc.AuthorizationEndpoint)
	doc.TokenEndpoint = strings.TrimSpace(doc.TokenEndpoint)
	doc.JWKSURI = strings.TrimSpace(doc.JWKSURI)
	if doc.Issuer == "" || doc.AuthorizationEndpoint == "" || doc.TokenEndpoint == "" || doc.JWKSURI == "" {
		return oidcDiscoveryDocument{}, errIncompleteOIDCDiscoveryDocument
	}
	if strings.TrimRight(doc.Issuer, "/") != o.issuerURL {
		return oidcDiscoveryDocument{}, errOIDCDiscoveryIssuerMismatch
	}
	for _, endpoint := range []string{doc.AuthorizationEndpoint, doc.TokenEndpoint, doc.JWKSURI} {
		if err := validateOIDCEndpoint(o.issuerURL, endpoint); err != nil {
			return oidcDiscoveryDocument{}, err
		}
	}
	return doc, nil
}

func (o *oidcAuthenticator) fetchJWKS(ctx context.Context) (jose.JSONWebKeySet, error) {
	doc, err := o.discoveryDocument(ctx)
	if err != nil {
		return jose.JSONWebKeySet{}, err
	}
	var jwks jose.JSONWebKeySet
	if err := fetchOIDCJSON(ctx, o.httpClient, doc.JWKSURI, &jwks); err != nil {
		return jose.JSONWebKeySet{}, fmt.Errorf("fetch oidc jwks: %w", err)
	}
	if len(jwks.Keys) == 0 {
		return jose.JSONWebKeySet{}, errOIDCJwksContainsNoKeys
	}
	return jwks, nil
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
