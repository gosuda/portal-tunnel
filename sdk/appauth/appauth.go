package appauth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
	"golang.org/x/sync/singleflight"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"
)

var (
	errOIDCIssuerURLIsRequired          = errors.New("oidc issuer url is required")
	errOIDCIssuerURLMustValidURL        = errors.New("oidc issuer url must be a valid URL without query or fragment")
	errOIDCIssuerURLMustUseHTTPS        = errors.New("oidc issuer url must use https (or http on a loopback host)")
	errProviderRedirectedTooManyTimes   = errors.New("identity provider redirected too many times")
	errEmailPrincipalsMustASCII         = errors.New("email principals must be ASCII; write internationalized domains in punycode")
	errApplicationAuthHandlerIsRequired = errors.New("application auth handler is required")
	errEmailRequiresPublicHosts         = errors.New("email requires PublicHosts: without them no host qualifies for a login link")
	errRequestHostNotPublic             = errors.New("request host is not a public address of this tunnel")
	errMissingIDTokenTokenResponse      = errors.New("missing id_token in token response")
	errIDTokenExpiryIsRequired          = errors.New("id_token expiry is required")
	errIDTokenNonceMismatch             = errors.New("id_token nonce mismatch")
	errIDTokenSubjectIsRequired         = errors.New("id_token subject is required")
	errIncompleteOIDCDiscoveryDocument  = errors.New("incomplete oidc discovery document")
	errOIDCDiscoveryIssuerMismatch      = errors.New("oidc discovery issuer mismatch")
	errOIDCJwksContainsNoKeys           = errors.New("oidc jwks contains no keys")
	errInvalidSignedValue               = errors.New("invalid signed value")
	errInvalidJSONRequest               = errors.New("invalid JSON request")
	errRequestMustContainOneJSONValue   = errors.New("request must contain one JSON value")
)

const (
	applicationAuthCookieName      = "__Host-portal_access"
	applicationAuthOIDCStateCookie = "__Host-portal_oidc_state"
	applicationAuthSessionTTL      = 24 * time.Hour
	applicationAuthLoginStateTTL   = 10 * time.Minute
	applicationAuthBodyLimit       = 64 << 10
	providerMetadataCacheTTL       = 15 * time.Minute
	oidcJWKSRefreshInterval        = time.Minute
	providerHTTPTimeout            = 10 * time.Second
	providerMaxRedirects           = 3
	oidcMetadataBodyLimit          = 256 << 10
)

const (
	applicationAuthStateTokenLimit = 3500
	applicationAuthNextLimit       = 16 << 10
	providerMinSessionTTL          = 15 * time.Minute
)

// Config configures the application sign-in gate. It is the auth component of a
// tunnel config: the agent config, the Agent API and the runtime carry it as it
// is, under its auth and auth_* keys.
//
// Allow holds the provider-scoped principal allowlist: Ethereum wallet addresses
// for siwe, credential subjects for credential. EmailList is the same list for
// the providers that name a visitor by email: verified emails, @domain entries,
// or sub: subjects for oidc and saml, and emails or @domain entries for email. A
// gate runs one provider, so the one list can mean either. oidc and saml also
// read Allow, where released configs keep it; use Allowed to read the list. oidc,
// saml and email refuse an empty list. An empty list opens siwe to any wallet and
// credential to any credential issued from the gate's identity.
//
// IdentityProof is a secret, like OIDCClientSecret and SMTPPassword: it is sent
// upstream with the identity headers and must not be logged. Only portal expose
// sets it; the agent config and the Agent API have no key for it.
//
// PublicHosts lists the hosts the application holds now, and the email provider
// requires it. A request names its own Host, and the next owner of an alias reads
// whatever a browser sends there, so with PublicHosts set the gate answers no
// request for any other host, and a session or sign-in on a host with a Since must
// be newer than it. Without it the gate believes the Host of a request. It is called on
// each request and is no setting, so no config format carries it and a stored
// Config leaves it nil.
type Config struct {
	Provider        string   `json:"auth,omitempty" toml:"auth,omitempty"`
	Allow           []string `json:"auth_allowed_wallets,omitempty" toml:"auth_allowed_wallets,omitempty"`
	EmailList       []string `json:"auth_email_list,omitempty" toml:"auth_email_list,omitempty"`
	IdentityHeaders bool     `json:"auth_identity_headers,omitempty" toml:"auth_identity_headers,omitempty"`
	IdentityProof   string   `json:"-" toml:"-"`
	OIDCConfig
	SAMLConfig
	EmailConfig
	PublicHosts func() []PublicHost `json:"-" toml:"-"`
}

// OIDCConfig holds the settings of the oidc provider; any other provider
// refuses them.
type OIDCConfig struct {
	OIDCIssuerURL    string `json:"auth_oidc_issuer,omitempty" toml:"auth_oidc_issuer,omitempty"`
	OIDCClientID     string `json:"auth_oidc_client_id,omitempty" toml:"auth_oidc_client_id,omitempty"`
	OIDCClientSecret string `json:"auth_oidc_client_secret,omitempty" toml:"auth_oidc_client_secret,omitempty"`
}

// SAMLConfig holds the settings of the saml provider; any other provider
// refuses them. The identity provider is described by its metadata, read from
// SAMLMetadataURL or from the SAMLMetadataFile path.
type SAMLConfig struct {
	SAMLMetadataURL      string `json:"auth_saml_metadata_url,omitempty" toml:"auth_saml_metadata_url,omitempty"`
	SAMLMetadataFile     string `json:"auth_saml_metadata_file,omitempty" toml:"auth_saml_metadata_file,omitempty"`
	SAMLEntityID         string `json:"auth_saml_entity_id,omitempty" toml:"auth_saml_entity_id,omitempty"`
	SAMLSubjectAttribute string `json:"auth_saml_subject_attribute,omitempty" toml:"auth_saml_subject_attribute,omitempty"`
}

// EmailConfig holds the settings of the email provider; any other provider
// refuses them. The tunnel mails each login link from SMTPFrom, the one fixed
// sender, through the operator's SMTP server at SMTPAddr. The username and
// password are for a server that requires a login; the password is a secret.
type EmailConfig struct {
	SMTPAddr     string `json:"auth_smtp_addr,omitempty" toml:"auth_smtp_addr,omitempty"`
	SMTPUsername string `json:"auth_smtp_username,omitempty" toml:"auth_smtp_username,omitempty"`
	SMTPPassword string `json:"auth_smtp_password,omitempty" toml:"auth_smtp_password,omitempty"`
	SMTPFrom     string `json:"auth_smtp_from,omitempty" toml:"auth_smtp_from,omitempty"`
}

// Allowed returns the allowlist from the key that holds it. Validation refuses a
// config that sets both.
func (c Config) Allowed() []string {
	if len(c.EmailList) > 0 {
		return c.EmailList
	}
	return c.Allow
}

// IsZero reports whether no auth setting is given. Any setting asks for the
// sign-in gate, so an incomplete one fails validation instead of leaving the
// application open.
func (c Config) IsZero() bool {
	return c.Provider == "" && len(c.Allowed()) == 0 && !c.IdentityHeaders && c.IdentityProof == "" &&
		c.OIDCConfig == (OIDCConfig{}) && c.SAMLConfig == (SAMLConfig{}) && c.EmailConfig == (EmailConfig{})
}

// Normalize returns c in the form a config stores: the provider in lower case,
// the allowlist normalized for that provider, and the provider settings without
// surrounding spaces. The identity proof is kept byte for byte. Validation stays
// with Validate, except that an allowlist next to an unknown provider is refused
// here already.
func (c Config) Normalize() (Config, error) {
	c.Provider = strings.ToLower(strings.TrimSpace(c.Provider))
	c.OIDCIssuerURL = strings.TrimSpace(c.OIDCIssuerURL)
	c.OIDCClientID = strings.TrimSpace(c.OIDCClientID)
	c.OIDCClientSecret = strings.TrimSpace(c.OIDCClientSecret)
	c.SAMLMetadataURL = strings.TrimSpace(c.SAMLMetadataURL)
	c.SAMLMetadataFile = strings.TrimSpace(c.SAMLMetadataFile)
	c.SAMLEntityID = strings.TrimSpace(c.SAMLEntityID)
	c.SAMLSubjectAttribute = strings.TrimSpace(c.SAMLSubjectAttribute)
	c.SMTPAddr = strings.TrimSpace(c.SMTPAddr)
	c.SMTPUsername = strings.TrimSpace(c.SMTPUsername)
	c.SMTPPassword = strings.TrimSpace(c.SMTPPassword)
	c.SMTPFrom = strings.TrimSpace(c.SMTPFrom)
	c.Allow, c.EmailList = slices.Clone(c.Allow), slices.Clone(c.EmailList)
	if c.Provider == "" {
		return c, nil
	}
	var err error
	if len(c.Allow) > 0 {
		if c.Allow, err = normalizeAllowed(c.Provider, c.Allow); err != nil {
			return c, err
		}
	}
	if len(c.EmailList) > 0 && ProviderTakesEmailList(c.Provider) {
		if c.EmailList, err = normalizeAllowed(c.Provider, c.EmailList); err != nil {
			return c, err
		}
	}
	return c, nil
}

// Public returns c without its secrets, the identity proof, the OIDC client
// secret and the SMTP password, for a status that must not reveal them.
func (c Config) Public() Config {
	c.Allow, c.EmailList = slices.Clone(c.Allow), slices.Clone(c.EmailList)
	c.IdentityProof = ""
	c.OIDCClientSecret = ""
	c.SMTPPassword = ""
	return c
}

type applicationAuth struct {
	next            http.Handler
	provider        string
	tunnelIdentity  types.Identity
	signingKey      []byte
	credentialKey   []byte
	siwe            *identity.SIWEAuthenticator
	oidc            *oidcAuthenticator
	saml            *samlAuthenticator
	email           *emailAuthenticator
	publicHosts     func() []PublicHost
	allowedSubjects map[string]struct{}
	allowAnySubject bool
	identityHeaders bool
	identityProof   string
}

// New wraps next in the sign-in gate. A request reaches next only when it carries
// a valid session or credential, and the gate's endpoints under
// types.PathApplicationAuthPrefix are the only other paths it answers.
// New reads no network, so a provider outage cannot keep it from building a gate: use Check to test the
// provider. A gate built from the same id, including its TokenSecret, and the same
// provider settings accepts the sessions of an earlier gate; the allowlist is
// checked again on every request.
func New(next http.Handler, id types.Identity, cfg Config) (http.Handler, error) {
	if next == nil {
		return nil, errApplicationAuthHandlerIsRequired
	}
	settings, err := resolveApplicationAuthConfig(cfg)
	if err != nil {
		return nil, err
	}
	state, err := buildApplicationAuthNewState(id, settings, cfg.PublicHosts)
	if err != nil {
		return nil, err
	}
	return &applicationAuth{
		next:            next,
		provider:        settings.provider,
		tunnelIdentity:  id,
		signingKey:      state.signingKey,
		credentialKey:   state.credentialKey,
		siwe:            state.siwe,
		oidc:            state.oidc,
		saml:            state.saml,
		email:           state.email,
		publicHosts:     cfg.PublicHosts,
		allowedSubjects: state.allowedSubjects,
		allowAnySubject: state.allowAnySubject,
		identityHeaders: cfg.IdentityHeaders,
		identityProof:   settings.identityProof,
	}, nil
}

type applicationAuthNewState struct {
	signingKey      []byte
	credentialKey   []byte
	allowedSubjects map[string]struct{}
	allowAnySubject bool
	siwe            *identity.SIWEAuthenticator
	oidc            *oidcAuthenticator
	saml            *samlAuthenticator
	email           *emailAuthenticator
}

func buildApplicationAuthNewState(id types.Identity, settings applicationAuthSettings, publicHosts func() []PublicHost) (applicationAuthNewState, error) {
	signingKeyRaw, err := identity.DeriveToken(id, "application-access-auth")
	if err != nil {
		return applicationAuthNewState{}, fmt.Errorf("derive application auth signing key: %w", err)
	}
	signingKey := []byte(signingKeyRaw)
	allowedSubjects := make(map[string]struct{}, len(settings.allowed))
	for _, subject := range settings.allowed {
		allowedSubjects[subject] = struct{}{}
	}
	allowAnySubject := settings.provider == ProviderSIWE || (settings.provider == ProviderCredential && len(settings.allowed) == 0)
	var siwe *identity.SIWEAuthenticator
	var oidc *oidcAuthenticator
	var saml *samlAuthenticator
	var email *emailAuthenticator
	switch settings.provider {
	case ProviderSIWE:
		siweAuth, err := identity.NewSIWEAuthenticator(identity.SIWEAuthConfig{
			AllowedAddresses: settings.allowed,
			AllowAnyAddress:  len(settings.allowed) == 0,
			Statement:        "Sign in to this Portal application",
			ChallengePrefix:  "pac_",
		})
		if err != nil {
			return applicationAuthNewState{}, err
		}
		siwe = siweAuth
	case ProviderOIDC, ProviderSAML:
		oidcAuth, samlAuth, err := buildOIDCSAMLProviders(id, settings)
		if err != nil {
			return applicationAuthNewState{}, err
		}
		oidc, saml = oidcAuth, samlAuth
	case ProviderEmail:
		if publicHosts == nil {
			return applicationAuthNewState{}, errEmailRequiresPublicHosts
		}
		email = newEmailAuthenticator(settings)
	}
	credentialKeyRaw, err := identity.DeriveToken(id, applicationCredentialKeyUse)
	if err != nil {
		return applicationAuthNewState{}, fmt.Errorf("derive application credential key: %w", err)
	}
	credentialKey := []byte(credentialKeyRaw)
	return applicationAuthNewState{
		signingKey:      signingKey,
		credentialKey:   credentialKey,
		allowedSubjects: allowedSubjects,
		allowAnySubject: allowAnySubject,
		siwe:            siwe,
		oidc:            oidc,
		saml:            saml,
		email:           email,
	}, nil
}

func buildOIDCSAMLProviders(id types.Identity, settings applicationAuthSettings) (*oidcAuthenticator, *samlAuthenticator, error) {
	stateKey, err := identity.DeriveToken(id, "application-access-"+settings.provider+"-state")
	if err != nil {
		return nil, nil, fmt.Errorf("derive %s state signing key: %w", settings.provider, err)
	}
	if settings.provider == ProviderOIDC {
		return newOIDCAuthenticator(settings, []byte(stateKey)), nil, nil
	}
	return nil, newSAMLAuthenticator(settings, []byte(stateKey)), nil
}

// Check fetches what the first login needs, the OIDC discovery document and
// signing keys or the SAML metadata, or signs in to the SMTP server without
// sending, so that a wrong issuer, metadata source, SMTP setting or an unreachable
// provider shows at startup instead of to the first visitor who tries to sign in.
// The email check matters most, because a visitor is never told that a mail could
// not be sent. Other providers depend on nothing outside the gate.
func Check(ctx context.Context, cfg Config) error {
	settings, err := resolveApplicationAuthConfig(cfg)
	if err != nil {
		return err
	}
	switch settings.provider {
	case ProviderOIDC:
		o := newOIDCAuthenticator(settings, nil)
		_, err = o.jwks.get(ctx, providerMetadataCacheTTL, o.fetchJWKS)
	case ProviderSAML:
		_, err = newSAMLAuthenticator(settings, nil).identityProvider(ctx)
	case ProviderEmail:
		err = newEmailAuthenticator(settings).check(ctx)
	}
	return err
}

func (a *applicationAuth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	credential := strings.TrimSpace(r.Header.Get(types.HeaderAccessCredential))
	utils.DelHeaderSpellings(r.Header, types.HeaderAccessCredential)
	utils.DelHeaderSpellings(r.Header, types.PortalIdentityHeaders...)
	if a.publicHosts != nil {
		if _, _, public := a.publicHost(r.Host); !public {
			a.writeJSONError(w, http.StatusMisdirectedRequest, errRequestHostNotPublic.Error())
			return
		}
	}

	switch r.URL.Path {
	case types.PathApplicationAuthLogin:
		a.serveLogin(w, r)
	case types.PathApplicationAuthChallenge:
		a.serveChallenge(w, r)
	case types.PathApplicationAuthVerify:
		a.serveVerify(w, r)
	case types.PathApplicationAuthRedeem:
		a.serveRedeem(w, r)
	case types.PathApplicationAuthCallback:
		a.serveOIDCCallback(w, r)
	case types.PathApplicationAuthSAMLACS:
		a.serveSAMLACS(w, r)
	case types.PathApplicationAuthSAMLMetadata:
		a.serveSAMLMetadata(w, r)
	case types.PathApplicationAuthEmailRequest:
		a.serveEmailRequest(w, r)
	case types.PathApplicationAuthEmailRedeem:
		a.serveEmailRedeem(w, r)
	case types.PathApplicationAuthLogout:
		a.serveLogout(w, r)
	default:
		a.serveGatedRequest(w, r, credential)
	}
}

func (a *applicationAuth) serveGatedRequest(w http.ResponseWriter, r *http.Request, credential string) {
	principal, ok := a.authenticate(r, credential)
	if !ok {
		a.requireLogin(w, r)
		return
	}
	if credential == "" && crossOriginWrite(r) {
		a.writeJSONError(w, http.StatusForbidden, "request origin is not allowed")
		return
	}
	stripApplicationAuthCookie(r)
	if a.identityHeaders {
		r.Header.Set(types.HeaderPortalUser, principal.Subject)
		r.Header.Set(types.HeaderPortalAuth, principal.Provider)
		if a.identityProof != "" {
			r.Header.Set(types.HeaderPortalProof, a.identityProof)
		}
	}
	a.next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalContextKey{}, principal)))
}

func (a *applicationAuth) heldSince(rawHost string) time.Time {
	if a.publicHosts == nil {
		return time.Time{}
	}
	_, since, _ := a.publicHost(rawHost)
	return since
}

func (a *applicationAuth) publicHost(rawHost string) (string, time.Time, bool) {
	requestHost, err := normalizeHost(rawHost)
	if err != nil {
		return "", time.Time{}, false
	}
	for _, candidate := range a.publicHosts() {
		if host, err := normalizeHost(candidate.URL); err == nil && host == requestHost {
			return host, candidate.Since, true
		}
	}
	return "", time.Time{}, false
}

func stripApplicationAuthCookie(r *http.Request) {
	cookies := r.Cookies()
	r.Header.Del("Cookie")
	for _, cookie := range cookies {
		if cookie.Name != applicationAuthCookieName && cookie.Name != applicationAuthOIDCStateCookie && cookie.Name != applicationAuthSAMLStateCookie {
			r.AddCookie(cookie)
		}
	}
}

func (a *applicationAuth) serveLogin(w http.ResponseWriter, r *http.Request) {
	if a.provider == ProviderOIDC && a.oidc != nil {
		a.oidc.serveLogin(w, r)
		return
	}
	if a.provider == ProviderSAML && a.saml != nil {
		a.saml.serveLogin(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	setSigninHeaders(w.Header())
	if r.Method == http.MethodHead {
		return
	}
	page := signinWalletPage
	switch a.provider {
	case ProviderCredential:
		page = signinCredentialPage
	case ProviderEmail:
		page = signinEmailPage
	}
	writeSigninPage(w, page, r.Host)
}

func (a *applicationAuth) serveLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || !sameOrigin(r) {
		a.writeJSONError(w, http.StatusForbidden, "logout requires a same-origin POST")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: applicationAuthCookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	w.WriteHeader(http.StatusNoContent)
}

func (a *applicationAuth) requireLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		next := r.URL.RequestURI()
		if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || len(next) > applicationAuthNextLimit {
			next = "/"
		}
		http.Redirect(w, r, types.PathApplicationAuthLogin+"?next="+url.QueryEscape(next), http.StatusSeeOther)
		return
	}
	a.writeJSONError(w, http.StatusUnauthorized, "authentication required")
}

func sameOrigin(r *http.Request) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	return strings.EqualFold(origin, "https://"+strings.TrimSpace(r.Host))
}

func crossOriginWrite(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" || sameOrigin(r) {
		return false
	}
	upgrade := r.Header.Get("Upgrade") != ""
	if origin == "null" && !upgrade && r.Header.Get("Sec-Fetch-Site") == "same-origin" {
		return false
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return upgrade
	default:
		return true
	}
}

func decodeApplicationAuthJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, applicationAuthBodyLimit)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return errInvalidJSONRequest
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errRequestMustContainOneJSONValue
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

type applicationAuthClaims struct {
	Subject        string `json:"sub"`
	Provider       string `json:"auth,omitempty"`
	Email          string `json:"email,omitempty"`
	Host           string `json:"host"`
	IssuedAtMillis int64  `json:"iat_ms,omitempty"`
	ExpiresAt      int64  `json:"exp"`
	Binding        string `json:"bnd,omitempty"`
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

type providerCache[T any] struct {
	flight singleflight.Group

	mu        sync.Mutex
	value     T
	fetchedAt time.Time
}

func (c *providerCache[T]) get(ctx context.Context, maxAge time.Duration, fetch func(context.Context) (T, error)) (T, error) {
	if value, ok := c.fresh(maxAge); ok {
		return value, nil
	}
	result := c.flight.DoChan("", func() (any, error) {
		if value, ok := c.fresh(maxAge); ok {
			return value, nil
		}
		value, err := fetch(context.WithoutCancel(ctx))
		if err != nil {
			return nil, err
		}
		c.mu.Lock()
		c.value, c.fetchedAt = value, time.Now()
		c.mu.Unlock()
		return value, nil
	})
	var zero T
	select {
	case res := <-result:
		if res.Err != nil {
			return zero, res.Err
		}
		return res.Val.(T), nil
	case <-ctx.Done():
		return zero, ctx.Err()
	}
}

func (c *providerCache[T]) fresh(maxAge time.Duration) (T, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.value, !c.fetchedAt.IsZero() && time.Since(c.fetchedAt) < maxAge
}

func (a *applicationAuth) authorizeMutation(w http.ResponseWriter, r *http.Request, provider string) bool {
	if a.provider != provider {
		a.writeJSONError(w, http.StatusNotFound, "not found")
		return false
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		a.writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return false
	}
	if !sameOrigin(r) {
		a.writeJSONError(w, http.StatusForbidden, "request origin is not allowed")
		return false
	}
	return true
}

func (a *applicationAuth) serveChallenge(w http.ResponseWriter, r *http.Request) {
	if !a.authorizeMutation(w, r, ProviderSIWE) {
		return
	}
	var req applicationAuthChallengeRequest
	if err := decodeApplicationAuthJSON(w, r, &req); err != nil {
		a.writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	host := strings.TrimSpace(r.Host)
	now := time.Now().UTC()
	challenge, err := a.siwe.Issue(req.Address, host, "https://"+host, now)
	if err != nil {
		a.writeJSONError(w, http.StatusUnauthorized, err.Error())
		return
	}
	a.writeJSON(w, http.StatusOK, applicationAuthChallengeResponse{ChallengeID: challenge.ID, Message: challenge.Message, ExpiresAt: challenge.ExpiresAt})
}

func (a *applicationAuth) serveVerify(w http.ResponseWriter, r *http.Request) {
	if !a.authorizeMutation(w, r, ProviderSIWE) {
		return
	}
	var req applicationAuthVerifyRequest
	if err := decodeApplicationAuthJSON(w, r, &req); err != nil {
		a.writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	now := time.Now().UTC()
	address, err := a.siwe.Verify(req.ChallengeID, req.Message, req.Signature, r.Host, a.heldSince(r.Host), now)
	if err != nil {
		a.writeJSONError(w, http.StatusUnauthorized, "wallet signature is invalid")
		return
	}
	if err := a.setSession(w, Principal{Provider: ProviderSIWE, Subject: address}, strings.TrimSpace(r.Host), now, now.Add(applicationAuthSessionTTL)); err != nil {
		a.writeJSONError(w, http.StatusInternalServerError, "could not create session")
		return
	}
	a.writeJSON(w, http.StatusOK, map[string]string{"address": address})
}

func (a *applicationAuth) serveRedeem(w http.ResponseWriter, r *http.Request) {
	if !a.authorizeMutation(w, r, ProviderCredential) {
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
	if err := a.setSession(w, Principal{Provider: ProviderCredential, Subject: claims.Subject}, strings.TrimSpace(r.Host), now, expiresAt); err != nil {
		a.writeJSONError(w, http.StatusInternalServerError, "could not create session")
		return
	}
	a.writeJSON(w, http.StatusOK, map[string]string{"subject": claims.Subject})
}

func (a *applicationAuth) authenticate(r *http.Request, credential string) (Principal, bool) {
	if credential == "" {
		return a.authenticateSession(r)
	}
	if a.provider != ProviderCredential {
		return Principal{}, false
	}
	claims, err := verifyApplicationCredential(a.credentialKey, a.tunnelIdentity, r.Host, credential, time.Now().UTC())
	if err == nil && a.subjectAllowed(claims.Subject) {
		return Principal{Provider: ProviderCredential, Subject: claims.Subject}, true
	}
	return Principal{}, false
}

func (a *applicationAuth) authenticateSession(r *http.Request) (Principal, bool) {
	cookie, err := r.Cookie(applicationAuthCookieName)
	if err != nil {
		return Principal{}, false
	}
	var claims applicationAuthClaims
	if err := decodeSignedApplicationAuthJSON(a.signingKey, cookie.Value, &claims); err != nil || !sameApplicationHost(claims.Host, r.Host) || time.Now().UTC().Unix() >= claims.ExpiresAt {
		return Principal{}, false
	}
	provider := claims.Provider
	if provider != a.provider {
		return Principal{}, false
	}
	if claims.IssuedAtMillis < a.heldSince(r.Host).UnixMilli() {
		return Principal{}, false
	}
	if provider == ProviderSIWE {
		address, err := identity.NormalizeEVMAddress(claims.Subject)
		if err != nil || a.siwe == nil || !a.siwe.AddressAllowed(address) {
			return Principal{}, false
		}
		return Principal{Provider: provider, Subject: address}, true
	}
	subject, ok := a.resolveAuthenticateSessionSubject(provider, claims.Subject, claims.Binding)
	if !ok {
		return Principal{}, false
	}
	return Principal{Provider: provider, Subject: subject, Email: claims.Email}, true
}

func (a *applicationAuth) resolveAuthenticateSessionSubject(provider, subjectClaim, bindingClaim string) (string, bool) {
	var subject string
	var err error
	switch provider {
	case ProviderOIDC, ProviderSAML, ProviderEmail:
		if binding := a.binding(); binding == "" || bindingClaim != binding {
			return "", false
		}
		subject, err = normalizeProviderPrincipal(subjectClaim)
	default:
		subject, err = normalizeApplicationAuthSubject(subjectClaim)
	}
	if err != nil || !a.subjectAllowed(subject) {
		return "", false
	}
	return subject, true
}

func (a *applicationAuth) issueSession(principal Principal, host string, issuedAt, expiresAt time.Time) (string, error) {
	claims := applicationAuthClaims{Subject: principal.Subject, Provider: principal.Provider, Email: principal.Email, Host: host, IssuedAtMillis: issuedAt.UnixMilli(), ExpiresAt: expiresAt.Unix(), Binding: a.binding()}
	return encodeSignedApplicationAuthJSON(a.signingKey, claims)
}

func (a *applicationAuth) binding() string {
	switch {
	case a.oidc != nil:
		return a.oidc.binding
	case a.saml != nil:
		return a.saml.binding
	case a.email != nil:
		return a.email.binding
	default:
		return ""
	}
}

func (a *applicationAuth) setSession(w http.ResponseWriter, principal Principal, host string, now, expiresAt time.Time) error {
	token, err := a.issueSession(principal, host, now, expiresAt)
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

func loginStateIssuedAt(expiresAt int64) time.Time {
	return time.Unix(expiresAt, 0).Add(-applicationAuthLoginStateTTL)
}

func encodeApplicationAuthLoginState(key []byte, claims any, next *string) (string, error) {
	token, err := encodeSignedApplicationAuthJSON(key, claims)
	if err == nil && len(token) > applicationAuthStateTokenLimit {
		*next = "/"
		token, err = encodeSignedApplicationAuthJSON(key, claims)
	}
	return token, err
}

func decodeSignedApplicationAuthJSON(key []byte, token string, dst any) error {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return errInvalidSignedValue
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return errInvalidSignedValue
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || !hmac.Equal(signature, signApplicationAuthPayload(key, payload)) {
		return errInvalidSignedValue
	}
	return json.Unmarshal(payload, dst)
}

func signApplicationAuthPayload(key, payload []byte) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(payload)
	return mac.Sum(nil)
}

type principalContextKey struct{}

// PublicHost is a URL the application is reachable at now.
type PublicHost struct {
	URL string
	// Since is when the application came to hold URL. Set it for a URL that can
	// change hands, such as an alias, so that a session or a sign-in from an
	// earlier hold does not count. Credentials are not dated, because they have to
	// outlive a restart. Leave Since zero for a URL only this identity can hold.
	Since time.Time
}

// Principal is the visitor the gate signed in.
type Principal struct {
	// Provider is the method that signed the visitor in, such as ProviderOIDC.
	Provider string
	// Subject is the principal the allowlist checks: a wallet address, a
	// credential subject, an email, or a sub:<subject> entry.
	Subject string
	// Email is the address oidc, saml or email vouches for, also when Subject
	// is a sub: entry, and empty when there is none. An OIDC email counts only
	// with email_verified. It is the value from the sign-in: the allowlist checks
	// Subject on each request, not this. A session from before this field reads
	// as no email until the visitor signs in again.
	Email string
}

// PrincipalFromContext returns the visitor of a request that passed the gate,
// with or without Config.IdentityHeaders. Without a gate in front of the handler
// there is none.
func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	principal, ok := ctx.Value(principalContextKey{}).(Principal)
	return principal, ok
}

func normalizeProviderPrincipals(values []string) ([]string, error) {
	if len(values) == 0 {
		return nil, nil
	}
	normalized := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, raw := range values {
		principal, err := normalizeProviderAllowlistEntry(raw)
		if err != nil {
			return nil, err
		}
		if _, ok := seen[principal]; ok {
			continue
		}
		seen[principal] = struct{}{}
		normalized = append(normalized, principal)
	}
	return normalized, nil
}

func normalizeProviderAllowlistEntry(raw string) (string, error) {
	principal, err := normalizeProviderPrincipal(raw)
	if err != nil {
		return "", fmt.Errorf("principal %q: %w", raw, err)
	}
	if strings.HasPrefix(principal, subjectPrincipalPrefix) {
		return principal, nil
	}
	_, domain, ok := strings.Cut(principal, "@")
	if !ok || domain == "" || strings.ContainsAny(domain, "@ ") {
		return "", fmt.Errorf("principal %q must be an email, an @example.com domain, or a sub:<subject> entry", raw)
	}
	return principal, nil
}

const subjectPrincipalPrefix = "sub:"

func normalizeProviderPrincipal(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	isSubject := len(raw) >= len(subjectPrincipalPrefix) && strings.EqualFold(raw[:len(subjectPrincipalPrefix)], subjectPrincipalPrefix)
	if isSubject {
		raw = raw[len(subjectPrincipalPrefix):]
	}
	subject, err := normalizeApplicationAuthSubject(raw)
	if err != nil {
		return "", err
	}
	if isSubject {
		return subjectPrincipalPrefix + subject, nil
	}
	if strings.ContainsFunc(subject, func(r rune) bool { return r > unicode.MaxASCII }) {
		return "", errEmailPrincipalsMustASCII
	}
	if strings.Contains(subject, "@") {
		subject = strings.ToLower(subject)
	}
	return subject, nil
}

func providerClaimPrincipal(raw string) string {
	principal, err := normalizeProviderPrincipal(raw)
	if err != nil || strings.HasPrefix(principal, "@") {
		return ""
	}
	return principal
}

func sanitizeApplicationAuthNext(raw string) string {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") || strings.HasPrefix(raw, "/\\") || strings.ContainsFunc(raw, isUnsafeRedirectRune) {
		return "/"
	}
	return raw
}

func isUnsafeRedirectRune(r rune) bool {
	return r < 0x20 || r == 0x7f || r == '\\'
}

func providerEmail(raw string) string {
	email := providerClaimPrincipal(raw)
	if !strings.Contains(email, "@") || strings.HasPrefix(email, subjectPrincipalPrefix) {
		return ""
	}
	return email
}

func providerAccount(email, subject string) string {
	if email := providerEmail(email); email != "" {
		return email
	}
	return subjectPrincipalPrefix + subject
}

func (a *applicationAuth) resolveAllowedPrincipal(email, subject string) (string, bool) {
	if email := providerEmail(email); email != "" && a.subjectAllowed(email) {
		return email, true
	}
	if subject != strings.TrimSpace(subject) {
		return "", false
	}
	sub, err := normalizeProviderPrincipal(subjectPrincipalPrefix + subject)
	if err == nil && a.subjectAllowed(sub) {
		return sub, true
	}
	return "", false
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
	if !ProviderTakesEmailList(a.provider) {
		return false
	}
	if strings.HasPrefix(subject, "sub:") {
		return false
	}
	if _, domain, ok := strings.Cut(subject, "@"); ok && !strings.Contains(domain, "@") {
		_, ok = a.allowedSubjects["@"+domain]
		return ok
	}
	return false
}
