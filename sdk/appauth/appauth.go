// Package appauth is the application sign-in gate: an http.Handler that signs
// visitors in with a wallet, an access credential, OpenID Connect, SAML, or an
// email link, and passes only signed-in requests to the application behind it.
package appauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
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
	providers, err := buildApplicationAuthNewProviders(id, settings, publicHosts)
	if err != nil {
		return applicationAuthNewState{}, err
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
		siwe:            providers.siwe,
		oidc:            providers.oidc,
		saml:            providers.saml,
		email:           providers.email,
	}, nil
}

type applicationAuthNewProviders struct {
	siwe  *identity.SIWEAuthenticator
	oidc  *oidcAuthenticator
	saml  *samlAuthenticator
	email *emailAuthenticator
}

func buildApplicationAuthNewProviders(id types.Identity, settings applicationAuthSettings, publicHosts func() []PublicHost) (applicationAuthNewProviders, error) {
	var providers applicationAuthNewProviders
	switch settings.provider {
	case ProviderSIWE:
		siweAuth, err := identity.NewSIWEAuthenticator(identity.SIWEAuthConfig{
			AllowedAddresses: settings.allowed,
			AllowAnyAddress:  len(settings.allowed) == 0,
			Statement:        "Sign in to this Portal application",
			ChallengePrefix:  "pac_",
		})
		if err != nil {
			return applicationAuthNewProviders{}, err
		}
		providers.siwe = siweAuth
	case ProviderOIDC, ProviderSAML:
		oidcAuth, samlAuth, err := buildOIDCSAMLProviders(id, settings)
		if err != nil {
			return applicationAuthNewProviders{}, err
		}
		providers.oidc, providers.saml = oidcAuth, samlAuth
	case ProviderEmail:
		if publicHosts == nil {
			return applicationAuthNewProviders{}, errEmailRequiresPublicHosts
		}
		providers.email = newEmailAuthenticator(settings)
	}
	return providers, nil
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
