// Package appauth is the application sign-in gate: an http.Handler that signs
// visitors in with a wallet, an access credential, OpenID Connect, SAML, or an
// email link, and passes only signed-in requests to the application behind it.
package appauth

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
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"golang.org/x/oauth2"
	"golang.org/x/sync/singleflight"

	"github.com/gosuda/portal-tunnel/v2/internal/siweauth"
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
	applicationAuthLoginPath       = "/_portal/auth/login"
	applicationAuthChallengePath   = "/_portal/auth/challenge"
	applicationAuthVerifyPath      = "/_portal/auth/verify"
	applicationAuthRedeemPath      = "/_portal/auth/redeem"
	applicationAuthCallbackPath    = "/_portal/auth/callback"
	applicationAuthLogoutPath      = "/_portal/auth/logout"
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
	// applicationAuthStateTokenLimit keeps a signed login state cookie well
	// under the roughly 4 KB a browser accepts, since it silently drops a larger one.
	applicationAuthStateTokenLimit = 3500
	// providerMinSessionTTL is the shortest OIDC or SAML session, so a
	// short-lived ID token or IdP session cannot produce a session that has
	// already expired.
	providerMinSessionTTL = 15 * time.Minute
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

type principalContextKey struct{}

// Principal is the visitor the gate signed in: the provider that vouched for
// them and the subject it named.
type Principal struct {
	Provider string
	Subject  string
}

// PrincipalFromContext returns the visitor of a request that passed the gate.
// Without a gate in front of the handler there is none.
func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	principal, ok := ctx.Value(principalContextKey{}).(Principal)
	return principal, ok
}

// ApplicationAuthConfig configures the tunnel-local application access gate.
// It is the auth component of a tunnel config: the agent config, the Agent API
// and the runtime carry it as it is, under its auth and auth_* keys, so a new
// provider setting is added here and in resolveApplicationAuthConfig only.
// AllowedWallets holds the provider-scoped principal allowlist: Ethereum wallet
// addresses for siwe, credential subjects for credential. EmailList is the same
// list for the providers that name a visitor by email: verified emails, @domain
// entries, or sub: subjects for oidc and saml, and emails or @domain entries for
// email. A tunnel runs one provider, so the one list can mean either. oidc and
// saml also read AllowedWallets, where released configs keep it; use Allowed to
// read the list. IdentityProof is a secret, like OIDCClientSecret and
// SMTPPassword: it is sent upstream with the identity headers and must not be
// logged. Only portal expose sets it; the agent config and the Agent API have no
// key for it.
type ApplicationAuthConfig struct {
	Provider        string   `json:"auth,omitempty" toml:"auth,omitempty"`
	AllowedWallets  []string `json:"auth_allowed_wallets,omitempty" toml:"auth_allowed_wallets,omitempty"`
	EmailList       []string `json:"auth_email_list,omitempty" toml:"auth_email_list,omitempty"`
	IdentityHeaders bool     `json:"auth_identity_headers,omitempty" toml:"auth_identity_headers,omitempty"`
	IdentityProof   string   `json:"-" toml:"-"`
	OIDCConfig
	SAMLConfig
	EmailConfig
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
func (c ApplicationAuthConfig) Allowed() []string {
	if len(c.EmailList) > 0 {
		return c.EmailList
	}
	return c.AllowedWallets
}

// IsZero reports whether no auth setting is given. Any setting asks for the
// sign-in gate, so an incomplete one fails validation instead of leaving the
// application open.
func (c ApplicationAuthConfig) IsZero() bool {
	return c.Provider == "" && len(c.Allowed()) == 0 && !c.IdentityHeaders && c.IdentityProof == "" &&
		c.OIDCConfig == (OIDCConfig{}) && c.SAMLConfig == (SAMLConfig{}) && c.EmailConfig == (EmailConfig{})
}

// Normalize returns c in the form a config stores: the provider in lower case,
// the allowlist normalized for that provider, and the provider settings without
// surrounding spaces. The identity proof is kept byte for byte. Validation stays
// with resolveApplicationAuthConfig, except that an allowlist next to an
// unknown provider is refused here already.
func (c ApplicationAuthConfig) Normalize() (ApplicationAuthConfig, error) {
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
	c.AllowedWallets, c.EmailList = slices.Clone(c.AllowedWallets), slices.Clone(c.EmailList)
	if c.Provider == "" {
		return c, nil
	}
	var err error
	if len(c.AllowedWallets) > 0 {
		if c.AllowedWallets, err = NormalizeApplicationAuthAllowed(c.Provider, c.AllowedWallets); err != nil {
			return c, err
		}
	}
	// A provider that does not take the list reads it as what it is not, so
	// resolveApplicationAuthConfig names the mistake instead.
	if len(c.EmailList) > 0 && ApplicationAuthProviderTakesEmailList(c.Provider) {
		if c.EmailList, err = NormalizeApplicationAuthAllowed(c.Provider, c.EmailList); err != nil {
			return c, err
		}
	}
	return c, nil
}

// Public returns c without its secrets, the identity proof, the OIDC client
// secret and the SMTP password, for a status that must not reveal them.
func (c ApplicationAuthConfig) Public() ApplicationAuthConfig {
	c.AllowedWallets, c.EmailList = slices.Clone(c.AllowedWallets), slices.Clone(c.EmailList)
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
	siwe            *siweauth.Authenticator
	oidc            *oidcAuthenticator
	saml            *samlAuthenticator
	email           *emailAuthenticator
	allowedSubjects map[string]struct{}
	allowAnySubject bool
	identityHeaders bool
	identityProof   string
}

type applicationAuthClaims struct {
	Subject   string `json:"sub"`
	Provider  string `json:"auth,omitempty"`
	Host      string `json:"host"`
	ExpiresAt int64  `json:"exp"`
	// Binding names the OIDC issuer and client, the SAML identity provider
	// and service provider, or the SMTP account and sender of email, that
	// authenticated the visitor.
	Binding string `json:"bnd,omitempty"`
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

// oidcEmailVerified decodes the email_verified claim. OIDC defines a JSON
// boolean, but some providers send the string "true". Only true and "true"
// count as verified; any other value, or none, decodes as not verified instead
// of failing the whole claims decode, which would also lock out sub: allowlists.
type oidcEmailVerified bool

func (v *oidcEmailVerified) UnmarshalJSON(data []byte) error {
	*v = string(data) == "true" || string(data) == `"true"`
	return nil
}

// vouchedEmail is the email the ID token vouches for: the email claim, and
// only when email_verified is true, so that an unverified address can never
// match an email or @domain allowlist entry.
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
	// binding digests the issuer and client ID into every OIDC session, since a
	// subject only means something at the issuer and client that produced it.
	binding    string
	stateKey   []byte
	httpClient *http.Client

	discovery providerCache[oidcDiscoveryDocument]
	jwks      providerCache[jose.JSONWebKeySet]
}

// providerCache holds one value fetched from the identity provider: the OIDC
// discovery document or signing keys, or the SAML metadata. mu guards only the
// cached value and is never held across network I/O.
type providerCache[T any] struct {
	flight singleflight.Group

	mu        sync.Mutex
	value     T
	fetchedAt time.Time
}

func newOIDCAuthenticator(settings applicationAuthSettings, stateKey []byte) *oidcAuthenticator {
	// A parsed issuer URL cannot hold a NUL, so the separator keeps the pair unambiguous.
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

// isLoopbackHTTP reports whether u is plain http on a loopback host, the one
// cleartext form an identity provider URL may take (local development and tests).
func isLoopbackHTTP(u *url.URL) bool {
	return u.Scheme == "http" && utils.IsLoopbackHost(u.Hostname())
}

// validateOIDCEndpoint checks an endpoint from the discovery document of
// issuerURL. Unlike an issuer identifier it may carry a query (RFC 6749
// sections 3.1/3.2). The token endpoint receives the authorization code, PKCE
// verifier and client secret, so an endpoint must be https unless the issuer
// itself is loopback http.
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

// checkProviderRedirect keeps a provider from redirecting the gateway's requests
// to cleartext or through a long chain. Like an endpoint, a redirect target
// must be https, or loopback http when the chain is already plain http.
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

// NormalizeApplicationAuthProviderPrincipals canonicalizes the allowed
// principals of an identity provider, oidc or saml (`--auth-email-list` /
// `auth_email_list`). Email addresses (containing '@') are lowercased and
// match an email the provider vouches for only, '@example.com' domain entries
// match that exact email domain, and `sub:<subject>` entries match the opaque
// provider subject exactly, including case. Subject entries must carry the
// sub: prefix so an email-shaped subject cannot impersonate an email entry.
func NormalizeApplicationAuthProviderPrincipals(values []string) ([]string, error) {
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

// normalizeProviderAllowlistEntry canonicalizes one `--auth-email-list` entry into its
// typed form: `sub:<subject>` for an opaque provider subject, a lowercased
// email for a verified-email entry, or a leading-'@' domain entry. A bare
// token cannot be told apart from an email-shaped subject claim, so subject
// entries must carry the sub: prefix.
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

// subjectPrincipalPrefix marks a principal as the provider's opaque subject:
// the OIDC sub claim or the SAML subject value.
const subjectPrincipalPrefix = "sub:"

// normalizeProviderPrincipal canonicalizes an OIDC or SAML principal or
// session subject. The provider's subject is an opaque, case-sensitive identifier, so a "sub:"
// principal keeps its subject byte for byte (only the prefix is matched without
// regard to case); only verified-email principals are lowercased. Email
// principals must be ASCII: Unicode lowercasing maps distinct characters onto
// ASCII ones (the Kelvin sign U+212A to "k", U+0130 to "i"), which would let a
// lookalike address match an allowlist entry. The length limit applies to the
// subject itself, not to the "sub:" prefix, so a maximum-length sub claim (255
// characters) still survives revalidation.
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

// providerClaimPrincipal normalizes an ID token claim or SAML subject value,
// or returns "" when it is unusable. A leading '@' is reserved for @domain
// allowlist entries, so a claim can never impersonate one.
func providerClaimPrincipal(raw string) string {
	principal, err := normalizeProviderPrincipal(raw)
	if err != nil || strings.HasPrefix(principal, "@") {
		return ""
	}
	return principal
}

// sanitizeApplicationAuthNext keeps a post-login target on this origin. A
// leading "//" or "/\" is read by browsers as a URL for another host, so the
// second character must be neither. Browsers also drop tabs and newlines from
// URLs, so "/<TAB>/host" would become "//host"; control characters and
// backslashes are therefore refused everywhere, keeping the target a plain path.
func sanitizeApplicationAuthNext(raw string) string {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") || strings.HasPrefix(raw, "/\\") || strings.ContainsFunc(raw, isUnsafeRedirectRune) {
		return "/"
	}
	return raw
}

// isUnsafeRedirectRune reports control characters and backslashes, which
// browsers drop or reinterpret in URLs.
func isUnsafeRedirectRune(r rune) bool {
	return r < 0x20 || r == 0x7f || r == '\\'
}

// NewApplicationAuth protects the complete HTTP gateway with tunnel-local
// authentication. Its reserved login endpoints are the only bypass paths.
// publicURLs lists the URLs the tunnel is reachable at now. Only the email
// provider uses it: a request names its own Host, so a login link is mailed
// only for a host on that list, and a nil publicURLs mails none.
func NewApplicationAuth(next http.Handler, tunnelIdentity types.Identity, cfg ApplicationAuthConfig, publicURLs func() []string) (http.Handler, error) {
	if next == nil {
		return nil, errApplicationAuthHandlerIsRequired
	}
	settings, err := resolveApplicationAuthConfig(cfg)
	if err != nil {
		return nil, err
	}
	signingKey, err := identity.DeriveToken(tunnelIdentity, "application-access-auth")
	if err != nil {
		return nil, fmt.Errorf("derive application auth signing key: %w", err)
	}
	var (
		siwe            *siweauth.Authenticator
		oidc            *oidcAuthenticator
		saml            *samlAuthenticator
		email           *emailAuthenticator
		allowedSubjects map[string]struct{}
		allowAnySubject = true
	)
	switch settings.provider {
	case ApplicationAuthProviderSIWE:
		siwe, err = siweauth.New(siweauth.Config{
			AllowedAddresses: settings.allowed,
			AllowAnyAddress:  len(settings.allowed) == 0,
			Statement:        "Sign in to this Portal application",
			ChallengePrefix:  "pac_",
		})
		if err != nil {
			return nil, err
		}
	case ApplicationAuthProviderCredential:
		if len(settings.allowed) > 0 {
			allowAnySubject = false
			allowedSubjects = make(map[string]struct{}, len(settings.allowed))
			for _, subject := range settings.allowed {
				allowedSubjects[subject] = struct{}{}
			}
		}
	case ApplicationAuthProviderOIDC, ApplicationAuthProviderSAML:
		// An identity provider never runs open: resolveApplicationAuthConfig
		// rejects an empty allowlist, because any account at the provider would pass.
		allowAnySubject = false
		allowedSubjects = make(map[string]struct{}, len(settings.allowed))
		for _, principal := range settings.allowed {
			allowedSubjects[principal] = struct{}{}
		}
		stateKey, err := identity.DeriveToken(tunnelIdentity, "application-access-"+settings.provider+"-state")
		if err != nil {
			return nil, fmt.Errorf("derive %s state signing key: %w", settings.provider, err)
		}
		if settings.provider == ApplicationAuthProviderOIDC {
			oidc = newOIDCAuthenticator(settings, []byte(stateKey))
		} else {
			saml = newSAMLAuthenticator(settings, []byte(stateKey))
		}
	case ApplicationAuthProviderEmail:
		// Like an identity provider, email never runs open: resolveApplicationAuthConfig
		// rejects an empty allowlist.
		allowAnySubject = false
		allowedSubjects = make(map[string]struct{}, len(settings.allowed))
		for _, principal := range settings.allowed {
			allowedSubjects[principal] = struct{}{}
		}
		email = newEmailAuthenticator(settings, publicURLs)
	}
	credentialKey, err := identity.DeriveToken(tunnelIdentity, applicationCredentialKeyUse)
	if err != nil {
		return nil, fmt.Errorf("derive application credential key: %w", err)
	}
	return &applicationAuth{
		next:            next,
		provider:        settings.provider,
		tunnelIdentity:  tunnelIdentity,
		signingKey:      []byte(signingKey),
		credentialKey:   []byte(credentialKey),
		siwe:            siwe,
		oidc:            oidc,
		saml:            saml,
		email:           email,
		allowedSubjects: allowedSubjects,
		allowAnySubject: allowAnySubject,
		identityHeaders: cfg.IdentityHeaders,
		identityProof:   settings.identityProof,
	}, nil
}

// CheckApplicationAuthProvider fetches what the first login needs, the OIDC
// discovery document and signing keys or the SAML metadata, or signs in to the
// SMTP server without sending, so that a wrong issuer, metadata source, SMTP
// setting or an unreachable provider shows when the tunnel starts instead of to
// the first visitor who tries to sign in. The email check matters most, because
// a visitor is never told that a mail could not be sent. Other providers depend
// on nothing outside the tunnel.
func CheckApplicationAuthProvider(ctx context.Context, cfg ApplicationAuthConfig) error {
	settings, err := resolveApplicationAuthConfig(cfg)
	if err != nil {
		return err
	}
	switch settings.provider {
	case ApplicationAuthProviderOIDC:
		o := newOIDCAuthenticator(settings, nil)
		// The keys are fetched through the discovery document.
		_, err = o.jwks.get(ctx, providerMetadataCacheTTL, o.fetchJWKS)
	case ApplicationAuthProviderSAML:
		_, err = newSAMLAuthenticator(settings, nil).identityProvider(ctx)
	case ApplicationAuthProviderEmail:
		err = newEmailAuthenticator(settings, nil).check(ctx)
	}
	return err
}

func (a *applicationAuth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	credential := strings.TrimSpace(r.Header.Get(types.HeaderAccessCredential))
	utils.DelHeaderSpellings(r.Header, types.HeaderAccessCredential)
	utils.DelHeaderSpellings(r.Header, types.PortalIdentityHeaders...)

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
	case applicationAuthSAMLACSPath:
		a.serveSAMLACS(w, r)
	case applicationAuthSAMLMetadataPath:
		a.serveSAMLMetadata(w, r)
	case applicationAuthEmailRequestPath:
		a.serveEmailRequest(w, r)
	case applicationAuthEmailRedeemPath:
		a.serveEmailRedeem(w, r)
	case applicationAuthLogoutPath:
		a.serveLogout(w, r)
	default:
		subject, provider, ok := a.authenticate(r, credential)
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
			r.Header.Set(types.HeaderPortalUser, subject)
			r.Header.Set(types.HeaderPortalAuth, provider)
			if a.identityProof != "" {
				r.Header.Set(types.HeaderPortalProof, a.identityProof)
			}
		}
		a.next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalContextKey{}, Principal{Provider: provider, Subject: subject})))
	}
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
	if a.provider == ApplicationAuthProviderOIDC && a.oidc != nil {
		a.oidc.serveLogin(w, r)
		return
	}
	if a.provider == ApplicationAuthProviderSAML && a.saml != nil {
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
	case ApplicationAuthProviderCredential:
		page = signinCredentialPage
	case ApplicationAuthProviderEmail:
		page = signinEmailPage
	}
	writeSigninPage(w, page, r.Host)
}

// accountChooserPrompt is the prompt value that asks the provider to show its
// account chooser. Only the retry on the not-allowed page sends it.
const accountChooserPrompt = "select_account"

func (o *oidcAuthenticator) serveLogin(w http.ResponseWriter, r *http.Request) {
	// A login keeps its state in one cookie, so a request that never completes
	// the login, like a HEAD probe, must not overwrite the state of one in progress.
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
	host, err := NormalizeApplicationAuthHost(r.Host)
	if err != nil {
		http.Error(w, "invalid request host", http.StatusBadRequest)
		return
	}
	state := rand.Text()
	nonce := rand.Text()
	codeVerifier := oauth2.GenerateVerifier()
	now := time.Now().UTC()
	expiresAt := now.Add(applicationAuthLoginStateTTL)
	next := sanitizeApplicationAuthNext(r.URL.Query().Get("next"))

	stateClaims := oidcStateClaims{
		State:        state,
		Nonce:        nonce,
		CodeVerifier: codeVerifier,
		Host:         host,
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

	oauthCfg := o.oauth2Config(doc, host)
	authOptions := []oauth2.AuthCodeOption{
		oauth2.S256ChallengeOption(codeVerifier),
		oauth2.SetAuthURLParam("nonce", nonce),
	}
	// A browser still signed in to the refused account is let straight back in
	// unless asked otherwise. Any other prompt value a caller sends is not passed on.
	if r.URL.Query().Get("prompt") == accountChooserPrompt {
		authOptions = append(authOptions, oauth2.SetAuthURLParam("prompt", accountChooserPrompt))
	}
	authURL := oauthCfg.AuthCodeURL(state, authOptions...)
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, authURL, http.StatusSeeOther)
}

func (a *applicationAuth) serveOIDCCallback(w http.ResponseWriter, r *http.Request) {
	if a.provider != ApplicationAuthProviderOIDC || a.oidc == nil {
		a.writeJSONError(w, http.StatusNotFound, "not found")
		return
	}
	// A login that ends without a session shows a browser what happened and
	// keeps the JSON error and status for every other caller.
	fail := func(message, page, next string, fields ...string) {
		if acceptsHTML(r) {
			writeSigninFailurePage(w, r, http.StatusUnauthorized, page, urlHost(a.oidc.issuerURL), next, fields...)
			return
		}
		a.writeJSONError(w, http.StatusUnauthorized, message)
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
		fail("missing oidc login state", signinProviderExpiredPage, "/")
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
		!sameApplicationHost(stateClaims.Host, host) ||
		now.Unix() >= stateClaims.ExpiresAt {
		// Only a state that verified carries a target worth keeping.
		next := "/"
		if err == nil {
			next = stateClaims.Next
		}
		fail("invalid or expired oidc login state", signinProviderExpiredPage, next)
		return
	}
	if errParam := strings.TrimSpace(r.URL.Query().Get("error")); errParam != "" {
		// access_denied is how a provider reports that the visitor declined,
		// and also how some report an account without access to the client.
		page := signinProviderFailedPage
		if errParam == "access_denied" {
			page = signinProviderCanceledPage
		}
		fail("oidc login failed", page, stateClaims.Next)
		return
	}
	queryState := strings.TrimSpace(r.URL.Query().Get("state"))
	code := strings.TrimSpace(r.URL.Query().Get("code"))
	if queryState == "" || code == "" || subtle.ConstantTimeCompare([]byte(queryState), []byte(stateClaims.State)) != 1 {
		fail("invalid oidc callback state", signinProviderExpiredPage, stateClaims.Next)
		return
	}

	claims, err := a.oidc.exchangeAndVerify(r.Context(), code, stateClaims, now)
	if err != nil {
		fail("oidc token verification failed", signinProviderFailedPage, stateClaims.Next)
		return
	}

	email := claims.vouchedEmail()
	subject, ok := a.resolveAllowedPrincipal(email, claims.Subject)
	if !ok {
		fail("oidc principal is not allowed", signinProviderDeniedPage, stateClaims.Next, "@@ACCOUNT@@", providerAccount(email, claims.Subject))
		return
	}

	// The session follows the ID token's lifetime, within providerMinSessionTTL and
	// applicationAuthSessionTTL: a token already inside the verification leeway
	// would otherwise give a session that is invalid on arrival, and the visitor
	// would loop through the provider. The allowlist is checked on every request,
	// so revoking a principal does not wait for the session to end.
	lifetime := min(max(claims.Expiry.Time().Sub(now), providerMinSessionTTL), applicationAuthSessionTTL)
	if err := a.setSession(w, subject, ApplicationAuthProviderOIDC, strings.TrimSpace(r.Host), now, now.Add(lifetime)); err != nil {
		a.writeJSONError(w, http.StatusInternalServerError, "could not create session")
		return
	}
	http.Redirect(w, r, sanitizeApplicationAuthNext(stateClaims.Next), http.StatusSeeOther)
}

// writeSigninFailurePage shows a browser why its OIDC or SAML login ended
// without a session. issuer names the identity provider, and the retry link
// starts a new login that returns the visitor to next.
func writeSigninFailurePage(w http.ResponseWriter, r *http.Request, status int, page, issuer, next string, fields ...string) {
	query := url.Values{}
	if next = sanitizeApplicationAuthNext(next); next != "/" {
		query.Set("next", next)
	}
	// The refused account's retry asks the provider for its account chooser
	if page == signinProviderDeniedPage {
		query.Set("prompt", accountChooserPrompt)
	}
	retry := applicationAuthLoginPath
	if len(query) > 0 {
		retry += "?" + query.Encode()
	}
	setSigninHeaders(w.Header())
	w.WriteHeader(status)
	writeSigninPage(w, page, r.Host, append([]string{"@@ISSUER@@", issuer, "@@RETRY@@", retry}, fields...)...)
}

// urlHost is the host of an identity provider URL, the name its failure
// screens show, or raw itself when it has none.
func urlHost(raw string) string {
	if parsed, err := url.Parse(raw); err == nil && parsed.Host != "" {
		return parsed.Host
	}
	return raw
}

// acceptsHTML reports whether the request is a browser navigation, the only
// kind of request that asks for HTML.
func acceptsHTML(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

// providerEmail normalizes an email the identity provider vouches for, or
// returns "" when raw is not one. An email shaped like a sub: entry would
// satisfy that entry through the exact lookup; it is not an email address.
func providerEmail(raw string) string {
	email := providerClaimPrincipal(raw)
	if !strings.Contains(email, "@") || strings.HasPrefix(email, subjectPrincipalPrefix) {
		return ""
	}
	return email
}

// providerAccount names the account the provider signed in, in the form an
// allowlist entry for it takes: the email when the provider vouches for one,
// and the sub: entry otherwise. It never reveals what the allowlist holds.
func providerAccount(email, subject string) string {
	if email := providerEmail(email); email != "" {
		return email
	}
	return subjectPrincipalPrefix + subject
}

// resolveAllowedPrincipal maps what an identity provider asserted to the
// session subject. email is an address the provider vouches for, or "" when
// it vouches for none: the verified email claim of OIDC, or the SAML subject
// value. Only such an email can match an email or @domain allowlist entry; the
// provider's opaque subject matches only an explicit `sub:` allowlist entry,
// so an email-shaped subject never satisfies an email entry by itself. A
// sub-matched session subject keeps the sub: prefix so the two principal
// types stay unambiguous on session revalidation and identity headers.
func (a *applicationAuth) resolveAllowedPrincipal(email, subject string) (string, bool) {
	if email := providerEmail(email); email != "" && a.subjectAllowed(email) {
		return email, true
	}
	// Reject noncanonical subjects instead of trimming an opaque identifier
	// into a different account's allowlisted subject.
	if subject != strings.TrimSpace(subject) {
		return "", false
	}
	// Prefixing the raw subject keeps it in the sub: namespace whatever it holds.
	sub, err := normalizeProviderPrincipal(subjectPrincipalPrefix + subject)
	if err == nil && a.subjectAllowed(sub) {
		return sub, true
	}
	return "", false
}

func (o *oidcAuthenticator) oauth2Config(doc oidcDiscoveryDocument, host string) oauth2.Config {
	// The auth style is named because the oauth2 default probes: it sends the
	// one-time authorization code with the credentials in the Authorization
	// header and, on any error, sends the same code again with them in the body.
	authStyle := oauth2.AuthStyleInHeader // client_secret_basic, the OIDC default
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
		RedirectURL:  "https://" + host + applicationAuthCallbackPath,
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
	// Load the keys before the exchange so an unreachable JWKS does not burn
	// the one-time authorization code.
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
	// Only a key error can be fixed by new keys: the provider may have rotated
	// since the cached set was fetched. The cache serves the same set again
	// when it was fetched less than oidcJWKSRefreshInterval ago.
	jwks, refreshErr := o.jwks.get(ctx, oidcJWKSRefreshInterval, o.fetchJWKS)
	if refreshErr != nil {
		return oidcIDTokenClaims{}, err
	}
	return o.verifyIDToken(rawIDToken, state.Nonce, doc.Issuer, jwks, now)
}

func (o *oidcAuthenticator) verifyIDToken(rawToken, expectedNonce, issuer string, jwks jose.JSONWebKeySet, now time.Time) (oidcIDTokenClaims, error) {
	parsed, err := jwt.ParseSigned(strings.TrimSpace(rawToken), oidcSupportedSignatureAlgorithms)
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

// oidcVerificationKey selects what a token is verified against. go-jose finds
// a key in a set by the token's kid and refuses a token without one, even when
// the set holds a single key. A provider that signs with one key may omit the
// kid, so that key, when it is a signing key, is used directly.
func oidcVerificationKey(headers []jose.Header, jwks *jose.JSONWebKeySet) any {
	if len(headers) != 1 || headers[0].KeyID != "" || len(jwks.Keys) != 1 {
		return jwks
	}
	if use := jwks.Keys[0].Use; use != "" && use != "sig" {
		return jwks
	}
	return jwks.Keys[0]
}

// get returns the cached value while it is younger than maxAge and otherwise
// refreshes it. Concurrent callers join one shared fetch instead of queueing
// behind a lock or fetching again, and each stops waiting when its own ctx
// ends. The fetch is detached from the first caller's cancellation so one
// abandoned login does not fail the others; the HTTP client timeout bounds it.
func (c *providerCache[T]) get(ctx context.Context, maxAge time.Duration, fetch func(context.Context) (T, error)) (T, error) {
	if value, ok := c.fresh(maxAge); ok {
		return value, nil
	}
	result := c.flight.DoChan("", func() (any, error) {
		// A caller can join just after the previous fetch finished.
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

// discoveryDocument is all that starting a login needs. The signing keys are
// fetched separately, and only to verify a token.
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
	if err := decodeSignedApplicationAuthJSON(a.signingKey, cookie.Value, &claims); err != nil || !sameApplicationHost(claims.Host, r.Host) || time.Now().UTC().Unix() >= claims.ExpiresAt {
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
	switch provider {
	case ApplicationAuthProviderOIDC, ApplicationAuthProviderSAML, ApplicationAuthProviderEmail:
		if binding := a.binding(); binding == "" || claims.Binding != binding {
			return "", "", false
		}
		subject, err = normalizeProviderPrincipal(claims.Subject)
	default:
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
	if a.provider != ApplicationAuthProviderOIDC && a.provider != ApplicationAuthProviderSAML && a.provider != ApplicationAuthProviderEmail {
		return false
	}
	// A `sub:` session subject is an opaque subject principal: it matches only
	// an explicit `sub:` allowlist entry (the exact lookup above), never an
	// email or @domain entry.
	if strings.HasPrefix(subject, "sub:") {
		return false
	}
	// An "@example.com" entry authorizes exactly that email domain, never its
	// subdomains. Login only passes an email the provider vouches for here, or
	// for email the address a link is about to be mailed to, and sessions only
	// carry subjects issued after that check.
	if _, domain, ok := strings.Cut(subject, "@"); ok && !strings.Contains(domain, "@") {
		_, ok = a.allowedSubjects["@"+domain]
		return ok
	}
	return false
}

func (a *applicationAuth) issueSession(subject, provider, host string, expiresAt time.Time) (string, error) {
	claims := applicationAuthClaims{Subject: subject, Provider: provider, Host: host, ExpiresAt: expiresAt.Unix(), Binding: a.binding()}
	return encodeSignedApplicationAuthJSON(a.signingKey, claims)
}

// binding is what every session of an identity provider or of email carries:
// the digest of the OIDC issuer and client, of the SAML settings, or of the SMTP
// account and sender. Other providers have none.
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

// encodeApplicationAuthLoginState signs the state of an OIDC or SAML login in
// progress for its cookie. A deep link too long for the cookie would fail the
// login when the visitor returns, so next, the target inside claims, becomes /.
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

// crossOriginWrite reports a protocol upgrade or an unsafe method that a browser
// sent from a page of another origin. A session is for the application's own
// origin, so the gate refuses both. A request without Origin does not come from
// such a page: browsers send Origin on both kinds. Sec-Fetch-Site settles the one
// same-origin request whose Origin is null, a form post from a page with
// Referrer-Policy: no-referrer. A page cannot set that header itself.
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
