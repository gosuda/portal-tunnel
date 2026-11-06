package appauth

import (
	"errors"
	"fmt"
	"net/mail"
	"net/url"
	"strings"
	"time"
	"unicode"

	"github.com/gosuda/portal-tunnel/v2/internal/siweauth"
	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/types"
)

var (
	errIdentityProofAuthIdentityProofAuth       = errors.New("identity proof (--auth-identity-proof / AUTH_IDENTITY_PROOF) requires --auth-identity-headers")
	errOIDCSettingsRequireOIDCApplicationAuth   = errors.New("oidc settings require the oidc application auth provider")
	errOIDCRequiresEmailList                    = errors.New("oidc requires at least one --auth-email-list entry: an email address, an @domain, or sub:<subject>")
	errOIDCClientIDIsRequired                   = errors.New("oidc client id is required")
	errSAMLSettingsRequireSAMLApplicationAuth   = errors.New("saml settings require the saml application auth provider")
	errSAMLRequiresEmailList                    = errors.New("saml requires at least one --auth-email-list entry: an email address, an @domain, or sub:<subject>")
	errSAMLMetadataIsRequired                   = errors.New("saml requires identity provider metadata: --auth-saml-metadata-url or --auth-saml-metadata-file")
	errSAMLMetadataSourcesConflict              = errors.New("saml metadata comes from --auth-saml-metadata-url or --auth-saml-metadata-file, not both")
	errEmailSettingsRequireEmailApplicationAuth = errors.New("email settings require the email application auth provider")
	errEmailRequiresEmailList                   = errors.New("email requires at least one --auth-email-list entry: an email address or an @domain")
	errEmailListRequiresEmailProvider           = errors.New("--auth-email-list works with oidc, saml, and email; siwe and credential use --auth-allow")
	errEmailProviderTakesEmailList              = errors.New("email reads its addresses from --auth-email-list, not --auth-allow")
	errAllowlistIsSetTwice                      = errors.New("--auth-email-list and --auth-allow are the same list: set one")
	errEmailAllowsNoSubjectEntries              = errors.New("email allows email addresses and @domain entries only, not sub:<subject>")
	errSMTPAddrIsRequired                       = errors.New("email requires an SMTP server: --auth-smtp-addr host:port")
	errSMTPFromIsRequired                       = errors.New("email requires a sender address: --auth-smtp-from")
	errEmailSMTPCredentialsArePaired            = errors.New("email smtp username and password are set together or not at all")
	errTunnelIdentityIsRequired                 = errors.New("tunnel identity is required")
	errApplicationCredentialExpiryMustFuture    = errors.New("application credential expiry must be in the future")
	errApplicationCredentialIsRequired          = errors.New("application credential is required")
	errApplicationAuthHostIsRequired            = errors.New("application auth host is required")
	errApplicationAuthHostMustHTTPSURL          = errors.New("application auth host must be an HTTPS URL or hostname without a path")
	errApplicationCredentialIsInvalid           = errors.New("application credential is invalid")
	errApplicationCredentialInvalidOrExpired    = errors.New("application credential is invalid or expired")
	errApplicationCredentialSubjectMust1256     = errors.New("application credential subject must be 1 to 256 printable characters")
)

const (
	ApplicationAuthProviderSIWE       = "siwe"
	ApplicationAuthProviderCredential = "credential"
	ApplicationAuthProviderOIDC       = "oidc"
	ApplicationAuthProviderSAML       = "saml"
	ApplicationAuthProviderEmail      = "email"

	applicationCredentialPrefix  = "pcred_"
	applicationCredentialVersion = 1
	applicationCredentialKeyUse  = "application-access-credential"
)

type applicationCredentialClaims struct {
	Version   int    `json:"v"`
	Subject   string `json:"sub"`
	Tunnel    string `json:"tunnel"`
	Host      string `json:"host"`
	ExpiresAt int64  `json:"exp"`
}

func NormalizeApplicationAuthProvider(provider string) (string, error) {
	provider = strings.ToLower(strings.TrimSpace(provider))
	switch provider {
	case ApplicationAuthProviderSIWE:
		return ApplicationAuthProviderSIWE, nil
	case ApplicationAuthProviderCredential:
		return ApplicationAuthProviderCredential, nil
	case ApplicationAuthProviderOIDC:
		return ApplicationAuthProviderOIDC, nil
	case ApplicationAuthProviderSAML:
		return ApplicationAuthProviderSAML, nil
	case ApplicationAuthProviderEmail:
		return ApplicationAuthProviderEmail, nil
	default:
		return "", fmt.Errorf("unsupported application auth provider %q", provider)
	}
}

// applicationAuthSettings is an ApplicationAuthConfig after validation and
// normalization. ValidateApplicationAuthConfig and NewApplicationAuth both get
// it from resolveApplicationAuthConfig, so what validation accepts is exactly
// what the gate is built from. It holds the identity proof, the OIDC client
// secret and the SMTP password, so it must not be formatted or logged.
type applicationAuthSettings struct {
	provider string
	// allowed holds the normalized principals; empty means any valid principal.
	allowed []string
	// identityProof is set only together with the identity headers.
	identityProof string
	// The OIDC fields are set only for the oidc provider.
	issuerURL    string
	clientID     string
	clientSecret string
	// The SAML fields are set only for the saml provider, with exactly one of
	// the metadata sources. An empty entity ID or subject attribute takes its
	// default: the metadata URL of the host and the NameID.
	samlMetadataURL      string
	samlMetadataFile     string
	samlEntityID         string
	samlSubjectAttribute string
	// The email fields are set only for the email provider. The SMTP username
	// and password are both set or both empty.
	emailSMTPAddr     string
	emailSMTPUsername string
	emailSMTPPassword string
	emailFrom         mail.Address
}

// ValidateApplicationAuthConfig validates the complete tunnel-local
// application authentication configuration, including provider-specific OIDC,
// SAML and email fields and principal allowlists.
func ValidateApplicationAuthConfig(cfg ApplicationAuthConfig) error {
	_, err := resolveApplicationAuthConfig(cfg)
	return err
}

// minIdentityProofLength keeps the proof from being guessed by a local process.
const minIdentityProofLength = 16

// resolveApplicationAuthConfig is the one place that validates and normalizes
// the provider, the allowlist, the identity proof and the OIDC, SAML and email
// settings.
func resolveApplicationAuthConfig(cfg ApplicationAuthConfig) (applicationAuthSettings, error) {
	provider, err := NormalizeApplicationAuthProvider(cfg.Provider)
	if err != nil {
		return applicationAuthSettings{}, err
	}
	allowed, err := resolveAllowlist(provider, cfg)
	if err != nil {
		return applicationAuthSettings{}, err
	}
	// The proof is sent as a header value and is compared byte for byte by the
	// upstream, so it is not trimmed here (the environment reader already trims
	// the whitespace around AUTH_IDENTITY_PROOF) and only visible ASCII is
	// accepted. The errors name both sources of the value, the flag and the
	// environment variable, and never include the value itself.
	proof := cfg.IdentityProof
	if proof != "" {
		if !cfg.IdentityHeaders {
			return applicationAuthSettings{}, errIdentityProofAuthIdentityProofAuth
		}
		if len(proof) < minIdentityProofLength || strings.ContainsFunc(proof, func(r rune) bool { return r < 0x21 || r > 0x7e }) {
			return applicationAuthSettings{}, fmt.Errorf("identity proof (--auth-identity-proof / AUTH_IDENTITY_PROOF) must be at least %d characters of visible ASCII without spaces", minIdentityProofLength)
		}
	}
	issuer := strings.TrimSpace(cfg.OIDCIssuerURL)
	clientID := strings.TrimSpace(cfg.OIDCClientID)
	clientSecret := strings.TrimSpace(cfg.OIDCClientSecret)
	metadataURL := strings.TrimSpace(cfg.SAMLMetadataURL)
	metadataFile := strings.TrimSpace(cfg.SAMLMetadataFile)
	entityID := strings.TrimSpace(cfg.SAMLEntityID)
	subjectAttribute := strings.TrimSpace(cfg.SAMLSubjectAttribute)
	smtpAddr := strings.TrimSpace(cfg.SMTPAddr)
	smtpUsername := strings.TrimSpace(cfg.SMTPUsername)
	smtpPassword := strings.TrimSpace(cfg.SMTPPassword)
	from := strings.TrimSpace(cfg.SMTPFrom)
	hasOIDCSettings := issuer != "" || clientID != "" || clientSecret != ""
	hasSAMLSettings := metadataURL != "" || metadataFile != "" || entityID != "" || subjectAttribute != ""
	hasEmailSettings := smtpAddr != "" || smtpUsername != "" || smtpPassword != "" || from != ""
	if hasOIDCSettings && provider != ApplicationAuthProviderOIDC {
		return applicationAuthSettings{}, errOIDCSettingsRequireOIDCApplicationAuth
	}
	if hasSAMLSettings && provider != ApplicationAuthProviderSAML {
		return applicationAuthSettings{}, errSAMLSettingsRequireSAMLApplicationAuth
	}
	if hasEmailSettings && provider != ApplicationAuthProviderEmail {
		return applicationAuthSettings{}, errEmailSettingsRequireEmailApplicationAuth
	}
	settings := applicationAuthSettings{provider: provider, allowed: allowed, identityProof: proof}
	switch provider {
	case ApplicationAuthProviderOIDC:
		// An identity provider authenticates accounts it does not restrict to
		// this application, so without an allowlist every one of them would pass.
		if len(allowed) == 0 {
			return applicationAuthSettings{}, errOIDCRequiresEmailList
		}
		settings.issuerURL, err = normalizeOIDCIssuerURL(issuer)
		if err != nil {
			return applicationAuthSettings{}, err
		}
		if clientID == "" {
			return applicationAuthSettings{}, errOIDCClientIDIsRequired
		}
		settings.clientID, settings.clientSecret = clientID, clientSecret
	case ApplicationAuthProviderSAML:
		if len(allowed) == 0 {
			return applicationAuthSettings{}, errSAMLRequiresEmailList
		}
		switch {
		case metadataURL == "" && metadataFile == "":
			return applicationAuthSettings{}, errSAMLMetadataIsRequired
		case metadataURL != "" && metadataFile != "":
			return applicationAuthSettings{}, errSAMLMetadataSourcesConflict
		case metadataURL != "":
			if settings.samlMetadataURL, err = normalizeSAMLMetadataURL(metadataURL); err != nil {
				return applicationAuthSettings{}, err
			}
		default:
			settings.samlMetadataFile = metadataFile
		}
		if err := validateSAMLName("saml entity id", entityID, samlEntityIDLimit); err != nil {
			return applicationAuthSettings{}, err
		}
		if err := validateSAMLName("saml subject attribute", subjectAttribute, samlSubjectAttributeLimit); err != nil {
			return applicationAuthSettings{}, err
		}
		settings.samlEntityID, settings.samlSubjectAttribute = entityID, subjectAttribute
	case ApplicationAuthProviderEmail:
		// Without an allowlist, anyone could make the tunnel mail any address.
		if len(allowed) == 0 {
			return applicationAuthSettings{}, errEmailRequiresEmailList
		}
		if smtpAddr == "" {
			return applicationAuthSettings{}, errSMTPAddrIsRequired
		}
		if err := validateSMTPAddr(smtpAddr); err != nil {
			return applicationAuthSettings{}, err
		}
		if from == "" {
			return applicationAuthSettings{}, errSMTPFromIsRequired
		}
		if settings.emailFrom, err = parseSMTPFrom(from); err != nil {
			return applicationAuthSettings{}, err
		}
		if (smtpUsername == "") != (smtpPassword == "") {
			return applicationAuthSettings{}, errEmailSMTPCredentialsArePaired
		}
		settings.emailSMTPAddr, settings.emailSMTPUsername, settings.emailSMTPPassword = smtpAddr, smtpUsername, smtpPassword
	}
	return settings, nil
}

// ApplicationAuthProviderTakesEmailList reports whether provider names a visitor
// by email, so that it reads `--auth-email-list` / `auth_email_list`.
func ApplicationAuthProviderTakesEmailList(provider string) bool {
	switch provider {
	case ApplicationAuthProviderOIDC, ApplicationAuthProviderSAML, ApplicationAuthProviderEmail:
		return true
	default:
		return false
	}
}

// resolveAllowlist reads the allowlist of provider from the key that may hold
// it. oidc and saml take both keys, because released configs hold the list under
// `--auth-allow`; email was never released with it, so it takes only the one.
func resolveAllowlist(provider string, cfg ApplicationAuthConfig) ([]string, error) {
	switch {
	case len(cfg.EmailList) > 0 && len(cfg.AllowedWallets) > 0:
		return nil, errAllowlistIsSetTwice
	case len(cfg.EmailList) > 0 && !ApplicationAuthProviderTakesEmailList(provider):
		return nil, errEmailListRequiresEmailProvider
	case len(cfg.AllowedWallets) > 0 && provider == ApplicationAuthProviderEmail:
		return nil, errEmailProviderTakesEmailList
	}
	return NormalizeApplicationAuthAllowed(provider, cfg.Allowed())
}

// NormalizeApplicationAuthAllowed validates and normalizes the provider-scoped
// principal allowlist (`--auth-allow` / `auth_allowed_wallets`, or
// `--auth-email-list` / `auth_email_list`): Ethereum
// addresses for `siwe`, credential subjects for `credential`, emails or
// subjects for `oidc` and `saml`, and emails for `email`. The email provider
// knows no subject but the address, so it refuses `sub:` entries.
func NormalizeApplicationAuthAllowed(provider string, values []string) ([]string, error) {
	provider, err := NormalizeApplicationAuthProvider(provider)
	if err != nil {
		return nil, err
	}
	switch provider {
	case ApplicationAuthProviderSIWE:
		return siweauth.NormalizeAddresses(values)
	case ApplicationAuthProviderCredential:
		return NormalizeApplicationAuthSubjects(values)
	case ApplicationAuthProviderOIDC, ApplicationAuthProviderSAML:
		return NormalizeApplicationAuthProviderPrincipals(values)
	case ApplicationAuthProviderEmail:
		allowed, err := NormalizeApplicationAuthProviderPrincipals(values)
		if err != nil {
			return nil, err
		}
		for _, principal := range allowed {
			if strings.HasPrefix(principal, subjectPrincipalPrefix) {
				return nil, errEmailAllowsNoSubjectEntries
			}
			// An address no visitor can sign in with would fail in silence, so
			// it fails at the start.
			if !strings.HasPrefix(principal, "@") {
				if _, err := normalizeVisitorEmail(principal); err != nil {
					return nil, fmt.Errorf("principal %q: %w", principal, err)
				}
			}
		}
		return allowed, nil
	default:
		return nil, fmt.Errorf("unsupported application auth provider %q", provider)
	}
}

// NormalizeApplicationAuthSubjects canonicalizes configured credential subjects
// and de-duplicates them while preserving declaration order.
func NormalizeApplicationAuthSubjects(values []string) ([]string, error) {
	if len(values) == 0 {
		return nil, nil
	}
	normalized := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, raw := range values {
		subject, err := normalizeApplicationAuthSubject(raw)
		if err != nil {
			return nil, err
		}
		if _, ok := seen[subject]; ok {
			continue
		}
		seen[subject] = struct{}{}
		normalized = append(normalized, subject)
	}
	return normalized, nil
}

// IssueApplicationCredential creates a host- and tunnel-scoped credential that
// can be exchanged for the tunnel-local application session cookie.
func IssueApplicationCredential(tunnelIdentity types.Identity, host, subject string, expiresAt time.Time) (string, error) {
	if tunnelIdentity.Key() == "" {
		return "", errTunnelIdentityIsRequired
	}
	host, err := NormalizeApplicationAuthHost(host)
	if err != nil {
		return "", err
	}
	subject, err = normalizeApplicationAuthSubject(subject)
	if err != nil {
		return "", err
	}
	if expiresAt.UTC().Unix() <= time.Now().UTC().Unix() {
		return "", errApplicationCredentialExpiryMustFuture
	}
	key, err := identity.DeriveToken(tunnelIdentity, applicationCredentialKeyUse)
	if err != nil {
		return "", fmt.Errorf("derive application credential key: %w", err)
	}
	token, err := encodeSignedApplicationAuthJSON([]byte(key), applicationCredentialClaims{
		Version:   applicationCredentialVersion,
		Subject:   subject,
		Tunnel:    tunnelIdentity.Key(),
		Host:      host,
		ExpiresAt: expiresAt.UTC().Unix(),
	})
	if err != nil {
		return "", err
	}
	return applicationCredentialPrefix + token, nil
}

func ApplicationCredentialRedeemURL(host, credential string) (string, error) {
	host, err := NormalizeApplicationAuthHost(host)
	if err != nil {
		return "", err
	}
	credential = strings.TrimSpace(credential)
	if credential == "" {
		return "", errApplicationCredentialIsRequired
	}
	return "https://" + host + applicationAuthLoginPath + "#credential=" + url.QueryEscape(credential), nil
}

// NormalizeApplicationAuthHost returns the canonical name of an application: lower
// case, without a trailing dot and without the default HTTPS port, which a browser
// leaves out of Host while an operator or a Go client may write it.
func NormalizeApplicationAuthHost(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errApplicationAuthHostIsRequired
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("%w: %w", errApplicationAuthHostMustHTTPSURL, err)
	}
	validAuthority := strings.EqualFold(parsed.Scheme, "https") && parsed.Host != "" && parsed.User == nil
	rootPath := parsed.Path == "" || parsed.Path == "/"
	if !validAuthority || !rootPath || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errApplicationAuthHostMustHTTPSURL
	}
	host := strings.TrimSuffix(strings.ToLower(parsed.Host), ":443")
	return strings.TrimSuffix(host, "."), nil
}

// sameApplicationHost reports whether two hosts name the same application: they
// are equal once each is normalized, so letter case, a trailing dot and the
// default port :443 do not tell applications apart. A host that does not
// normalize names nothing, and neither does a URL: NormalizeApplicationAuthHost
// also reads https://host/, but a Host header or a stored host never has a slash
// (net/http answers such a header with 400).
func sameApplicationHost(a, b string) bool {
	if strings.Contains(a, "/") || strings.Contains(b, "/") {
		return false
	}
	normalizedA, errA := NormalizeApplicationAuthHost(a)
	normalizedB, errB := NormalizeApplicationAuthHost(b)
	return errA == nil && errB == nil && normalizedA == normalizedB
}

func verifyApplicationCredential(key []byte, tunnelIdentity types.Identity, host, credential string, now time.Time) (applicationCredentialClaims, error) {
	credential = strings.TrimSpace(credential)
	if !strings.HasPrefix(credential, applicationCredentialPrefix) {
		return applicationCredentialClaims{}, errApplicationCredentialIsInvalid
	}
	var claims applicationCredentialClaims
	if err := decodeSignedApplicationAuthJSON(key, strings.TrimPrefix(credential, applicationCredentialPrefix), &claims); err != nil || claims.Version != applicationCredentialVersion || claims.Tunnel != tunnelIdentity.Key() {
		return applicationCredentialClaims{}, errApplicationCredentialIsInvalid
	}
	// A credential issued before the default port was dropped from the name still
	// carries it, and names the same application.
	if !sameApplicationHost(claims.Host, host) || !now.UTC().Before(time.Unix(claims.ExpiresAt, 0)) {
		return applicationCredentialClaims{}, errApplicationCredentialInvalidOrExpired
	}
	subject, err := normalizeApplicationAuthSubject(claims.Subject)
	if err != nil {
		return applicationCredentialClaims{}, errApplicationCredentialIsInvalid
	}
	claims.Subject = subject
	return claims, nil
}

func normalizeApplicationAuthSubject(subject string) (string, error) {
	subject = strings.TrimSpace(subject)
	if subject == "" || len(subject) > 256 || strings.ContainsFunc(subject, unicode.IsControl) {
		return "", errApplicationCredentialSubjectMust1256
	}
	return subject, nil
}
