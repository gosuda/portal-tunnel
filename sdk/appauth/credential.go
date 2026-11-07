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
	ProviderSIWE       = "siwe"
	ProviderCredential = "credential"
	ProviderOIDC       = "oidc"
	ProviderSAML       = "saml"
	ProviderEmail      = "email"

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

func normalizeProvider(provider string) (string, error) {
	provider = strings.ToLower(strings.TrimSpace(provider))
	switch provider {
	case ProviderSIWE:
		return ProviderSIWE, nil
	case ProviderCredential:
		return ProviderCredential, nil
	case ProviderOIDC:
		return ProviderOIDC, nil
	case ProviderSAML:
		return ProviderSAML, nil
	case ProviderEmail:
		return ProviderEmail, nil
	default:
		return "", fmt.Errorf("unsupported application auth provider %q", provider)
	}
}

// applicationAuthSettings is a Config after validation and
// normalization. Validate and New both get
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

// Validate checks the complete configuration of a gate, including the
// provider-specific OIDC, SAML and email settings and the allowlist. New runs the
// same checks and also needs what a config file does not hold: the identity and,
// for email, PublicHosts.
func Validate(cfg Config) error {
	_, err := resolveApplicationAuthConfig(cfg)
	return err
}

// minIdentityProofLength keeps the proof from being guessed by a local process.
const minIdentityProofLength = 16

// resolveApplicationAuthConfig is the one place that validates and normalizes
// the provider, the allowlist, the identity proof and the OIDC, SAML and email
// settings.
func resolveApplicationAuthConfig(cfg Config) (applicationAuthSettings, error) {
	provider, err := normalizeProvider(cfg.Provider)
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
	if hasOIDCSettings && provider != ProviderOIDC {
		return applicationAuthSettings{}, errOIDCSettingsRequireOIDCApplicationAuth
	}
	if hasSAMLSettings && provider != ProviderSAML {
		return applicationAuthSettings{}, errSAMLSettingsRequireSAMLApplicationAuth
	}
	if hasEmailSettings && provider != ProviderEmail {
		return applicationAuthSettings{}, errEmailSettingsRequireEmailApplicationAuth
	}
	settings := applicationAuthSettings{provider: provider, allowed: allowed, identityProof: proof}
	switch provider {
	case ProviderOIDC:
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
	case ProviderSAML:
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
	case ProviderEmail:
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

// ProviderTakesEmailList reports whether provider names a visitor
// by email, so that it reads `--auth-email-list` / `auth_email_list`.
func ProviderTakesEmailList(provider string) bool {
	switch provider {
	case ProviderOIDC, ProviderSAML, ProviderEmail:
		return true
	default:
		return false
	}
}

// resolveAllowlist reads the allowlist of provider from the key that may hold
// it. oidc and saml take both keys, because released configs hold the list under
// `--auth-allow`; email was never released with it, so it takes only the one.
func resolveAllowlist(provider string, cfg Config) ([]string, error) {
	switch {
	case len(cfg.EmailList) > 0 && len(cfg.Allow) > 0:
		return nil, errAllowlistIsSetTwice
	case len(cfg.EmailList) > 0 && !ProviderTakesEmailList(provider):
		return nil, errEmailListRequiresEmailProvider
	case len(cfg.Allow) > 0 && provider == ProviderEmail:
		return nil, errEmailProviderTakesEmailList
	}
	return normalizeAllowed(provider, cfg.Allowed())
}

// normalizeAllowed validates and normalizes the provider-scoped
// principal allowlist (`--auth-allow` / `auth_allowed_wallets`, or
// `--auth-email-list` / `auth_email_list`): Ethereum
// addresses for `siwe`, credential subjects for `credential`, emails or
// subjects for `oidc` and `saml`, and emails for `email`. The email provider
// knows no subject but the address, so it refuses `sub:` entries.
func normalizeAllowed(provider string, values []string) ([]string, error) {
	provider, err := normalizeProvider(provider)
	if err != nil {
		return nil, err
	}
	switch provider {
	case ProviderSIWE:
		return siweauth.NormalizeAddresses(values)
	case ProviderCredential:
		return normalizeSubjects(values)
	case ProviderOIDC, ProviderSAML:
		return normalizeProviderPrincipals(values)
	case ProviderEmail:
		allowed, err := normalizeProviderPrincipals(values)
		if err != nil {
			return nil, err
		}
		for _, principal := range allowed {
			if strings.HasPrefix(principal, subjectPrincipalPrefix) {
				return nil, errEmailAllowsNoSubjectEntries
			}
			// An entry no visitor can sign in with would fail in silence, so it
			// fails at the start. A domain is tried with the shortest local part.
			address := principal
			if strings.HasPrefix(principal, "@") {
				address = "a" + principal
			}
			if _, err := normalizeVisitorEmail(address); err != nil {
				return nil, fmt.Errorf("principal %q: %w", principal, err)
			}
		}
		return allowed, nil
	default:
		return nil, fmt.Errorf("unsupported application auth provider %q", provider)
	}
}

// normalizeSubjects canonicalizes configured credential subjects
// and de-duplicates them while preserving declaration order.
func normalizeSubjects(values []string) ([]string, error) {
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

// IssueCredential creates a credential for one host and one identity. A gate
// built from that identity accepts it in a request header and exchanges it for a
// session.
func IssueCredential(id types.Identity, host, subject string, expiresAt time.Time) (string, error) {
	if id.Key() == "" {
		return "", errTunnelIdentityIsRequired
	}
	host, err := normalizeHost(host)
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
	key, err := identity.DeriveToken(id, applicationCredentialKeyUse)
	if err != nil {
		return "", fmt.Errorf("derive application credential key: %w", err)
	}
	token, err := encodeSignedApplicationAuthJSON([]byte(key), applicationCredentialClaims{
		Version:   applicationCredentialVersion,
		Subject:   subject,
		Tunnel:    id.Key(),
		Host:      host,
		ExpiresAt: expiresAt.UTC().Unix(),
	})
	if err != nil {
		return "", err
	}
	return applicationCredentialPrefix + token, nil
}

// CredentialRedeemURL returns the sign-in link of a credential. The credential
// travels in the fragment, so it reaches neither a relay nor a server log.
func CredentialRedeemURL(host, credential string) (string, error) {
	host, err := normalizeHost(host)
	if err != nil {
		return "", err
	}
	credential = strings.TrimSpace(credential)
	if credential == "" {
		return "", errApplicationCredentialIsRequired
	}
	return "https://" + host + applicationAuthLoginPath + "#credential=" + url.QueryEscape(credential), nil
}

// normalizeHost returns the canonical name of an application: lower
// case, without a trailing dot and without the default HTTPS port, which a browser
// leaves out of Host while an operator or a Go client may write it.
func normalizeHost(raw string) (string, error) {
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
// normalize names nothing, and neither does a URL: normalizeHost
// also reads https://host/, but a Host header or a stored host never has a slash
// (net/http answers such a header with 400).
func sameApplicationHost(a, b string) bool {
	if strings.Contains(a, "/") || strings.Contains(b, "/") {
		return false
	}
	normalizedA, errA := normalizeHost(a)
	normalizedB, errB := normalizeHost(b)
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
