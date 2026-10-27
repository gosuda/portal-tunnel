package gateway

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
	"unicode"

	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/siweauth"
	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/types"
)

const (
	ApplicationAuthProviderSIWE       = "siwe"
	ApplicationAuthProviderCredential = "credential"
	ApplicationAuthProviderOIDC       = "oidc"

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
	default:
		return "", fmt.Errorf("unsupported application auth provider %q", provider)
	}
}

// applicationAuthSettings is an ApplicationAuthConfig after validation and
// normalization. ValidateApplicationAuthConfig and NewApplicationAuth both get
// it from resolveApplicationAuthConfig, so what validation accepts is exactly
// what the gate is built from. It holds the identity proof and the OIDC client
// secret, so it must not be formatted or logged.
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
}

// ValidateApplicationAuthConfig validates the complete tunnel-local
// application authentication configuration, including provider-specific OIDC
// fields and principal allowlists.
func ValidateApplicationAuthConfig(cfg ApplicationAuthConfig) error {
	_, err := resolveApplicationAuthConfig(cfg)
	return err
}

// minIdentityProofLength keeps the proof from being guessed by a local process.
const minIdentityProofLength = 16

// resolveApplicationAuthConfig is the one place that validates and normalizes
// the provider, the allowlist, the identity proof and the OIDC settings.
func resolveApplicationAuthConfig(cfg ApplicationAuthConfig) (applicationAuthSettings, error) {
	provider, err := NormalizeApplicationAuthProvider(cfg.Provider)
	if err != nil {
		return applicationAuthSettings{}, err
	}
	allowed, err := NormalizeApplicationAuthAllowed(provider, cfg.AllowedWallets)
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
			return applicationAuthSettings{}, errors.New("identity proof (--auth-identity-proof / AUTH_IDENTITY_PROOF) requires --auth-identity-headers")
		}
		if len(proof) < minIdentityProofLength || strings.ContainsFunc(proof, func(r rune) bool { return r < 0x21 || r > 0x7e }) {
			return applicationAuthSettings{}, fmt.Errorf("identity proof (--auth-identity-proof / AUTH_IDENTITY_PROOF) must be at least %d characters of visible ASCII without spaces", minIdentityProofLength)
		}
	}
	issuer := strings.TrimSpace(cfg.OIDCIssuerURL)
	clientID := strings.TrimSpace(cfg.OIDCClientID)
	clientSecret := strings.TrimSpace(cfg.OIDCClientSecret)
	if provider != ApplicationAuthProviderOIDC {
		if issuer != "" || clientID != "" || clientSecret != "" {
			return applicationAuthSettings{}, errors.New("oidc settings require the oidc application auth provider")
		}
		return applicationAuthSettings{provider: provider, allowed: allowed, identityProof: proof}, nil
	}
	// An identity provider authenticates accounts it does not restrict to
	// this application, so without an allowlist every one of them would pass.
	if len(allowed) == 0 {
		return applicationAuthSettings{}, errors.New("oidc requires at least one --auth-allow entry: an email address, an @domain, or sub:<subject>")
	}
	issuerURL, err := normalizeOIDCIssuerURL(issuer)
	if err != nil {
		return applicationAuthSettings{}, err
	}
	if clientID == "" {
		return applicationAuthSettings{}, errors.New("oidc client id is required")
	}
	return applicationAuthSettings{provider: provider, allowed: allowed, identityProof: proof, issuerURL: issuerURL, clientID: clientID, clientSecret: clientSecret}, nil
}

// NormalizeApplicationAuthAllowed validates and normalizes the provider-scoped
// principal allowlist (`--auth-allow` / `auth_allowed_wallets`): Ethereum
// addresses for `siwe`, credential subjects for `credential`, and emails or
// subjects for `oidc`.
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
	case ApplicationAuthProviderOIDC:
		return NormalizeApplicationAuthOIDCPrincipals(values)
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
		return "", errors.New("tunnel identity is required")
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
		return "", errors.New("application credential expiry must be in the future")
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
		return "", errors.New("application credential is required")
	}
	return "https://" + host + applicationAuthLoginPath + "#credential=" + url.QueryEscape(credential), nil
}

// NormalizeApplicationAuthHost returns the canonical name of an application: lower
// case, without a trailing dot and without the default HTTPS port, which a browser
// leaves out of Host while an operator or a Go client may write it.
func NormalizeApplicationAuthHost(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("application auth host is required")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", errors.New("application auth host must be an HTTPS URL or hostname without a path")
	}
	validAuthority := strings.EqualFold(parsed.Scheme, "https") && parsed.Host != "" && parsed.User == nil
	rootPath := parsed.Path == "" || parsed.Path == "/"
	if !validAuthority || !rootPath || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("application auth host must be an HTTPS URL or hostname without a path")
	}
	host := strings.TrimSuffix(strings.ToLower(parsed.Host), ":443")
	return strings.TrimSuffix(host, "."), nil
}

func verifyApplicationCredential(key []byte, tunnelIdentity types.Identity, host, credential string, now time.Time) (applicationCredentialClaims, error) {
	credential = strings.TrimSpace(credential)
	if !strings.HasPrefix(credential, applicationCredentialPrefix) {
		return applicationCredentialClaims{}, errors.New("application credential is invalid")
	}
	var claims applicationCredentialClaims
	if err := decodeSignedApplicationAuthJSON(key, strings.TrimPrefix(credential, applicationCredentialPrefix), &claims); err != nil || claims.Version != applicationCredentialVersion || claims.Tunnel != tunnelIdentity.Key() {
		return applicationCredentialClaims{}, errors.New("application credential is invalid")
	}
	// A credential issued before the default port was dropped from the name still
	// carries it, and names the same application.
	normalizedHost, err := NormalizeApplicationAuthHost(host)
	claimedHost, claimedErr := NormalizeApplicationAuthHost(claims.Host)
	if err != nil || claimedErr != nil || claimedHost != normalizedHost || !now.UTC().Before(time.Unix(claims.ExpiresAt, 0)) {
		return applicationCredentialClaims{}, errors.New("application credential is invalid or expired")
	}
	claims.Subject, err = normalizeApplicationAuthSubject(claims.Subject)
	if err != nil {
		return applicationCredentialClaims{}, errors.New("application credential is invalid")
	}
	return claims, nil
}

func normalizeApplicationAuthSubject(subject string) (string, error) {
	subject = strings.TrimSpace(subject)
	if subject == "" || len(subject) > 256 || strings.ContainsFunc(subject, unicode.IsControl) {
		return "", errors.New("application credential subject must be 1 to 256 printable characters")
	}
	return subject, nil
}
