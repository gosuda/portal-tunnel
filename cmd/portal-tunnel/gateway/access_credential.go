package gateway

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
	"unicode"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/types"
)

const (
	ApplicationAuthProviderSIWE  = "siwe"
	ApplicationAuthProviderToken = "token"

	applicationCredentialPrefix  = "pat_"
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
	case "", ApplicationAuthProviderSIWE:
		return ApplicationAuthProviderSIWE, nil
	case ApplicationAuthProviderToken:
		return ApplicationAuthProviderToken, nil
	default:
		return "", fmt.Errorf("unsupported application auth provider %q", provider)
	}
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
	payload, err := json.Marshal(applicationCredentialClaims{
		Version:   applicationCredentialVersion,
		Subject:   subject,
		Tunnel:    tunnelIdentity.Key(),
		Host:      host,
		ExpiresAt: expiresAt.UTC().Unix(),
	})
	if err != nil {
		return "", err
	}
	return applicationCredentialPrefix + base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(signApplicationCredential([]byte(key), payload)), nil
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

func NormalizeApplicationAuthHost(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("application auth host is required")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	parsed, err := url.Parse(raw)
	if err != nil || !strings.EqualFold(parsed.Scheme, "https") || parsed.Host == "" || parsed.User != nil || (parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("application auth host must be an HTTPS URL or hostname without a path")
	}
	return strings.ToLower(strings.TrimSuffix(parsed.Host, ".")), nil
}

func verifyApplicationCredential(key []byte, tunnelIdentity types.Identity, host, credential string, now time.Time) (applicationCredentialClaims, error) {
	credential = strings.TrimSpace(credential)
	if !strings.HasPrefix(credential, applicationCredentialPrefix) {
		return applicationCredentialClaims{}, errors.New("application credential is invalid")
	}
	parts := strings.Split(strings.TrimPrefix(credential, applicationCredentialPrefix), ".")
	if len(parts) != 2 {
		return applicationCredentialClaims{}, errors.New("application credential is invalid")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return applicationCredentialClaims{}, errors.New("application credential is invalid")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || !hmac.Equal(signature, signApplicationCredential(key, payload)) {
		return applicationCredentialClaims{}, errors.New("application credential is invalid")
	}
	var claims applicationCredentialClaims
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Version != applicationCredentialVersion || claims.Tunnel != tunnelIdentity.Key() {
		return applicationCredentialClaims{}, errors.New("application credential is invalid")
	}
	normalizedHost, err := NormalizeApplicationAuthHost(host)
	if err != nil || !strings.EqualFold(claims.Host, normalizedHost) || !now.UTC().Before(time.Unix(claims.ExpiresAt, 0)) {
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

func signApplicationCredential(key, payload []byte) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(payload)
	return mac.Sum(nil)
}
