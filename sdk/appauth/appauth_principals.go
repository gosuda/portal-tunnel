// Package appauth is the application sign-in gate: an http.Handler that signs
// visitors in with a wallet, an access credential, OpenID Connect, SAML, or an
// email link, and passes only signed-in requests to the application behind it.
package appauth

import (
	"context"
	"fmt"
	"strings"
	"time"
	"unicode"
)

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
