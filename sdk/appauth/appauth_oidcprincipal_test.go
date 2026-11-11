package appauth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
)

func TestApplicationAuthOIDCPrincipalMatching(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		allow  []string
		sub    string
		email  string
		status oidcEmailVerified
		want   string
	}{
		{"verified email exact", []string{"alice@example.com"}, "s1", "Alice@Example.com", true, "alice@example.com"},
		{"absent email_verified does not authorize email", []string{"alice@example.com"}, "s1", "alice@example.com", false, ""},
		{"false email_verified does not authorize email", []string{"alice@example.com"}, "s1", "alice@example.com", false, ""},
		{"sub allowlist ignores email_verified", []string{"sub:s1"}, "s1", "alice@example.com", false, "sub:s1"},
		{"subject with leading space cannot impersonate an allowed subject", []string{"sub:s1"}, " s1", "", false, ""},
		{"subject with trailing space cannot impersonate an allowed subject", []string{"sub:s1"}, "s1 ", "", false, ""},
		{"subject with surrounding Unicode space cannot impersonate an allowed subject", []string{"sub:s1"}, " s1 ", "", false, ""},
		{"email-shaped sub cannot satisfy an email entry", []string{"alice@example.com"}, "alice@example.com", "", false, ""},
		{"email-shaped sub cannot satisfy an email entry without email_verified", []string{"alice@example.com"}, "alice@example.com", "", false, ""},
		{"email-shaped sub matches a sub: entry", []string{"sub:alice@example.com"}, "alice@example.com", "", false, "sub:alice@example.com"},
		{"sub: entry matches the subject in exactly its case", []string{"sub:Alice@Example.com"}, "Alice@Example.com", "", false, "sub:Alice@Example.com"},
		{"sub: entry rejects a subject that differs only in case", []string{"sub:Alice@Example.com"}, "alice@example.com", "", false, ""},
		{"lowercase sub: entry rejects an uppercase subject", []string{"sub:alice@example.com"}, "Alice@Example.com", "", false, ""},
		{"sub: prefix case does not change the subject case", []string{"SUB:Alice@Example.com"}, "Alice@Example.com", "", false, "sub:Alice@Example.com"},
		{"non-ASCII sub matches only itself", []string{"sub:Kevin"}, "Kevin", "", false, "sub:Kevin"},
		{"ASCII sub: entry rejects a Kelvin-sign lookalike subject", []string{"sub:kevin"}, "Kevin", "", false, ""},
		{"Kelvin-sign email cannot stand in for an ASCII email", []string{"kevin@example.com"}, "s1", "Kevin@example.com", true, ""},
		{"dotted capital I domain cannot stand in for an ASCII domain", []string{"@github.com"}, "s1", "bob@gİthub.com", true, ""},
		{"verified email matches domain", []string{"@Example.com"}, "s1", "bob@example.com", true, "bob@example.com"},
		{"absent email_verified does not match domain", []string{"@example.com"}, "s1", "bob@example.com", false, ""},
		{"domain excludes subdomains", []string{"@example.com"}, "s1", "bob@sub.example.com", true, ""},
		{"domain excludes other domains", []string{"@example.com"}, "s1", "bob@example.org", true, ""},
		{"email-shaped sub never matches a domain", []string{"@example.com"}, "mallory@example.com", "", false, ""},
		{"sub cannot impersonate a domain entry", []string{"@example.com"}, "@example.com", "", false, ""},
		{"verified email claim cannot impersonate a sub: entry", []string{"sub:alice@example.com"}, "s9", "sub:alice@example.com", true, ""},
		{"verified email claim cannot impersonate a sub: entry in another case", []string{"sub:alice@example.com"}, "s9", "SUB:Alice@Example.com", true, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			checkPrincipalResolution(t, tt.allow, tt.sub, tt.email, tt.status, tt.want)
		})
	}

	t.Run("domain session remains valid", func(t *testing.T) {
		t.Parallel()
		checkDomainSessionSubject(t)
	})
	t.Run("sub session remains valid", func(t *testing.T) {
		t.Parallel()
		checkSubSessionSubjects(t)
	})
	t.Run("sub session cannot widen to a domain entry", func(t *testing.T) {
		t.Parallel()
		checkSubIgnoresDomain(t)
	})
	t.Run("credential subjects ignore domain entries", func(t *testing.T) {
		t.Parallel()
		checkCredentialIgnoresDomain(t)
	})
	t.Run("malformed domain entries are rejected", func(t *testing.T) {
		t.Parallel()
		rejectMalformedPrincipals(t)
	})
	t.Run("untyped or malformed entries are rejected", func(t *testing.T) {
		t.Parallel()
		rejectUntypedPrincipals(t)
	})
}

func newPrincipalGate(t *testing.T, provider string, allow ...string) *applicationAuth {
	t.Helper()
	cfg := Config{Provider: provider, Allow: allow}
	if provider == ProviderOIDC {
		cfg.OIDCIssuerURL = "https://idp.example"
		cfg.OIDCClientID = "portal-client"
	}
	handler, err := New(http.NotFoundHandler(), applicationAuthTestIdentity(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	return handler.(*applicationAuth)
}

func checkPrincipalResolution(t *testing.T, allow []string, sub, email string, status oidcEmailVerified, want string) {
	t.Helper()
	gate := newPrincipalGate(t, ProviderOIDC, allow...)
	claims := oidcIDTokenClaims{
		Claims:        jwt.Claims{Subject: sub},
		Email:         email,
		EmailVerified: status,
	}
	got, ok := gate.resolveAllowedPrincipal(claims.vouchedEmail(), claims.Subject)
	if got != want || ok != (want != "") {
		t.Fatalf("resolveAllowedPrincipal = (%q, %v); want %q", got, ok, want)
	}
}

func checkDomainSessionSubject(t *testing.T) {
	t.Helper()
	if !newPrincipalGate(t, ProviderOIDC, "@example.com").subjectAllowed("bob@example.com") {
		t.Fatal("domain-authorized subject rejected on session validation")
	}
}

func checkSubSessionSubjects(t *testing.T) {
	t.Helper()
	gate := newPrincipalGate(t, ProviderOIDC, "sub:alice@example.com")
	if !gate.subjectAllowed("sub:alice@example.com") {
		t.Fatal("sub:-authorized subject rejected on session validation")
	}
	if gate.subjectAllowed("sub:mallory@example.com") {
		t.Fatal("unlisted sub: subject accepted on session validation")
	}
}

func checkSubIgnoresDomain(t *testing.T) {
	t.Helper()
	if newPrincipalGate(t, ProviderOIDC, "@example.com").subjectAllowed("sub:mallory@example.com") {
		t.Fatal("sub: session subject honored an @domain entry")
	}
}

func checkCredentialIgnoresDomain(t *testing.T) {
	t.Helper()
	if newPrincipalGate(t, ProviderCredential, "@example.com").subjectAllowed("bob@example.com") {
		t.Fatal("credential provider honored an @domain entry")
	}
}

func rejectMalformedPrincipals(t *testing.T) {
	t.Helper()
	for _, entry := range []string{"@", "@a@b", "@ex ample.com"} {
		if _, err := normalizeProviderPrincipals([]string{entry}); err == nil {
			t.Fatalf("normalizeProviderPrincipals(%q) = nil error", entry)
		}
	}
}

func rejectUntypedPrincipals(t *testing.T) {
	t.Helper()
	for _, entry := range []string{"alice", "sub:", "sub: ", "alice@", "alice@a@b", "Kevin@example.com", "@gİthub.com"} {
		if _, err := normalizeProviderPrincipals([]string{entry}); err == nil {
			t.Fatalf("normalizeProviderPrincipals(%q) = nil error", entry)
		}
	}
}

func TestNormalizeProviderPrincipalKeepsSubjectCase(t *testing.T) {
	t.Parallel()

	tests := []struct {
		raw  string
		want string
	}{
		{"sub:Alice@Example.com", "sub:Alice@Example.com"},
		{"  sub:Alice@Example.com ", "sub:Alice@Example.com"},
		{"SUB:Alice@Example.com", "sub:Alice@Example.com"},
		{"sub:AbC123", "sub:AbC123"},
		{"Alice@Example.com", "alice@example.com"},
	}
	for _, tt := range tests {
		got, err := normalizeProviderPrincipal(tt.raw)
		if err != nil || got != tt.want {
			t.Errorf("normalizeProviderPrincipal(%q) = (%q, %v); want %q", tt.raw, got, err, tt.want)
		}
	}
}

func TestApplicationAuthOIDCLongSubSurvivesRevalidation(t *testing.T) {
	t.Parallel()

	sub := strings.Repeat("a", 255)
	handler, err := New(http.NotFoundHandler(), applicationAuthTestIdentity(), Config{
		Provider:   ProviderOIDC,
		Allow:      []string{"sub:" + sub},
		OIDCConfig: OIDCConfig{OIDCIssuerURL: "https://idp.example", OIDCClientID: oidcTestClientID},
	})
	if err != nil {
		t.Fatal(err)
	}
	gate := handler.(*applicationAuth)
	subject, ok := gate.resolveAllowedPrincipal("", sub)
	if !ok {
		t.Fatal("maximum-length sub was not authorized at login")
	}

	rec := httptest.NewRecorder()
	if err := gate.setSession(rec, Principal{Provider: ProviderOIDC, Subject: subject}, "app.example", time.Now(), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "https://app.example/dashboard", nil)
	for _, c := range rec.Result().Cookies() {
		req.AddCookie(c)
	}
	if got, ok := gate.authenticateSession(req); !ok || got.Subject != subject {
		t.Fatalf("authenticateSession = (%q, %v); want the session to stay valid for %q", got, ok, subject)
	}
}

func TestApplicationAuthOIDCSessionIsBoundToIssuerAndClient(t *testing.T) {
	t.Parallel()

	issuer := newSessionBindingGate(t, "https://idp.example", "portal-client", "secret")
	cookies := issueSessionCookies(t, issuer)
	for _, tt := range []struct {
		name         string
		issuer       string
		clientID     string
		clientSecret string
		want         bool
	}{
		{"same configuration after a restart", "https://idp.example", "portal-client", "secret", true},
		{"issuer written with a trailing slash", "https://idp.example/", "portal-client", "secret", true},
		{"rotated client secret", "https://idp.example", "portal-client", "rotated", true},
		{"different issuer", "https://other-idp.example", "portal-client", "secret", false},
		{"different client id", "https://idp.example", "other-client", "secret", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			checkSessionBindingCase(t, cookies, tt.issuer, tt.clientID, tt.clientSecret, tt.want)
		})
	}

	t.Run("session carrying no binding", func(t *testing.T) {
		t.Parallel()
		checkSessionWithoutBinding(t, issuer)
	})
}

func newSessionBindingGate(t *testing.T, issuer, clientID, clientSecret string) *applicationAuth {
	t.Helper()
	handler, err := New(http.NotFoundHandler(), applicationAuthTestIdentity(), Config{
		Provider:   ProviderOIDC,
		Allow:      []string{"alice@example.com"},
		OIDCConfig: OIDCConfig{OIDCIssuerURL: issuer, OIDCClientID: clientID, OIDCClientSecret: clientSecret},
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler.(*applicationAuth)
}

func newSessionCookieRequest(cookies []*http.Cookie) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "https://app.example/dashboard", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	return req
}

func issueSessionCookies(t *testing.T, issuer *applicationAuth) []*http.Cookie {
	t.Helper()
	rec := httptest.NewRecorder()
	if err := issuer.setSession(rec, Principal{Provider: ProviderOIDC, Subject: "alice@example.com"}, "app.example", time.Now(), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	return rec.Result().Cookies()
}

func checkSessionBindingCase(t *testing.T, cookies []*http.Cookie, issuer, clientID, clientSecret string, want bool) {
	t.Helper()
	gate := newSessionBindingGate(t, issuer, clientID, clientSecret)
	if _, ok := gate.authenticateSession(newSessionCookieRequest(cookies)); ok != want {
		t.Fatalf("authenticateSession ok = %v; want %v", ok, want)
	}
}

func checkSessionWithoutBinding(t *testing.T, issuer *applicationAuth) {
	t.Helper()
	token, err := encodeSignedApplicationAuthJSON(issuer.signingKey, applicationAuthClaims{
		Subject:   "alice@example.com",
		Provider:  ProviderOIDC,
		Host:      "app.example",
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	cookie := &http.Cookie{Name: applicationAuthCookieName, Value: token}
	if _, ok := issuer.authenticateSession(newSessionCookieRequest([]*http.Cookie{cookie})); ok {
		t.Fatal("an OIDC session without an issuer and client binding was accepted")
	}
}
