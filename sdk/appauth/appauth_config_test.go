package appauth

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestApplicationCredentialRejectsOtherHostAndExpiry(t *testing.T) {
	tunnelIdentity := applicationAuthTestIdentity()
	credential, err := IssueCredential(tunnelIdentity, "app.example", "alice", time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	key, err := identity.DeriveToken(tunnelIdentity, applicationCredentialKeyUse)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyApplicationCredential([]byte(key), tunnelIdentity, "other.example", credential, time.Now().UTC()); err == nil {
		t.Fatal("other host accepted")
	}
	if _, err := verifyApplicationCredential([]byte(key), tunnelIdentity, "app.example", credential, time.Now().UTC().Add(2*time.Hour)); err == nil {
		t.Fatal("expired credential accepted")
	}
}

func TestApplicationCredentialHostIgnoresTheDefaultPort(t *testing.T) {
	t.Parallel()

	tunnelIdentity := applicationAuthTestIdentity()
	key := deriveCredentialHostKey(t, tunnelIdentity)
	checkCredentialHostPortPairs(t, tunnelIdentity, key)
	checkClaimedHostAccepted(t, tunnelIdentity, key)
	checkRedeemURLDropsPort(t)
}

func deriveCredentialHostKey(t *testing.T, tunnelIdentity types.Identity) []byte {
	t.Helper()
	key, err := identity.DeriveToken(tunnelIdentity, applicationCredentialKeyUse)
	if err != nil {
		t.Fatal(err)
	}
	return []byte(key)
}

func checkCredentialHostPortPairs(t *testing.T, tunnelIdentity types.Identity, key []byte) {
	t.Helper()
	for _, tt := range []struct {
		issuedFor   string
		requestHost string
		want        bool
	}{
		{"app.example", "app.example", true},
		{"https://app.example:443", "app.example", true},
		{"app.example:443", "app.example", true},
		{"app.example", "app.example:443", true},
		{"App.Example.:443", "app.example", true},
		{"https://app.example:8443", "app.example:8443", true},
		{"app.example:8443", "app.example", false},
		{"app.example", "app.example:8443", false},
		{"app.example:1443", "app.example", false},
		{"app.example", "app.example:1443", false},
	} {
		credential, err := IssueCredential(tunnelIdentity, tt.issuedFor, "alice", time.Now().UTC().Add(time.Hour))
		if err != nil {
			t.Fatalf("IssueCredential(%q) error = %v", tt.issuedFor, err)
		}
		_, err = verifyApplicationCredential(key, tunnelIdentity, tt.requestHost, credential, time.Now().UTC())
		if (err == nil) != tt.want {
			t.Errorf("a credential issued for %q, redeemed at Host %q: error = %v; want accepted %v", tt.issuedFor, tt.requestHost, err, tt.want)
		}
	}
}

func checkClaimedHostAccepted(t *testing.T, tunnelIdentity types.Identity, key []byte) {
	t.Helper()
	for _, claimedHost := range []string{"app.example:443", "App.Example.:443"} {
		token, err := encodeSignedApplicationAuthJSON(key, applicationCredentialClaims{
			Version: applicationCredentialVersion, Subject: "alice", Tunnel: tunnelIdentity.Key(), Host: claimedHost,
			ExpiresAt: time.Now().UTC().Add(time.Hour).Unix(),
		})
		if err != nil {
			t.Fatal(err)
		}
		for _, requestHost := range []string{"app.example", "app.example:443"} {
			if _, err := verifyApplicationCredential(key, tunnelIdentity, requestHost, applicationCredentialPrefix+token, time.Now().UTC()); err != nil {
				t.Errorf("a credential issued for %q, redeemed at Host %q: %v; want accepted", claimedHost, requestHost, err)
			}
		}
		if _, err := verifyApplicationCredential(key, tunnelIdentity, "app.example:8443", applicationCredentialPrefix+token, time.Now().UTC()); err == nil {
			t.Errorf("a credential issued for %q accepted at another port", claimedHost)
		}
	}
}

func checkRedeemURLDropsPort(t *testing.T) {
	t.Helper()
	redeemURL, err := CredentialRedeemURL("https://app.example:443", "portal_cred_x")
	if err != nil || !strings.HasPrefix(redeemURL, "https://app.example/") {
		t.Errorf("CredentialRedeemURL() = %q, %v; want a URL on app.example without the default port", redeemURL, err)
	}
}
func TestSanitizeApplicationAuthNext(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		next string
		want string
	}{
		{"plain path", "/dashboard", "/dashboard"},
		{"path with query", "/private?q=1", "/private?q=1"},
		{"root", "/", "/"},
		{"surrounding space is trimmed", "  /dashboard ", "/dashboard"},
		{"empty", "", "/"},
		{"relative path", "dashboard", "/"},
		{"absolute URL", "https://evil.example/", "/"},
		{"scheme-relative URL", "//evil.example/", "/"},
		{"slash then backslash", "/\\evil.example/", "/"},
		{"backslash later in the path", "/a\\b", "/"},
		{"backslash only", "\\evil.example", "/"},
		{"tab after the slash", "/\t/evil.example", "/"},
		{"newline after the slash", "/\n/evil.example", "/"},
		{"carriage return after the slash", "/\r/evil.example", "/"},
		{"tab later in the path", "/a\tb", "/"},
		{"delete character", "/a\x7fb", "/"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := sanitizeApplicationAuthNext(tc.next); got != tc.want {
				t.Fatalf("sanitizeApplicationAuthNext(%q) = %q; want %q", tc.next, got, tc.want)
			}
		})
	}
}

func TestResolveApplicationAuthConfig(t *testing.T) {
	t.Parallel()

	const mixedCaseWallet = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
	wallet := normalizeMixedCaseWallet(t, mixedCaseWallet)
	tests := []struct {
		name    string
		cfg     Config
		want    applicationAuthSettings
		wantErr string
	}{
		{
			name: "oidc values are trimmed and normalized",
			cfg: Config{
				Provider:   " OIDC ",
				Allow:      []string{"Alice@Example.com", "alice@example.com"},
				OIDCConfig: OIDCConfig{OIDCIssuerURL: " https://idp.example/ ", OIDCClientID: " portal-client ", OIDCClientSecret: " secret "},
			},
			want: applicationAuthSettings{
				provider:     ProviderOIDC,
				allowed:      []string{"alice@example.com"},
				issuerURL:    "https://idp.example",
				clientID:     "portal-client",
				clientSecret: "secret",
			},
		},
		{
			name: "credential subjects are de-duplicated and carry no oidc settings",
			cfg:  Config{Provider: "Credential", Allow: []string{"alice", "alice"}},
			want: applicationAuthSettings{provider: ProviderCredential, allowed: []string{"alice"}},
		},
		{
			name: "wallet addresses are normalized and de-duplicated",
			cfg:  Config{Provider: "SIWE", Allow: []string{mixedCaseWallet, strings.ToLower(mixedCaseWallet)}},
			want: applicationAuthSettings{provider: ProviderSIWE, allowed: []string{wallet}},
		},
		{
			name: "identity proof is kept as given",
			cfg:  Config{Provider: ProviderCredential, IdentityHeaders: true, IdentityProof: "!~" + strings.Repeat("a", 14)},
			want: applicationAuthSettings{provider: ProviderCredential, identityProof: "!~" + strings.Repeat("a", 14)},
		},
		{
			name: "identity proof with oidc",
			cfg: Config{
				Provider:        ProviderOIDC,
				Allow:           []string{"alice@example.com"},
				IdentityHeaders: true,
				IdentityProof:   identityProofTestValue,
				OIDCConfig:      OIDCConfig{OIDCIssuerURL: "https://idp.example", OIDCClientID: oidcTestClientID},
			},
			want: applicationAuthSettings{
				provider:      ProviderOIDC,
				allowed:       []string{"alice@example.com"},
				identityProof: identityProofTestValue,
				issuerURL:     "https://idp.example",
				clientID:      oidcTestClientID,
			},
		},
		{
			name:    "identity proof without identity headers",
			cfg:     Config{Provider: ProviderSIWE, IdentityProof: identityProofTestValue},
			wantErr: "(--auth-identity-proof / AUTH_IDENTITY_PROOF) requires --auth-identity-headers",
		},
		{
			name:    "identity proof too short",
			cfg:     Config{Provider: ProviderCredential, IdentityHeaders: true, IdentityProof: "abcdefghijklmno"},
			wantErr: "(--auth-identity-proof / AUTH_IDENTITY_PROOF) must be at least 16 characters",
		},
		{
			name:    "identity proof with a space",
			cfg:     Config{Provider: ProviderCredential, IdentityHeaders: true, IdentityProof: "test proof 0123456789"},
			wantErr: "visible ASCII",
		},
		{
			name:    "identity proof is not trimmed",
			cfg:     Config{Provider: ProviderCredential, IdentityHeaders: true, IdentityProof: " " + identityProofTestValue},
			wantErr: "visible ASCII",
		},
		{
			name:    "identity proof with a line break",
			cfg:     Config{Provider: ProviderCredential, IdentityHeaders: true, IdentityProof: identityProofTestValue + "\r\nX-Injected: 1"},
			wantErr: "visible ASCII",
		},
		{
			name:    "identity proof with the delete character",
			cfg:     Config{Provider: ProviderCredential, IdentityHeaders: true, IdentityProof: identityProofTestValue + "\x7f"},
			wantErr: "visible ASCII",
		},
		{
			name:    "identity proof with a non-ASCII character",
			cfg:     Config{Provider: ProviderCredential, IdentityHeaders: true, IdentityProof: "test-proof-01234567é"},
			wantErr: "visible ASCII",
		},
		{
			name:    "unknown provider",
			cfg:     Config{Provider: "ldap"},
			wantErr: "unsupported application auth provider",
		},
		{
			name:    "oidc settings with another provider",
			cfg:     Config{Provider: ProviderSIWE, OIDCConfig: OIDCConfig{OIDCClientID: oidcTestClientID}},
			wantErr: "oidc settings require the oidc application auth provider",
		},
		{
			name:    "oidc without an allowlist",
			cfg:     Config{Provider: ProviderOIDC, OIDCConfig: OIDCConfig{OIDCIssuerURL: "https://idp.example", OIDCClientID: oidcTestClientID}},
			wantErr: "--auth-email-list",
		},
		{
			name:    "oidc without an issuer",
			cfg:     Config{Provider: ProviderOIDC, Allow: []string{"alice@example.com"}, OIDCConfig: OIDCConfig{OIDCClientID: oidcTestClientID}},
			wantErr: "issuer url is required",
		},
		{
			name:    "oidc with a cleartext issuer",
			cfg:     Config{Provider: ProviderOIDC, Allow: []string{"alice@example.com"}, OIDCConfig: OIDCConfig{OIDCIssuerURL: "http://idp.example", OIDCClientID: oidcTestClientID}},
			wantErr: "must use https",
		},
		{
			name:    "oidc without a client id",
			cfg:     Config{Provider: ProviderOIDC, Allow: []string{"alice@example.com"}, OIDCConfig: OIDCConfig{OIDCIssuerURL: "https://idp.example", OIDCClientID: "  "}},
			wantErr: "client id is required",
		},
		{
			name: "saml values are trimmed and normalized",
			cfg: Config{
				Provider:   " SAML ",
				Allow:      []string{"Alice@Example.com", "@example.org", "sub:A1"},
				SAMLConfig: SAMLConfig{SAMLMetadataURL: " https://login.example/federationmetadata.xml?appid=1 ", SAMLEntityID: " urn:portal:app ", SAMLSubjectAttribute: " email "},
			},
			want: applicationAuthSettings{
				provider:             ProviderSAML,
				allowed:              []string{"alice@example.com", "@example.org", "sub:A1"},
				samlMetadataURL:      "https://login.example/federationmetadata.xml?appid=1",
				samlEntityID:         "urn:portal:app",
				samlSubjectAttribute: "email",
			},
		},
		{
			name: "saml metadata from a file",
			cfg:  Config{Provider: ProviderSAML, Allow: []string{"alice@example.com"}, SAMLConfig: SAMLConfig{SAMLMetadataFile: " idp.xml "}},
			want: applicationAuthSettings{provider: ProviderSAML, allowed: []string{"alice@example.com"}, samlMetadataFile: "idp.xml"},
		},
		{
			name:    "saml settings with another provider",
			cfg:     Config{Provider: ProviderOIDC, Allow: []string{"alice@example.com"}, OIDCConfig: OIDCConfig{OIDCIssuerURL: "https://idp.example", OIDCClientID: oidcTestClientID}, SAMLConfig: SAMLConfig{SAMLEntityID: "urn:portal:app"}},
			wantErr: "saml settings require the saml application auth provider",
		},
		{
			name:    "oidc settings with saml",
			cfg:     Config{Provider: ProviderSAML, Allow: []string{"alice@example.com"}, SAMLConfig: SAMLConfig{SAMLMetadataFile: "idp.xml"}, OIDCConfig: OIDCConfig{OIDCClientID: oidcTestClientID}},
			wantErr: "oidc settings require the oidc application auth provider",
		},
		{
			name:    "saml without an allowlist",
			cfg:     Config{Provider: ProviderSAML, SAMLConfig: SAMLConfig{SAMLMetadataURL: "https://idp.example/metadata"}},
			wantErr: "--auth-email-list",
		},
		{
			name:    "saml without metadata",
			cfg:     Config{Provider: ProviderSAML, Allow: []string{"alice@example.com"}},
			wantErr: "requires identity provider metadata",
		},
		{
			name:    "saml with two metadata sources",
			cfg:     Config{Provider: ProviderSAML, Allow: []string{"alice@example.com"}, SAMLConfig: SAMLConfig{SAMLMetadataURL: "https://idp.example/metadata", SAMLMetadataFile: "idp.xml"}},
			wantErr: "not both",
		},
		{
			name:    "saml with cleartext metadata",
			cfg:     Config{Provider: ProviderSAML, Allow: []string{"alice@example.com"}, SAMLConfig: SAMLConfig{SAMLMetadataURL: "http://idp.example/metadata"}},
			wantErr: "must use https",
		},
		{
			name:    "saml entity id longer than SAML allows",
			cfg:     Config{Provider: ProviderSAML, Allow: []string{"alice@example.com"}, SAMLConfig: SAMLConfig{SAMLMetadataFile: "idp.xml", SAMLEntityID: "urn:" + strings.Repeat("a", 1024)}},
			wantErr: "saml entity id must be at most 1024 characters",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			checkResolvedConfigCase(t, tt.cfg, tt.want, tt.wantErr)
		})
	}
}

func normalizeMixedCaseWallet(t *testing.T, mixedCaseWallet string) string {
	t.Helper()
	wallet, err := identity.NormalizeEVMAddress(mixedCaseWallet)
	if err != nil {
		t.Fatal(err)
	}
	return wallet
}

func checkResolvedConfigCase(t *testing.T, cfg Config, want applicationAuthSettings, wantErr string) {
	t.Helper()
	got, err := resolveApplicationAuthConfig(cfg)
	if wantErr != "" {
		if err == nil || !strings.Contains(err.Error(), wantErr) {
			t.Fatalf("resolveApplicationAuthConfig() error = %v; want one containing %q", err, wantErr)
		}
		if cfg.IdentityProof != "" && strings.Contains(err.Error(), cfg.IdentityProof) {
			t.Fatalf("resolveApplicationAuthConfig() error %q contains the identity proof", err)
		}
		if validateErr := Validate(cfg); validateErr == nil || validateErr.Error() != err.Error() {
			t.Fatalf("Validate() = %v; want the resolver's error %v", validateErr, err)
		}
		return
	}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("resolveApplicationAuthConfig() = %+v, %v; want %+v", got, err, want)
	}
	if validateErr := Validate(cfg); validateErr != nil {
		t.Fatalf("Validate() = %v; want nil for a config the resolver accepts", validateErr)
	}
}
