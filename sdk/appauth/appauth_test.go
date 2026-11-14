package appauth

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestApplicationAuthRequiresLogin(t *testing.T) {
	handler := newApplicationAuthTestHandler(t, nil, false, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("unauthenticated request reached upstream")
	}))
	req := httptest.NewRequest(http.MethodGet, "https://app.example/private?q=1", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d; want %d", rec.Code, http.StatusSeeOther)
	}
	if location := rec.Header().Get("Location"); location != types.PathApplicationAuthLogin+"?next=%2Fprivate%3Fq%3D1" {
		t.Fatalf("Location = %q", location)
	}

	req = httptest.NewRequest(http.MethodPost, "https://app.example/private", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("POST status = %d; want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestApplicationAuthSIWEAndIdentityHeaders(t *testing.T) {
	wallet := applicationAuthTestWallet(t, "1")
	var upstreamUser, upstreamAuth string
	var upstreamPortalNames []string
	handler := newApplicationAuthTestHandler(t, []string{wallet.Identity().Address}, true, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamUser = r.Header.Get(types.HeaderPortalUser)
		upstreamAuth = r.Header.Get(types.HeaderPortalAuth)
		upstreamPortalNames = portalHeaderNames(r.Header)
		w.WriteHeader(http.StatusNoContent)
	}))

	challenge := fetchApplicationAuthSIWEChallenge(t, handler, wallet.Identity().Address)
	cookies, verifyBody := redeemApplicationAuthSIWEChallenge(t, handler, wallet, challenge)
	protectedRec := serveApplicationAuthSIWEProtected(t, handler, cookies[0])
	if protectedRec.Code != http.StatusNoContent {
		t.Fatalf("protected status = %d", protectedRec.Code)
	}
	if upstreamUser != wallet.Identity().Address || upstreamAuth != "siwe" {
		t.Fatalf("identity headers = %q, %q", upstreamUser, upstreamAuth)
	}
	if want := []string{types.HeaderPortalAuth, types.HeaderPortalUser}; !slices.Equal(upstreamPortalNames, want) {
		t.Fatalf("portal headers at the upstream = %q; want only %q", upstreamPortalNames, want)
	}

	replayRec := serveApplicationAuthSIWEReplay(t, handler, verifyBody)
	if replayRec.Code != http.StatusOK {
		t.Fatalf("challenge replay status = %d; want %d", replayRec.Code, http.StatusOK)
	}
	if len(replayRec.Result().Cookies()) != 1 {
		t.Fatalf("challenge replay session cookie missing")
	}
}

func fetchApplicationAuthSIWEChallenge(t *testing.T, handler http.Handler, address string) applicationAuthChallengeResponse {
	t.Helper()
	challengeBody, _ := json.Marshal(applicationAuthChallengeRequest{Address: address})
	challengeReq := httptest.NewRequest(http.MethodPost, "https://app.example"+types.PathApplicationAuthChallenge, bytes.NewReader(challengeBody))
	challengeReq.Header.Set("Origin", "https://app.example")
	challengeRec := httptest.NewRecorder()
	handler.ServeHTTP(challengeRec, challengeReq)
	if challengeRec.Code != http.StatusOK {
		t.Fatalf("challenge status = %d, body = %s", challengeRec.Code, challengeRec.Body.String())
	}
	var challenge applicationAuthChallengeResponse
	if err := json.NewDecoder(challengeRec.Body).Decode(&challenge); err != nil {
		t.Fatal(err)
	}
	return challenge
}

func redeemApplicationAuthSIWEChallenge(t *testing.T, handler http.Handler, wallet identity.LocalAuthority, challenge applicationAuthChallengeResponse) ([]*http.Cookie, []byte) {
	t.Helper()
	signature, err := wallet.SignEthereumPersonalMessage(challenge.Message)
	if err != nil {
		t.Fatal(err)
	}
	verifyBody, _ := json.Marshal(applicationAuthVerifyRequest{ChallengeID: challenge.ChallengeID, Message: challenge.Message, Signature: signature})
	verifyReq := httptest.NewRequest(http.MethodPost, "https://app.example"+types.PathApplicationAuthVerify, bytes.NewReader(verifyBody))
	verifyReq.Header.Set("Origin", "https://app.example")
	verifyRec := httptest.NewRecorder()
	handler.ServeHTTP(verifyRec, verifyReq)
	if verifyRec.Code != http.StatusOK {
		t.Fatalf("verify status = %d, body = %s", verifyRec.Code, verifyRec.Body.String())
	}
	cookies := verifyRec.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteLaxMode {
		t.Fatalf("session cookie = %#v", cookies)
	}
	return cookies, verifyBody
}

func serveApplicationAuthSIWEProtected(t *testing.T, handler http.Handler, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	protectedReq := httptest.NewRequest(http.MethodGet, "https://app.example/private", nil)
	protectedReq.AddCookie(cookie)
	protectedReq.Header.Set(types.HeaderPortalUser, "attacker")
	protectedReq.Header.Set(types.HeaderPortalAuth, "attacker")
	protectedReq.Header["X_Portal_User"] = []string{"attacker"}
	protectedReq.Header["X_portal_auth"] = []string{"attacker"}
	protectedRec := httptest.NewRecorder()
	handler.ServeHTTP(protectedRec, protectedReq)
	return protectedRec
}

func serveApplicationAuthSIWEReplay(t *testing.T, handler http.Handler, verifyBody []byte) *httptest.ResponseRecorder {
	t.Helper()
	replayReq := httptest.NewRequest(http.MethodPost, "https://app.example"+types.PathApplicationAuthVerify, bytes.NewReader(verifyBody))
	replayReq.Header.Set("Origin", "https://app.example")
	replayRec := httptest.NewRecorder()
	handler.ServeHTTP(replayRec, replayReq)
	return replayRec
}

func TestApplicationAuthStripsPortalCredentials(t *testing.T) {
	var user, auth, proof, cookies string
	requests := 0
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		user, auth = r.Header.Get(types.HeaderPortalUser), r.Header.Get(types.HeaderPortalAuth)
		proof = r.Header.Get(types.HeaderPortalProof)
		cookies = r.Header.Get("Cookie")
	})
	handler := newApplicationAuthTestHandler(t, nil, false, next)
	gate := handler.(*applicationAuth)
	token := issueStrippedHeaderSession(t, gate)
	providerlessToken := issueProviderlessSession(t, gate)
	req := httptest.NewRequest(http.MethodGet, "https://app.example/", nil)
	req.AddCookie(&http.Cookie{Name: "app_session", Value: "abc"})
	req.AddCookie(&http.Cookie{Name: applicationAuthCookieName, Value: token})
	req.Header.Set(types.HeaderPortalUser, "attacker")
	req.Header.Set(types.HeaderPortalAuth, "attacker")
	req.Header.Set(types.HeaderPortalProof, "attacker")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if user != "" || auth != "" || proof != "" {
		t.Fatalf("untrusted identity headers reached upstream: %q, %q, %q", user, auth, proof)
	}
	if cookies != "app_session=abc" {
		t.Fatalf("upstream Cookie = %q; want only application cookie", cookies)
	}
	for name, requestToken := range map[string]string{
		"other host":       token,
		"tampered":         "x" + token[1:],
		"missing provider": providerlessToken,
	} {
		t.Run(name, func(t *testing.T) {
			checkRejectedSessionRedirects(t, handler, name, requestToken)
		})
	}
	if requests != 1 {
		t.Fatalf("upstream requests = %d; want 1", requests)
	}
}

func issueStrippedHeaderSession(t *testing.T, gate *applicationAuth) string {
	t.Helper()
	token, err := gate.issueSession(Principal{Provider: ProviderSIWE, Subject: applicationAuthTestWallet(t, "2").Identity().Address}, "app.example", time.Now(), applicationAuthTestTime().Add(applicationAuthSessionTTL))
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func issueProviderlessSession(t *testing.T, gate *applicationAuth) string {
	t.Helper()
	providerlessToken, err := encodeSignedApplicationAuthJSON(gate.signingKey, applicationAuthClaims{Subject: applicationAuthTestWallet(t, "2").Identity().Address, Host: "app.example", ExpiresAt: applicationAuthTestTime().Add(applicationAuthSessionTTL).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	return providerlessToken
}

func checkRejectedSessionRedirects(t *testing.T, handler http.Handler, name, requestToken string) {
	t.Helper()
	host := "app.example"
	if name == "other host" {
		host = "other.example"
	}
	req := httptest.NewRequest(http.MethodGet, "https://"+host+"/", nil)
	req.AddCookie(&http.Cookie{Name: applicationAuthCookieName, Value: requestToken})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d; want %d", rec.Code, http.StatusSeeOther)
	}
}

func issueAppCredential(t *testing.T, tunnelIdentity types.Identity, subject string) string {
	t.Helper()
	credential, err := IssueCredential(tunnelIdentity, "app.example", subject, time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return credential
}

func TestApplicationAuthCredential(t *testing.T) {
	tunnelIdentity := applicationAuthTestIdentity()
	var upstreamUser, upstreamAuth, upstreamCredential string
	upstreamRequests := 0
	handler, err := New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamRequests++
		upstreamUser, upstreamAuth = r.Header.Get(types.HeaderPortalUser), r.Header.Get(types.HeaderPortalAuth)
		upstreamCredential = r.Header.Get(types.HeaderAccessCredential)
		w.WriteHeader(http.StatusNoContent)
	}), tunnelIdentity, Config{Provider: ProviderCredential, IdentityHeaders: true})
	if err != nil {
		t.Fatal(err)
	}
	credential := issueAppCredential(t, tunnelIdentity, "alice")
	cookies := redeemCredentialForCookies(t, handler, credential)
	protectedRec := serveProtectedWithCookie(t, handler, cookies[0])
	if protectedRec.Code != http.StatusNoContent || upstreamUser != "alice" || upstreamAuth != ProviderCredential {
		t.Fatalf("protected status = %d, identity = %q/%q", protectedRec.Code, upstreamUser, upstreamAuth)
	}
	directRec := serveProtectedWithCredential(t, handler, credential)
	if directRec.Code != http.StatusNoContent || upstreamUser != "alice" || upstreamAuth != ProviderCredential || upstreamCredential != "" {
		t.Fatalf("credential header status = %d, identity = %q/%q, upstream credential = %q", directRec.Code, upstreamUser, upstreamAuth, upstreamCredential)
	}
	bobCredential := issueAppCredential(t, tunnelIdentity, "bob")
	credentialAndCookieRec := serveCookiePlusCredential(t, handler, cookies[0], bobCredential)
	if credentialAndCookieRec.Code != http.StatusNoContent || upstreamUser != "bob" {
		t.Fatalf("credential with cookie status = %d, user = %q; want bob", credentialAndCookieRec.Code, upstreamUser)
	}
	invalidRec := serveCookiePlusCredential(t, handler, cookies[0], "invalid")
	if invalidRec.Code == http.StatusNoContent || upstreamRequests != 3 {
		t.Fatalf("invalid credential with cookie status = %d, upstream requests = %d; want rejection", invalidRec.Code, upstreamRequests)
	}
}

func redeemCredentialForCookies(t *testing.T, handler http.Handler, credential string) []*http.Cookie {
	t.Helper()
	body, _ := json.Marshal(applicationAuthRedeemRequest{Credential: credential})
	req := httptest.NewRequest(http.MethodPost, "https://app.example"+types.PathApplicationAuthRedeem, bytes.NewReader(body))
	req.Header.Set("Origin", "https://app.example")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("redeem status = %d, body = %s", rec.Code, rec.Body.String())
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies = %#v", cookies)
	}
	return cookies
}

func serveProtectedWithCookie(t *testing.T, handler http.Handler, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	protected := httptest.NewRequest(http.MethodGet, "https://app.example/private", nil)
	protected.AddCookie(cookie)
	protectedRec := httptest.NewRecorder()
	handler.ServeHTTP(protectedRec, protected)
	return protectedRec
}

func serveProtectedWithCredential(t *testing.T, handler http.Handler, credential string) *httptest.ResponseRecorder {
	t.Helper()
	direct := httptest.NewRequest(http.MethodGet, "https://app.example/api", nil)
	direct.Header.Set(types.HeaderAccessCredential, credential)
	directRec := httptest.NewRecorder()
	handler.ServeHTTP(directRec, direct)
	return directRec
}

func serveCookiePlusCredential(t *testing.T, handler http.Handler, cookie *http.Cookie, credential string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "https://app.example/api", nil)
	req.AddCookie(cookie)
	req.Header.Set(types.HeaderAccessCredential, credential)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}
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
func portalHeaderNames(h http.Header) []string {
	var names []string
	for key := range h {
		if strings.HasPrefix(strings.ToLower(strings.ReplaceAll(key, "_", "-")), "x-portal-") {
			names = append(names, key)
		}
	}
	slices.Sort(names)
	return names
}

const identityProofTestValue = "test-proof-0123456789"

func newApplicationAuthTestHandler(t *testing.T, allowed []string, identityHeaders bool, next http.Handler) http.Handler {
	t.Helper()
	tunnelIdentity := applicationAuthTestIdentity()
	handler, err := New(next, tunnelIdentity, Config{Provider: ProviderSIWE, Allow: allowed, IdentityHeaders: identityHeaders})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func applicationAuthTestIdentity() types.Identity {
	return types.Identity{Name: "application-auth-test", Address: "0x0000000000000000000000000000000000000001", TokenSecret: strings.Repeat("k", 32)}
}

func applicationAuthTestWallet(t *testing.T, digit string) identity.LocalAuthority {
	t.Helper()
	resolved, err := identity.ResolveSecp256k1Identity(strings.Repeat("0", 63) + digit)
	if err != nil {
		t.Fatal(err)
	}
	resolved.Name = "application-auth-test"
	return identity.NewLocalAuthority(resolved)
}

func applicationAuthTestTime() time.Time {
	return time.Now().UTC()
}
func TestLoginStateFromAnEarlierHoldIsRefused(t *testing.T) {
	t.Parallel()

	const alias = "alias.example"
	now := time.Now().UTC()
	expires := now.Add(applicationAuthLoginStateTTL).Unix()
	checkLoginStateHoldRefusals(t, alias, expires, now)
}

func serveLoginStateAtHold(gate *applicationAuth, since time.Time, req *http.Request) string {
	const alias = "alias.example"
	gate.publicHosts = func() []PublicHost { return []PublicHost{{URL: "https://" + alias, Since: since}} }
	rec := httptest.NewRecorder()
	gate.ServeHTTP(rec, req)
	return rec.Body.String()
}

func seedOIDCLoginStateCase(t *testing.T, alias string, expires int64) (*applicationAuth, func() *http.Request, string) {
	t.Helper()
	oidcGate := newOIDCTestGate(t, newOIDCTestIdP(t, nil), "alice@example.com")
	oidcState, err := encodeSignedApplicationAuthJSON(oidcGate.oidc.stateKey, oidcStateClaims{State: "state", Nonce: "nonce", CodeVerifier: "verifier", Host: alias, Next: "/", ExpiresAt: expires})
	if err != nil {
		t.Fatal(err)
	}
	callback := func() *http.Request {
		req := httptest.NewRequest(http.MethodGet, "https://"+alias+types.PathApplicationAuthCallback+"?state=state&code=code", nil)
		req.AddCookie(&http.Cookie{Name: applicationAuthOIDCStateCookie, Value: oidcState})
		return req
	}
	return oidcGate, callback, "invalid or expired oidc login state"
}

func seedSAMLLoginStateCase(t *testing.T, alias string, expires int64) (*applicationAuth, func() *http.Request, string) {
	t.Helper()
	samlGate := newSAMLTestGate(t, newSAMLTestIdP(t), http.NotFoundHandler(), nil)
	samlState, err := encodeSignedApplicationAuthJSON(samlGate.saml.stateKey, samlStateClaims{RequestID: "request", Host: alias, Next: "/", ExpiresAt: expires})
	if err != nil {
		t.Fatal(err)
	}
	acs := func() *http.Request {
		req := httptest.NewRequest(http.MethodPost, "https://"+alias+types.PathApplicationAuthSAMLACS, strings.NewReader("SAMLResponse=x"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(&http.Cookie{Name: applicationAuthSAMLStateCookie, Value: samlState})
		return req
	}
	return samlGate, acs, "invalid or expired saml login state"
}

func checkLoginStateHoldRefusals(t *testing.T, alias string, expires int64, now time.Time) {
	t.Helper()
	oidcGate, oidcCallback, oidcRefused := seedOIDCLoginStateCase(t, alias, expires)
	samlGate, samlCallback, samlRefused := seedSAMLLoginStateCase(t, alias, expires)
	for _, tt := range []struct {
		name    string
		gate    *applicationAuth
		request func() *http.Request
		refused string
	}{
		{"oidc", oidcGate, oidcCallback, oidcRefused},
		{"saml", samlGate, samlCallback, samlRefused},
	} {
		if body := serveLoginStateAtHold(tt.gate, now.Add(time.Minute), tt.request()); !strings.Contains(body, tt.refused) {
			t.Errorf("%s login from an earlier hold: %s", tt.name, body)
		}
		if body := serveLoginStateAtHold(tt.gate, now.Add(-time.Minute), tt.request()); strings.Contains(body, tt.refused) {
			t.Errorf("%s login from this hold was refused: %s", tt.name, body)
		}
	}
}

func postSIWEChallengeRequest(t *testing.T, handler http.Handler, alias, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "https://"+alias+path, bytes.NewReader(raw))
	req.Header.Set("Origin", "https://"+alias)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func seedSIWEStaleHoldGate(t *testing.T, hosts *atomic.Value, allow string) http.Handler {
	t.Helper()
	handler, err := New(http.NotFoundHandler(), applicationAuthTestIdentity(), Config{
		Provider:    ProviderSIWE,
		Allow:       []string{allow},
		PublicHosts: func() []PublicHost { return hosts.Load().([]PublicHost) },
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func buildSIWEVerifyRequest(t *testing.T, handler http.Handler, wallet identity.LocalAuthority, alias string) applicationAuthVerifyRequest {
	t.Helper()
	asked := postSIWEChallengeRequest(t, handler, alias, types.PathApplicationAuthChallenge, applicationAuthChallengeRequest{Address: wallet.Identity().Address})
	var challenge applicationAuthChallengeResponse
	if err := json.NewDecoder(asked.Body).Decode(&challenge); err != nil {
		t.Fatal(err)
	}
	signature, err := wallet.SignEthereumPersonalMessage(challenge.Message)
	if err != nil {
		t.Fatal(err)
	}
	return applicationAuthVerifyRequest{ChallengeID: challenge.ChallengeID, Message: challenge.Message, Signature: signature}
}

type staleSIWEHold struct {
	handler http.Handler
	hosts   *atomic.Value
	alias   string
	since   time.Time
}

func checkStaleSIWEHoldRefused(t *testing.T, hold staleSIWEHold, verify applicationAuthVerifyRequest) {
	t.Helper()
	hold.hosts.Store([]PublicHost{{URL: "https://" + hold.alias, Since: time.Now().UTC().Add(time.Minute)}})
	if rec := postSIWEChallengeRequest(t, hold.handler, hold.alias, types.PathApplicationAuthVerify, verify); rec.Code == http.StatusOK {
		t.Fatalf("a challenge from an earlier hold signed in: %s", rec.Body)
	}
}

func checkCurrentSIWEHoldAccepted(t *testing.T, hold staleSIWEHold, verify applicationAuthVerifyRequest) {
	t.Helper()
	hold.hosts.Store([]PublicHost{{URL: "https://" + hold.alias, Since: hold.since}})
	if rec := postSIWEChallengeRequest(t, hold.handler, hold.alias, types.PathApplicationAuthVerify, verify); rec.Code != http.StatusOK {
		t.Fatalf("a challenge from this hold = %d: %s", rec.Code, rec.Body)
	}
}

func TestSIWEChallengeFromAnEarlierHoldIsRefused(t *testing.T) {
	t.Parallel()

	const alias = "alias.example"
	wallet := applicationAuthTestWallet(t, "1")
	since := time.Now().UTC().Add(-time.Minute)
	var hosts atomic.Value
	hosts.Store([]PublicHost{{URL: "https://" + alias, Since: since}})
	handler := seedSIWEStaleHoldGate(t, &hosts, wallet.Identity().Address)
	verify := buildSIWEVerifyRequest(t, handler, wallet, alias)
	hold := staleSIWEHold{handler: handler, hosts: &hosts, alias: alias, since: since}
	checkStaleSIWEHoldRefused(t, hold, verify)
	checkCurrentSIWEHoldAccepted(t, hold, verify)
}

func TestApplicationCredentialHeaderPassesFromAnyOrigin(t *testing.T) {
	t.Parallel()

	tunnelIdentity := applicationAuthTestIdentity()
	handler, err := New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), tunnelIdentity, Config{Provider: ProviderCredential})
	if err != nil {
		t.Fatal(err)
	}
	credential, err := IssueCredential(tunnelIdentity, "app.example", "alice", time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "https://app.example/private", nil)
	req.Header.Set("Origin", "https://other.example")
	req.Header.Set(types.HeaderAccessCredential, credential)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d; want %d", rec.Code, http.StatusNoContent)
	}
}

func TestApplicationAuthWithoutSessionIgnoresOrigin(t *testing.T) {
	t.Parallel()

	handler, err := New(http.NotFoundHandler(), applicationAuthTestIdentity(), Config{Provider: ProviderCredential})
	if err != nil {
		t.Fatal(err)
	}
	upgrade := httptest.NewRequest(http.MethodGet, "https://app.example/private", nil)
	upgrade.Header = http.Header{"Connection": {"Upgrade"}, "Upgrade": {"websocket"}, "Origin": {"https://other.example"}}
	upgradeRec := httptest.NewRecorder()
	handler.ServeHTTP(upgradeRec, upgrade)
	if upgradeRec.Code != http.StatusSeeOther {
		t.Fatalf("upgrade status = %d; want %d", upgradeRec.Code, http.StatusSeeOther)
	}
	post := httptest.NewRequest(http.MethodPost, "https://app.example/private", nil)
	post.Header.Set("Origin", "https://other.example")
	postRec := httptest.NewRecorder()
	handler.ServeHTTP(postRec, post)
	if postRec.Code != http.StatusUnauthorized {
		t.Fatalf("post status = %d; want %d", postRec.Code, http.StatusUnauthorized)
	}
}
func TestSameApplicationHost(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		a, b string
		want bool
	}{
		{"app.example", "app.example", true},
		{"app.example", "App.Example", true},
		{"app.example", "app.example.", true},
		{"app.example:443", "app.example", true},
		{"App.Example.:443", "app.example", true},
		{"app.example:8443", "app.example:8443", true},
		{"app.example:8443", "app.example", false},
		{"app.example:1443", "app.example", false},
		{"app.example", "other.example", false},
		{"", "", false},
		{"app.example", "", false},
		{"app.example", "app example", false},
		{"app example", "app example", false},
		{"https://app.example/", "app.example", false},
		{"app.example", "https://app.example", false},
		{"app.example/", "app.example", false},
		{"https://app.example/", "https://app.example/", false},
	} {
		if got := sameApplicationHost(tt.a, tt.b); got != tt.want {
			t.Errorf("sameApplicationHost(%q, %q) = %v; want %v", tt.a, tt.b, got, tt.want)
		}
	}
}

func seedHostSpellingGate(t *testing.T, tunnelIdentity types.Identity) http.Handler {
	t.Helper()
	handler, err := New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), tunnelIdentity, Config{Provider: ProviderCredential})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func redeemHostSpellingSession(t *testing.T, handler http.Handler, tunnelIdentity types.Identity, host string) *http.Cookie {
	t.Helper()
	credential, err := IssueCredential(tunnelIdentity, "app.example", "alice", time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(applicationAuthRedeemRequest{Credential: credential})
	req := httptest.NewRequest(http.MethodPost, "https://"+host+types.PathApplicationAuthRedeem, bytes.NewReader(body))
	req.Header.Set("Origin", "https://"+host)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	cookies := rec.Result().Cookies()
	if rec.Code != http.StatusOK || len(cookies) != 1 {
		t.Fatalf("redeem at %q: status = %d, cookies = %v", host, rec.Code, cookies)
	}
	return cookies[0]
}

func fetchHostSpellingStatus(handler http.Handler, cookie *http.Cookie, host string) int {
	req := httptest.NewRequest(http.MethodGet, "https://"+host+"/private", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec.Code
}

func checkHostSpellingAccepted(t *testing.T, handler http.Handler, cookie *http.Cookie, issuedAt string) {
	t.Helper()
	for _, usedAt := range []string{"app.example", "app.example:443", "App.Example", "app.example."} {
		if got := fetchHostSpellingStatus(handler, cookie, usedAt); got != http.StatusNoContent {
			t.Errorf("a session issued at %q, used at %q: status = %d; want %d", issuedAt, usedAt, got, http.StatusNoContent)
		}
	}
}

func checkHostSpellingRejected(t *testing.T, handler http.Handler, cookie *http.Cookie, issuedAt string) {
	t.Helper()
	for _, usedAt := range []string{"app.example:8443", "other.example"} {
		if got := fetchHostSpellingStatus(handler, cookie, usedAt); got == http.StatusNoContent {
			t.Errorf("a session issued at %q was accepted at %q", issuedAt, usedAt)
		}
	}
}

func TestApplicationSessionFollowsTheHostNotItsSpelling(t *testing.T) {
	t.Parallel()

	tunnelIdentity := applicationAuthTestIdentity()
	handler := seedHostSpellingGate(t, tunnelIdentity)
	for _, issuedAt := range []string{"app.example", "app.example:443"} {
		cookie := redeemHostSpellingSession(t, handler, tunnelIdentity, issuedAt)
		checkHostSpellingAccepted(t, handler, cookie, issuedAt)
		checkHostSpellingRejected(t, handler, cookie, issuedAt)
	}
}

type identityProofGate struct {
	handler  http.Handler
	reached  *bool
	gotProof *[]string
}

func seedIdentityProofGate(t *testing.T, tunnelIdentity types.Identity, cfg Config) identityProofGate {
	t.Helper()
	reached := false
	var gotProof []string
	handler, err := New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		gotProof = r.Header.Values(types.HeaderPortalProof)
		w.WriteHeader(http.StatusNoContent)
	}), tunnelIdentity, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return identityProofGate{handler: handler, reached: &reached, gotProof: &gotProof}
}

func checkIdentityProofAuthenticated(t *testing.T, gate identityProofGate, credential string, wantProof []string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "https://app.example/api", nil)
	req.Header.Set(types.HeaderAccessCredential, credential)
	req.Header.Set(types.HeaderPortalProof, "forged-proof-value")
	rec := httptest.NewRecorder()
	gate.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent || !slices.Equal(*gate.gotProof, wantProof) {
		t.Fatalf("authenticated request: status = %d, upstream %s = %q; want %q", rec.Code, types.HeaderPortalProof, *gate.gotProof, wantProof)
	}
}

func checkIdentityProofRedirected(t *testing.T, gate identityProofGate) {
	t.Helper()
	*gate.reached = false
	req := httptest.NewRequest(http.MethodGet, "https://app.example/api", nil)
	req.Header.Set(types.HeaderPortalProof, identityProofTestValue)
	rec := httptest.NewRecorder()
	gate.handler.ServeHTTP(rec, req)
	if *gate.reached || rec.Code != http.StatusSeeOther {
		t.Fatalf("unauthenticated request: reached upstream = %v, status = %d; want a login redirect", *gate.reached, rec.Code)
	}
}

func TestApplicationAuthIdentityProof(t *testing.T) {
	t.Parallel()

	tunnelIdentity := applicationAuthTestIdentity()
	credential, err := IssueCredential(tunnelIdentity, "app.example", "alice", time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name      string
		cfg       Config
		wantProof []string
	}{
		{"configured", Config{IdentityHeaders: true, IdentityProof: identityProofTestValue}, []string{identityProofTestValue}},
		{"not configured", Config{IdentityHeaders: true}, nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tt.cfg.Provider = ProviderCredential
			gate := seedIdentityProofGate(t, tunnelIdentity, tt.cfg)
			checkIdentityProofAuthenticated(t, gate, credential, tt.wantProof)
			checkIdentityProofRedirected(t, gate)
		})
	}
}

func issueAllowlistCredential(t *testing.T, tunnelIdentity types.Identity, subject string) string {
	t.Helper()
	credential, err := IssueCredential(tunnelIdentity, "app.example", subject, time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return credential
}

func seedAllowlistInitialGate(t *testing.T, tunnelIdentity types.Identity) http.Handler {
	t.Helper()
	initialGate, err := New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), tunnelIdentity, Config{
		Provider:        ProviderCredential,
		Allow:           []string{"alice", "bob"},
		IdentityHeaders: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return initialGate
}

func redeemAllowlistAliceCookie(t *testing.T, initialGate http.Handler, redeemBody []byte) *http.Cookie {
	t.Helper()
	redeemReq := httptest.NewRequest(http.MethodPost, "https://app.example"+types.PathApplicationAuthRedeem, bytes.NewReader(redeemBody))
	redeemReq.Header.Set("Origin", "https://app.example")
	redeemRec := httptest.NewRecorder()
	initialGate.ServeHTTP(redeemRec, redeemReq)
	if redeemRec.Code != http.StatusOK {
		t.Fatalf("alice redeem status = %d", redeemRec.Code)
	}
	return redeemRec.Result().Cookies()[0]
}

func seedAllowlistRevokedGate(t *testing.T, tunnelIdentity types.Identity) http.Handler {
	t.Helper()
	revokedGate, err := New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), tunnelIdentity, Config{
		Provider:        ProviderCredential,
		Allow:           []string{"bob"},
		IdentityHeaders: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return revokedGate
}

func checkRevokedAllowlistRedeem(t *testing.T, revokedGate http.Handler, redeemBody []byte) {
	t.Helper()
	revokedRedeemReq := httptest.NewRequest(http.MethodPost, "https://app.example"+types.PathApplicationAuthRedeem, bytes.NewReader(redeemBody))
	revokedRedeemReq.Header.Set("Origin", "https://app.example")
	revokedRedeemRec := httptest.NewRecorder()
	revokedGate.ServeHTTP(revokedRedeemRec, revokedRedeemReq)
	if revokedRedeemRec.Code != http.StatusUnauthorized {
		t.Fatalf("revoked redeem status = %d; want 401", revokedRedeemRec.Code)
	}
}

func checkRevokedAllowlistCookie(t *testing.T, revokedGate http.Handler, aliceCookie *http.Cookie) {
	t.Helper()
	revokedCookieReq := httptest.NewRequest(http.MethodGet, "https://app.example/private", nil)
	revokedCookieReq.AddCookie(aliceCookie)
	revokedCookieRec := httptest.NewRecorder()
	revokedGate.ServeHTTP(revokedCookieRec, revokedCookieReq)
	if revokedCookieRec.Code != http.StatusSeeOther {
		t.Fatalf("revoked session status = %d; want 303", revokedCookieRec.Code)
	}
}

func checkRevokedAllowlistHeader(t *testing.T, revokedGate http.Handler, aliceCredential string) {
	t.Helper()
	revokedHeaderReq := httptest.NewRequest(http.MethodGet, "https://app.example/api", nil)
	revokedHeaderReq.Header.Set(types.HeaderAccessCredential, aliceCredential)
	revokedHeaderRec := httptest.NewRecorder()
	revokedGate.ServeHTTP(revokedHeaderRec, revokedHeaderReq)
	if revokedHeaderRec.Code != http.StatusSeeOther {
		t.Fatalf("revoked header status = %d; want 303", revokedHeaderRec.Code)
	}
}

func checkAllowlistBobAccepted(t *testing.T, revokedGate http.Handler, bobCredential string) {
	t.Helper()
	bobHeaderReq := httptest.NewRequest(http.MethodGet, "https://app.example/api", nil)
	bobHeaderReq.Header.Set(types.HeaderAccessCredential, bobCredential)
	bobHeaderRec := httptest.NewRecorder()
	revokedGate.ServeHTTP(bobHeaderRec, bobHeaderReq)
	if bobHeaderRec.Code != http.StatusNoContent {
		t.Fatalf("allowed bob header status = %d; want 204", bobHeaderRec.Code)
	}
}

func TestApplicationAuthCredentialAllowlistAndRevocation(t *testing.T) {
	tunnelIdentity := applicationAuthTestIdentity()
	aliceCredential := issueAllowlistCredential(t, tunnelIdentity, "alice")
	bobCredential := issueAllowlistCredential(t, tunnelIdentity, "bob")
	initialGate := seedAllowlistInitialGate(t, tunnelIdentity)
	redeemBody, _ := json.Marshal(applicationAuthRedeemRequest{Credential: aliceCredential})
	aliceCookie := redeemAllowlistAliceCookie(t, initialGate, redeemBody)
	revokedGate := seedAllowlistRevokedGate(t, tunnelIdentity)
	checkRevokedAllowlistRedeem(t, revokedGate, redeemBody)
	checkRevokedAllowlistCookie(t, revokedGate, aliceCookie)
	checkRevokedAllowlistHeader(t, revokedGate, aliceCredential)
	checkAllowlistBobAccepted(t, revokedGate, bobCredential)
}
func TestApplicationSessionRefusesOtherOrigins(t *testing.T) {
	t.Parallel()

	tunnelIdentity := applicationAuthTestIdentity()
	upstreamRequests := 0
	handler, err := New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamRequests++
		w.WriteHeader(http.StatusNoContent)
	}), tunnelIdentity, Config{Provider: ProviderCredential})
	if err != nil {
		t.Fatal(err)
	}
	credential := issueOriginCredential(t, tunnelIdentity)
	session := redeemOriginCookie(t, handler, credential)

	checkOriginPolicyTable(t, handler, session, &upstreamRequests)
}

func issueOriginCredential(t *testing.T, tunnelIdentity types.Identity) string {
	t.Helper()
	credential, err := IssueCredential(tunnelIdentity, "app.example", "alice", time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return credential
}

func redeemOriginCookie(t *testing.T, handler http.Handler, credential string) *http.Cookie {
	t.Helper()
	body, _ := json.Marshal(applicationAuthRedeemRequest{Credential: credential})
	redeem := httptest.NewRequest(http.MethodPost, "https://app.example"+types.PathApplicationAuthRedeem, bytes.NewReader(body))
	redeem.Header.Set("Origin", "https://app.example")
	redeemRec := httptest.NewRecorder()
	handler.ServeHTTP(redeemRec, redeem)
	if redeemRec.Code != http.StatusOK || len(redeemRec.Result().Cookies()) != 1 {
		t.Fatalf("redeem status = %d, cookies = %#v", redeemRec.Code, redeemRec.Result().Cookies())
	}
	return redeemRec.Result().Cookies()[0]
}

func upgradeOriginHeaders(origin string) http.Header {
	return http.Header{"Connection": {"Upgrade"}, "Upgrade": {"websocket"}, "Origin": {origin}}
}

func buildOriginHeader(origin string) http.Header {
	return http.Header{"Origin": {origin}}
}

func fetchSiteOriginHeaders(origin, site string) http.Header {
	return http.Header{"Origin": {origin}, "Sec-Fetch-Site": {site}}
}

func checkOriginPolicyTable(t *testing.T, handler http.Handler, session *http.Cookie, upstream *int) {
	t.Helper()
	const self, other = "https://app.example", "https://other.example"
	for _, tt := range []struct {
		name       string
		method     string
		headers    http.Header
		wantStatus int
	}{
		{"upgrade from own origin", http.MethodGet, upgradeOriginHeaders(self), http.StatusNoContent},
		{"upgrade from another origin", http.MethodGet, upgradeOriginHeaders(other), http.StatusForbidden},
		{"upgrade with another port", http.MethodGet, upgradeOriginHeaders(self + ":8443"), http.StatusForbidden},
		{"upgrade from plain http", http.MethodGet, upgradeOriginHeaders("http://app.example"), http.StatusForbidden},
		{"upgrade from opaque origin", http.MethodGet, upgradeOriginHeaders("null"), http.StatusForbidden},
		{"upgrade without origin", http.MethodGet, http.Header{"Connection": {"Upgrade"}, "Upgrade": {"websocket"}}, http.StatusNoContent},
		{"post from own origin", http.MethodPost, buildOriginHeader(self), http.StatusNoContent},
		{"post from another origin", http.MethodPost, buildOriginHeader(other), http.StatusForbidden},
		{"post from opaque origin", http.MethodPost, buildOriginHeader("null"), http.StatusForbidden},
		{"post without origin", http.MethodPost, http.Header{}, http.StatusNoContent},
		{"form post from a no-referrer page of the own origin", http.MethodPost, fetchSiteOriginHeaders("null", "same-origin"), http.StatusNoContent},
		{"form post from a no-referrer page elsewhere", http.MethodPost, fetchSiteOriginHeaders("null", "cross-site"), http.StatusForbidden},
		{"same-origin mark on a real origin", http.MethodPost, fetchSiteOriginHeaders(other, "same-origin"), http.StatusForbidden},
		{"same-origin mark on an upgrade", http.MethodGet, http.Header{"Upgrade": {"websocket"}, "Origin": {"null"}, "Sec-Fetch-Site": {"same-origin"}}, http.StatusForbidden},
		{"post from a sibling host", http.MethodPost, fetchSiteOriginHeaders(other, "same-site"), http.StatusForbidden},
		{"post from a sandboxed frame", http.MethodPost, fetchSiteOriginHeaders("null", "same-site"), http.StatusForbidden},
		{"put from another origin", http.MethodPut, buildOriginHeader(other), http.StatusForbidden},
		{"patch from another origin", http.MethodPatch, buildOriginHeader(other), http.StatusForbidden},
		{"delete from another origin", http.MethodDelete, buildOriginHeader(other), http.StatusForbidden},
		{"get from another origin", http.MethodGet, buildOriginHeader(other), http.StatusNoContent},
		{"head from another origin", http.MethodHead, buildOriginHeader(other), http.StatusNoContent},
		{"options from another origin", http.MethodOptions, buildOriginHeader(other), http.StatusNoContent},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "https://app.example/private", nil)
			req.Header = tt.headers.Clone()
			req.AddCookie(session)
			before := *upstream
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d; want %d", rec.Code, tt.wantStatus)
			}
			if reached := *upstream > before; reached != (tt.wantStatus == http.StatusNoContent) {
				t.Fatalf("upstream reached = %v with status %d", reached, rec.Code)
			}
		})
	}
}

func TestGateAnswersOnlyForHostsItHolds(t *testing.T) {
	t.Parallel()

	const canonical, alias = "app.example", "alias.example"
	now := time.Now().UTC()
	hostsWithAlias := []PublicHost{{URL: "https://" + canonical}, {URL: "https://" + alias, Since: now.Add(-time.Hour)}}
	var hosts atomic.Value
	hosts.Store(hostsWithAlias)
	tunnelIdentity := applicationAuthTestIdentity()
	handler, err := New(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), tunnelIdentity, Config{Provider: ProviderCredential, PublicHosts: func() []PublicHost { return hosts.Load().([]PublicHost) }})
	if err != nil {
		t.Fatal(err)
	}
	gate := handler.(*applicationAuth)
	checkHeldGateSessions(t, gate, now, hostsWithAlias)
	checkLostAliasRefused(t, gate, &hosts, hostsWithAlias, now)
}

func issueGateSessionSend(t *testing.T, gate *applicationAuth, host string, issuedAt, expires time.Time) func(*http.Request) {
	t.Helper()
	value, err := gate.issueSession(Principal{Provider: ProviderCredential, Subject: "alice"}, host, issuedAt, expires)
	if err != nil {
		t.Fatal(err)
	}
	return func(r *http.Request) { r.AddCookie(&http.Cookie{Name: applicationAuthCookieName, Value: value}) }
}

func serveGateRequest(gate *applicationAuth, host, path string, send func(*http.Request)) int {
	req := httptest.NewRequest(http.MethodGet, "https://"+host+path, nil)
	send(req)
	rec := httptest.NewRecorder()
	gate.ServeHTTP(rec, req)
	return rec.Code
}

func issueAliasCredential(t *testing.T, tunnelIdentity types.Identity, alias string, now time.Time) string {
	t.Helper()
	credential, err := IssueCredential(tunnelIdentity, alias, "alice", now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return credential
}

func presentGateCredential(credential string) func(*http.Request) {
	return func(r *http.Request) { r.Header.Set(types.HeaderAccessCredential, credential) }
}

func checkHeldGateSessions(t *testing.T, gate *applicationAuth, now time.Time, hostsWithAlias []PublicHost) {
	t.Helper()
	const canonical, alias = "app.example", "alias.example"
	credential := issueAliasCredential(t, applicationAuthTestIdentity(), alias, now)
	presentCredential := presentGateCredential(credential)
	longAgo := now.Add(-23 * time.Hour)
	held := hostsWithAlias[1].Since
	for _, tt := range []struct {
		name string
		host string
		send func(*http.Request)
		want int
	}{
		{"a session from this hold of the alias", alias, issueGateSessionSend(t, gate, alias, now, now.Add(time.Hour)), http.StatusNoContent},
		{"a session from the start of this hold", alias, issueGateSessionSend(t, gate, alias, held, now.Add(time.Hour)), http.StatusNoContent},
		{"a session from just before this hold", alias, issueGateSessionSend(t, gate, alias, held.Add(-time.Millisecond), now.Add(time.Hour)), http.StatusSeeOther},
		{"a session from an earlier hold of the alias", alias, issueGateSessionSend(t, gate, alias, longAgo, now.Add(time.Hour)), http.StatusSeeOther},
		{"a session too old to carry its date", alias, issueGateSessionSend(t, gate, alias, time.Unix(0, 0), now.Add(time.Hour)), http.StatusSeeOther},
		{"an old session on a host that cannot change hands", canonical, issueGateSessionSend(t, gate, canonical, longAgo, now.Add(time.Hour)), http.StatusNoContent},
		{"a credential for the alias", alias, presentCredential, http.StatusNoContent},
		{"a host the application never held", "attacker.example", issueGateSessionSend(t, gate, "attacker.example", now, now.Add(time.Hour)), http.StatusMisdirectedRequest},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := serveGateRequest(gate, tt.host, "/private", tt.send); got != tt.want {
				t.Fatalf("status = %d; want %d", got, tt.want)
			}
		})
	}
}

func checkLostAliasRefused(t *testing.T, gate *applicationAuth, hosts *atomic.Value, hostsWithAlias []PublicHost, now time.Time) {
	t.Helper()
	const canonical, alias = "app.example", "alias.example"
	hosts.Store(hostsWithAlias[:1])
	credential := issueAliasCredential(t, applicationAuthTestIdentity(), alias, now)
	for name, send := range map[string]func(*http.Request){
		"session":    issueGateSessionSend(t, gate, alias, now, now.Add(time.Hour)),
		"credential": presentGateCredential(credential),
	} {
		if got := serveGateRequest(gate, alias, "/private", send); got != http.StatusMisdirectedRequest {
			t.Fatalf("%s on a lost alias = %d; want 421", name, got)
		}
	}
	if got := serveGateRequest(gate, alias, types.PathApplicationAuthLogin, func(*http.Request) {}); got != http.StatusMisdirectedRequest {
		t.Fatalf("login page on a lost alias = %d; want 421", got)
	}
	if got := serveGateRequest(gate, canonical, "/private", issueGateSessionSend(t, gate, canonical, now, now.Add(time.Hour))); got != http.StatusNoContent {
		t.Fatalf("losing the alias touched the canonical host: %d", got)
	}
}
func loadFrontendFile(t *testing.T, name string, into any) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "frontend", "src", "lib", name))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, into); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
}

type frontendAuthRules struct {
	Allow []struct {
		Method    string `json:"method"`
		Typed     string `json:"typed"`
		Valid     bool   `json:"valid"`
		Canonical string `json:"canonical"`
	} `json:"allow"`
	Issuer []struct {
		Value string `json:"value"`
		Valid bool   `json:"valid"`
	} `json:"issuer"`
	SAMLMetadata []struct {
		Value string `json:"value"`
		Valid bool   `json:"valid"`
	} `json:"samlMetadata"`
	SMTPAddr []struct {
		Value string `json:"value"`
		Valid bool   `json:"valid"`
	} `json:"emailSMTPAddr"`
	SMTPFrom []struct {
		Value string `json:"value"`
		Valid bool   `json:"valid"`
	} `json:"emailFrom"`
	Host []struct {
		Address string `json:"address"`
		Host    string `json:"host"`
	} `json:"host"`
}

func checkFrontendAuthRulesCounts(t *testing.T, rules frontendAuthRules) {
	t.Helper()
	for name, rows := range map[string]int{
		"allow":         len(rules.Allow),
		"issuer":        len(rules.Issuer),
		"samlMetadata":  len(rules.SAMLMetadata),
		"emailSMTPAddr": len(rules.SMTPAddr),
		"emailFrom":     len(rules.SMTPFrom),
		"host":          len(rules.Host),
	} {
		if rows == 0 {
			t.Fatalf("authRuleVectors.json has no %s rows", name)
		}
	}
}

func checkFrontendAuthRulesAllowlist(t *testing.T, rules frontendAuthRules) {
	t.Helper()
	for _, row := range rules.Allow {
		got, err := normalizeAllowed(row.Method, []string{row.Typed})
		if (err == nil) != row.Valid {
			t.Errorf("%s entry %q: error = %v; the frontend says valid = %v", row.Method, row.Typed, err, row.Valid)
			continue
		}
		wantCanonical := row.Valid && row.Canonical != ""
		canonicalMismatch := len(got) != 1 || got[0] != row.Canonical
		if wantCanonical && canonicalMismatch {
			t.Errorf("%s entry %q normalizes to %q; the frontend says %q", row.Method, row.Typed, got, row.Canonical)
		}
	}
}

func checkFrontendAuthRulesIssuers(t *testing.T, rules frontendAuthRules) {
	t.Helper()
	for _, row := range rules.Issuer {
		err := Validate(Config{
			Provider:   ProviderOIDC,
			Allow:      []string{"alice@example.com"},
			OIDCConfig: OIDCConfig{OIDCIssuerURL: row.Value, OIDCClientID: "client"},
		})
		if (err == nil) != row.Valid {
			t.Errorf("issuer %q: error = %v; the frontend says valid = %v", row.Value, err, row.Valid)
		}
	}
}

func checkFrontendAuthRulesSAMLMetadata(t *testing.T, rules frontendAuthRules) {
	t.Helper()
	for _, row := range rules.SAMLMetadata {
		err := Validate(Config{
			Provider:   ProviderSAML,
			Allow:      []string{"alice@example.com"},
			SAMLConfig: SAMLConfig{SAMLMetadataURL: row.Value},
		})
		if (err == nil) != row.Valid {
			t.Errorf("metadata URL %q: error = %v; the frontend says valid = %v", row.Value, err, row.Valid)
		}
	}
}

func checkFrontendAuthRulesSMTPAddr(t *testing.T, rules frontendAuthRules) {
	t.Helper()
	for _, row := range rules.SMTPAddr {
		err := Validate(Config{
			Provider:    ProviderEmail,
			EmailList:   []string{"alice@example.com"},
			EmailConfig: EmailConfig{SMTPAddr: row.Value, SMTPFrom: "login@example.com"},
		})
		if (err == nil) != row.Valid {
			t.Errorf("SMTP address %q: error = %v; the frontend says valid = %v", row.Value, err, row.Valid)
		}
	}
}

func checkFrontendAuthRulesSMTPFrom(t *testing.T, rules frontendAuthRules) {
	t.Helper()
	for _, row := range rules.SMTPFrom {
		err := Validate(Config{
			Provider:    ProviderEmail,
			EmailList:   []string{"alice@example.com"},
			EmailConfig: EmailConfig{SMTPAddr: "smtp.example.com:587", SMTPFrom: row.Value},
		})
		if (err == nil) != row.Valid {
			t.Errorf("sender %q: error = %v; the frontend says valid = %v", row.Value, err, row.Valid)
		}
	}
}

func checkFrontendAuthRulesHosts(t *testing.T, rules frontendAuthRules) {
	t.Helper()
	for _, row := range rules.Host {
		got, err := normalizeHost(row.Address)
		if row.Host == "" {
			if err == nil {
				t.Errorf("address %q is accepted as %q; the frontend says it is unusable", row.Address, got)
			}
			continue
		}
		if err != nil || got != row.Host {
			t.Errorf("address %q = %q, %v; the frontend says %q", row.Address, got, err, row.Host)
		}
	}
}

func TestFrontendAuthRulesMatchTheGateway(t *testing.T) {
	t.Parallel()

	var rules frontendAuthRules
	loadFrontendFile(t, "authRuleVectors.json", &rules)
	checkFrontendAuthRulesCounts(t, rules)

	t.Run("allowlist entries", func(t *testing.T) {
		t.Parallel()
		checkFrontendAuthRulesAllowlist(t, rules)
	})

	t.Run("OIDC issuers", func(t *testing.T) {
		t.Parallel()
		checkFrontendAuthRulesIssuers(t, rules)
	})

	t.Run("SAML metadata URLs", func(t *testing.T) {
		t.Parallel()
		checkFrontendAuthRulesSAMLMetadata(t, rules)
	})

	t.Run("email SMTP addresses", func(t *testing.T) {
		t.Parallel()
		checkFrontendAuthRulesSMTPAddr(t, rules)
	})

	t.Run("email senders", func(t *testing.T) {
		t.Parallel()
		checkFrontendAuthRulesSMTPFrom(t, rules)
	})

	t.Run("hosts of a private link", func(t *testing.T) {
		t.Parallel()
		checkFrontendAuthRulesHosts(t, rules)
	})
}
