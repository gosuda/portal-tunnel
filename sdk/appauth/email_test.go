package appauth

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/mail"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
)

const (
	emailTestHost     = "app.example"
	emailTestFrom     = "Portal <login@portal.example>"
	emailTestSender   = "login@portal.example"
	emailTestUsername = "portal"
	emailTestPassword = "smtp-secret"
)

func emailTestConfig(smtpAddr string, allowed ...string) Config {
	return Config{
		Provider:  ProviderEmail,
		EmailList: allowed,
		EmailConfig: EmailConfig{
			SMTPAddr:     smtpAddr,
			SMTPUsername: emailTestUsername,
			SMTPPassword: emailTestPassword,
			SMTPFrom:     emailTestFrom,
		},
	}
}

func newEmailTestGate(t *testing.T, cfg Config, next http.Handler) *applicationAuth {
	t.Helper()
	cfg.PublicHosts = func() []PublicHost { return []PublicHost{{URL: "https://" + emailTestHost}, {}} }
	handler, err := New(next, applicationAuthTestIdentity(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	return handler.(*applicationAuth)
}

func postEmailJSON(handler http.Handler, host, path string, body any) *httptest.ResponseRecorder {
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "https://"+host+path, bytes.NewReader(data))
	req.Header.Set("Origin", "https://"+host)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func emailLinkToken(t *testing.T, message smtpTestMessage) string {
	t.Helper()
	const marker = "#email_token="
	_, rest, ok := strings.Cut(message.data, marker)
	if !ok {
		t.Fatalf("mail has no login link:\n%s", message.data)
	}
	token, _, _ := strings.Cut(rest, "\n")
	return strings.TrimSpace(token)
}

type emailLoginFixture struct {
	server       *smtpTestServer
	gate         *applicationAuth
	upstreamUser *string
	upstreamAuth *string
}

func seedEmailLoginFixture(t *testing.T) *emailLoginFixture {
	t.Helper()
	server := newSMTPTestServer(t, emailTestUsername, emailTestPassword)
	fixture := &emailLoginFixture{server: server, upstreamUser: new(string), upstreamAuth: new(string)}
	cfg := emailTestConfig(server.addr, "alice@example.com")
	cfg.IdentityHeaders = true
	fixture.gate = newEmailTestGate(t, cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*fixture.upstreamUser, *fixture.upstreamAuth = r.Header.Get(types.HeaderPortalUser), r.Header.Get(types.HeaderPortalAuth)
		w.WriteHeader(http.StatusNoContent)
	}))
	return fixture
}
func requestEmailLoginMessage(t *testing.T, fixture *emailLoginFixture) smtpTestMessage {
	t.Helper()
	rec := postEmailJSON(fixture.gate, emailTestHost, types.PathApplicationAuthEmailRequest, applicationAuthEmailRequest{Email: " Alice@Example.com ", Next: "/inbox?view=all"})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("request status = %d, body = %s", rec.Code, rec.Body.String())
	}
	message := fixture.server.next(t)
	if message.from != emailTestSender || !slices.Equal(message.to, []string{"alice@example.com"}) {
		t.Fatalf("envelope = %q -> %q", message.from, message.to)
	}
	return message
}
func extractEmailLoginToken(t *testing.T, message smtpTestMessage) string {
	t.Helper()
	parsed, err := mail.ReadMessage(strings.NewReader(message.data))
	if err != nil {
		t.Fatal(err)
	}
	if got := parsed.Header.Get("From"); got != `"Portal" <login@portal.example>` {
		t.Fatalf("From = %q", got)
	}
	if _, ok := parsed.Header["To"]; ok || strings.Contains(strings.ToLower(message.data), "alice@example.com") {
		t.Fatalf("the address the visitor typed is part of the mail:\n%s", message.data)
	}
	if !strings.Contains(message.data, "https://"+emailTestHost+types.PathApplicationAuthLogin+"#email_token=") {
		t.Fatalf("mail does not link to the login page of %s:\n%s", emailTestHost, message.data)
	}
	token := emailLinkToken(t, message)
	if raw, err := base64.RawURLEncoding.DecodeString(token); err != nil || len(raw) != 32 {
		t.Fatalf("token %q is not 256 random bits", token)
	}
	return token
}
func redeemEmailLoginToken(t *testing.T, fixture *emailLoginFixture, token string) []*http.Cookie {
	t.Helper()
	rec := postEmailJSON(fixture.gate, emailTestHost, types.PathApplicationAuthEmailRedeem, applicationAuthEmailRedeemRequest{Token: token})
	if rec.Code != http.StatusOK {
		t.Fatalf("redeem status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var redeemed map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&redeemed); err != nil {
		t.Fatal(err)
	}
	if redeemed["subject"] != "alice@example.com" || redeemed["next"] != "/inbox?view=all" {
		t.Fatalf("redeem = %v", redeemed)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != applicationAuthCookieName {
		t.Fatalf("redeem cookies = %v", cookies)
	}
	return cookies
}
func checkEmailLoginSession(t *testing.T, fixture *emailLoginFixture, cookies []*http.Cookie) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "https://"+emailTestHost+"/inbox", nil)
	req.AddCookie(cookies[0])
	rec := httptest.NewRecorder()
	fixture.gate.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent || *fixture.upstreamUser != "alice@example.com" || *fixture.upstreamAuth != ProviderEmail {
		t.Fatalf("session request = %d as %q via %q", rec.Code, *fixture.upstreamUser, *fixture.upstreamAuth)
	}
}
func checkEmailLoginReuseRefused(t *testing.T, fixture *emailLoginFixture, token string) {
	t.Helper()
	rec := postEmailJSON(fixture.gate, emailTestHost, types.PathApplicationAuthEmailRedeem, applicationAuthEmailRedeemRequest{Token: token})
	if rec.Code != http.StatusUnauthorized || len(rec.Result().Cookies()) != 0 {
		t.Fatalf("second redeem status = %d with cookies %v; want 401 without a session", rec.Code, rec.Result().Cookies())
	}
}
func TestEmailLoginLinkCreatesSessionOnce(t *testing.T) {
	t.Parallel()
	fixture := seedEmailLoginFixture(t)
	message := requestEmailLoginMessage(t, fixture)
	token := extractEmailLoginToken(t, message)
	cookies := redeemEmailLoginToken(t, fixture, token)
	checkEmailLoginSession(t, fixture, cookies)
	checkEmailLoginReuseRefused(t, fixture, token)
}

func requestEmailAlikeAnswers(t *testing.T, gate *applicationAuth) []*httptest.ResponseRecorder {
	t.Helper()
	var answers []*httptest.ResponseRecorder
	for _, address := range []string{"mallory@evil.example", "alice@example.com", "alice@example.com", "bob@team.example"} {
		answers = append(answers, postEmailJSON(gate, emailTestHost, types.PathApplicationAuthEmailRequest, applicationAuthEmailRequest{Email: address}))
	}
	return answers
}
func checkEmailAnswersUniform(t *testing.T, answers []*httptest.ResponseRecorder) {
	t.Helper()
	for i, rec := range answers {
		first := answers[0]
		if rec.Code != first.Code || rec.Body.String() != first.Body.String() ||
			rec.Header().Get("Content-Type") != first.Header().Get("Content-Type") ||
			rec.Header().Get("Cache-Control") != first.Header().Get("Cache-Control") {
			t.Fatalf("answer %d = %d %q %v; answer 0 = %d %q %v", i, rec.Code, rec.Body.String(), rec.Header(), first.Code, first.Body.String(), first.Header())
		}
	}
	if answers[0].Code != http.StatusAccepted {
		t.Fatalf("status = %d; want 202", answers[0].Code)
	}
}
func checkEmailAlikeRecipients(t *testing.T, server *smtpTestServer) {
	t.Helper()
	var recipients []string
	for range 2 {
		recipients = append(recipients, server.next(t).to...)
	}
	slices.Sort(recipients)
	if !slices.Equal(recipients, []string{"alice@example.com", "bob@team.example"}) {
		t.Fatalf("recipients = %q", recipients)
	}
	server.expectNoMore(t)
}
func TestEmailRequestAnswersAlikeForEveryAddress(t *testing.T) {
	t.Parallel()
	server := newSMTPTestServer(t, emailTestUsername, emailTestPassword)
	gate := newEmailTestGate(t, emailTestConfig(server.addr, "alice@example.com", "@team.example"), http.NotFoundHandler())
	answers := requestEmailAlikeAnswers(t, gate)
	checkEmailAnswersUniform(t, answers)
	checkEmailAlikeRecipients(t, server)
}

func TestEmailRequestRefusesHeaderInjection(t *testing.T) {
	t.Parallel()

	server := newSMTPTestServer(t, emailTestUsername, emailTestPassword)
	gate := newEmailTestGate(t, emailTestConfig(server.addr, "alice@example.com", "@example.com"), http.NotFoundHandler())

	for _, body := range []any{
		map[string]string{"email": "alice@example.com", "from": "ceo@example.com"},
		applicationAuthEmailRequest{Email: "alice@example.com\r\nBcc: mallory@evil.example"},
		applicationAuthEmailRequest{Email: "alice@example.com\nSubject: hi"},
		applicationAuthEmailRequest{Email: "Alice <alice@example.com>"},
	} {
		if rec := postEmailJSON(gate, emailTestHost, types.PathApplicationAuthEmailRequest, body); rec.Code != http.StatusBadRequest {
			t.Fatalf("request %v status = %d; want 400", body, rec.Code)
		}
	}
	server.expectNoMore(t)

	if _, err := emailLoginMessage(mail.Address{Address: emailTestSender}, emailTestHost+"\r\nBcc: mallory@evil.example", "token", time.Now()); !errors.Is(err, errEmailHeaderHasLineBreak) {
		t.Fatalf("emailLoginMessage error = %v; want a line break refusal", err)
	}
}

func TestNormalizeVisitorEmail(t *testing.T) {
	t.Parallel()

	for raw, want := range map[string]string{
		"alice@example.com":                       "alice@example.com",
		" Alice@Example.COM ":                     "alice@example.com",
		"first.last+tag@example.co":               "first.last+tag@example.co",
		"":                                        "",
		"alice":                                   "",
		"@example.com":                            "",
		"Alice <alice@example.com>":               "",
		"<alice@example.com>":                     "",
		`"alice"@example.com`:                     "",
		"alice@example.com (work)":                "",
		"alice@example.com\r\n":                   "alice@example.com",
		"alice\r\n@example.com":                   "",
		"a, b@example.com":                        "",
		"alice@exämple.com":                       "",
		"alice@ex\u212aample.com":                 "",
		"attacker%evil.example@team.example":      "",
		"evil.example!attacker@team.example":      "",
		"sub:alice@example.com":                   "",
		strings.Repeat("a", 250) + "@example.com": "",
	} {
		got, err := normalizeVisitorEmail(raw)
		if got != want || (err == nil) != (want != "") {
			t.Errorf("normalizeVisitorEmail(%q) = %q, %v; want %q", raw, got, err, want)
		}
	}
}

func checkEmailAttackerHostRefused(t *testing.T, gate *applicationAuth) {
	t.Helper()
	rec := postEmailJSON(gate, "attacker.example", types.PathApplicationAuthEmailRequest, applicationAuthEmailRequest{Email: "alice@example.com"})
	if rec.Code != http.StatusMisdirectedRequest {
		t.Fatalf("status = %d; want 421", rec.Code)
	}
}
func checkEmailCanonicalHostAccepted(t *testing.T, gate *applicationAuth, server *smtpTestServer) {
	t.Helper()
	rec := postEmailJSON(gate, emailTestHost+":443", types.PathApplicationAuthEmailRequest, applicationAuthEmailRequest{Email: "alice@example.com"})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d; want 202", rec.Code)
	}
	if message := server.next(t); !strings.Contains(message.data, "https://"+emailTestHost+types.PathApplicationAuthLogin+"#") {
		t.Fatalf("link does not use the canonical host:\n%s", message.data)
	}
}
func checkEmailOfflineHostRefused(t *testing.T, server *smtpTestServer) {
	t.Helper()
	offline := emailTestConfig(server.addr, "alice@example.com")
	offline.PublicHosts = func() []PublicHost { return nil }
	handler, err := New(http.NotFoundHandler(), applicationAuthTestIdentity(), offline)
	if err != nil {
		t.Fatal(err)
	}
	if rec := postEmailJSON(handler, emailTestHost, types.PathApplicationAuthEmailRequest, applicationAuthEmailRequest{Email: "alice@example.com"}); rec.Code != http.StatusMisdirectedRequest {
		t.Fatalf("status without public hosts = %d; want 421", rec.Code)
	}
	server.expectNoMore(t)
}
func TestEmailRequestRefusesHostThatIsNotPublic(t *testing.T) {
	t.Parallel()
	server := newSMTPTestServer(t, emailTestUsername, emailTestPassword)
	gate := newEmailTestGate(t, emailTestConfig(server.addr, "alice@example.com"), http.NotFoundHandler())
	checkEmailAttackerHostRefused(t, gate)
	checkEmailCanonicalHostAccepted(t, gate, server)
	checkEmailOfflineHostRefused(t, server)
}

func TestEmailGateRequiresPublicHosts(t *testing.T) {
	t.Parallel()

	if _, err := New(http.NotFoundHandler(), applicationAuthTestIdentity(), emailTestConfig("127.0.0.1:25", "alice@example.com")); !errors.Is(err, errEmailRequiresPublicHosts) {
		t.Fatalf("New without PublicHosts = %v; want %v", err, errEmailRequiresPublicHosts)
	}
}

func TestEmailMailHoldsOneLink(t *testing.T) {
	t.Parallel()

	message, err := emailLoginMessage(mail.Address{Address: emailTestSender}, emailTestHost, "token", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	headers, body, ok := strings.Cut(string(message), "\r\n\r\n")
	if !ok || !strings.Contains(headers, "Subject: Sign in to "+emailTestHost) {
		t.Fatalf("subject does not name the host:\n%s", headers)
	}
	if got := strings.Count(body, emailTestHost); got != 1 || !strings.Contains(body, "https://"+emailTestHost+types.PathApplicationAuthLogin+"#email_token=token") {
		t.Fatalf("body names the host %d times, want only in the login link:\n%s", got, body)
	}
}

func checkSingleLinkFirstRedeem(t *testing.T, e *emailAuthenticator, now time.Time) {
	t.Helper()
	token := e.issue("alice@example.com", true, emailTestHost, "/next", now)
	if email, next, ok := e.redeem(token, emailTestHost, time.Time{}, now.Add(emailLinkTTL-time.Second)); !ok || email != "alice@example.com" || next != "/next" {
		t.Fatalf("redeem = %q, %q, %v", email, next, ok)
	}
	if _, _, ok := e.redeem(token, emailTestHost, time.Time{}, now); ok {
		t.Fatal("a used link worked again")
	}
}
func checkSingleLinkExpiry(t *testing.T, e *emailAuthenticator, now time.Time) {
	t.Helper()
	token := e.issue("bob@example.com", true, emailTestHost, "/", now)
	if _, _, ok := e.redeem(token, emailTestHost, time.Time{}, now.Add(emailLinkTTL)); ok {
		t.Fatal("an expired link worked")
	}
}
func checkSingleLinkHost(t *testing.T, e *emailAuthenticator, now time.Time) {
	t.Helper()
	token := e.issue("carol@example.com", true, emailTestHost, "/", now)
	if _, _, ok := e.redeem(token, "other.example", time.Time{}, now); ok {
		t.Fatal("a link worked at another host")
	}
	if _, _, ok := e.redeem(token, emailTestHost, time.Time{}, now); ok {
		t.Fatal("a link tried at another host still worked")
	}
	if _, _, ok := e.redeem("not-a-token", emailTestHost, time.Time{}, now); ok {
		t.Fatal("an unknown token worked")
	}
}
func TestEmailLinkIsSingleUseAndExpires(t *testing.T) {
	t.Parallel()
	e := newEmailAuthenticator(applicationAuthSettings{emailSMTPAddr: "127.0.0.1:25"})
	now := time.Now().UTC()
	checkSingleLinkFirstRedeem(t, e, now)
	checkSingleLinkExpiry(t, e, now)
	checkSingleLinkHost(t, e, now)
}

func TestEmailRequestRefusesARoutedAddress(t *testing.T) {
	t.Parallel()

	server := newSMTPTestServer(t, emailTestUsername, emailTestPassword)
	gate := newEmailTestGate(t, emailTestConfig(server.addr, "@team.example"), http.NotFoundHandler())
	for _, address := range []string{"attacker%evil.example@team.example", "evil.example!attacker@team.example"} {
		if rec := postEmailJSON(gate, emailTestHost, types.PathApplicationAuthEmailRequest, applicationAuthEmailRequest{Email: address}); rec.Code != http.StatusBadRequest {
			t.Fatalf("request for %s status = %d; want 400", address, rec.Code)
		}
	}
	server.expectNoMore(t)
}

func TestEmailEndpointsRefuseAnotherOrigin(t *testing.T) {
	t.Parallel()

	server := newSMTPTestServer(t, emailTestUsername, emailTestPassword)
	gate := newEmailTestGate(t, emailTestConfig(server.addr, "alice@example.com", "bob@example.com"), http.NotFoundHandler())
	post := func(path string, body any) int {
		data, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, "https://"+emailTestHost+path, bytes.NewReader(data))
		req.Header.Set("Origin", "https://attacker.example")
		rec := httptest.NewRecorder()
		gate.ServeHTTP(rec, req)
		return rec.Code
	}

	if code := post(types.PathApplicationAuthEmailRequest, applicationAuthEmailRequest{Email: "alice@example.com"}); code != http.StatusForbidden {
		t.Fatalf("request status = %d; want 403", code)
	}
	server.expectNoMore(t)

	token := gate.email.issue("bob@example.com", true, emailTestHost, "/", time.Now().UTC())
	<-gate.email.sendSlots
	if code := post(types.PathApplicationAuthEmailRedeem, applicationAuthEmailRedeemRequest{Token: token}); code != http.StatusForbidden {
		t.Fatalf("redeem status = %d; want 403", code)
	}
	if rec := postEmailJSON(gate, emailTestHost, types.PathApplicationAuthEmailRedeem, applicationAuthEmailRedeemRequest{Token: token}); rec.Code != http.StatusOK {
		t.Fatalf("same-origin redeem status = %d; want 200", rec.Code)
	}
}

func TestEmailLinkReturnsOnlyToLocalPaths(t *testing.T) {
	t.Parallel()

	server := newSMTPTestServer(t, emailTestUsername, emailTestPassword)
	gate := newEmailTestGate(t, emailTestConfig(server.addr, "@example.com"), http.NotFoundHandler())
	for i, next := range []string{"https://evil.example/", "//evil.example/", "/\\evil.example", "/\t/evil.example"} {
		email := fmt.Sprintf("user%d@example.com", i)
		postEmailJSON(gate, emailTestHost, types.PathApplicationAuthEmailRequest, applicationAuthEmailRequest{Email: email, Next: next})
		rec := postEmailJSON(gate, emailTestHost, types.PathApplicationAuthEmailRedeem, applicationAuthEmailRedeemRequest{Token: emailLinkToken(t, server.next(t))})
		var redeemed map[string]string
		if err := json.Unmarshal(rec.Body.Bytes(), &redeemed); err != nil || rec.Code != http.StatusOK {
			t.Fatalf("redeem = %d, %v", rec.Code, err)
		}
		if redeemed["next"] != "/" {
			t.Fatalf("next %q returned %q; want /", next, redeemed["next"])
		}
	}
}

func checkValidEmailSettings(t *testing.T, valid Config) {
	t.Helper()
	settings, err := resolveApplicationAuthConfig(valid)
	if err != nil {
		t.Fatal(err)
	}
	want := applicationAuthSettings{
		provider:          ProviderEmail,
		allowed:           []string{"alice@example.com", "@team.example"},
		emailSMTPAddr:     "smtp.example:587",
		emailSMTPUsername: emailTestUsername,
		emailSMTPPassword: emailTestPassword,
		emailFrom:         mail.Address{Name: "Portal", Address: emailTestSender},
	}
	if !reflect.DeepEqual(settings, want) {
		t.Fatalf("settings = %+v; want %+v", settings, want)
	}
}
func checkInvalidEmailSettings(t *testing.T, name string, change func(*Config), wantErr error) {
	t.Helper()
	cfg := emailTestConfig("smtp.example:587", "alice@example.com")
	change(&cfg)
	if _, err := resolveApplicationAuthConfig(cfg); !errors.Is(err, wantErr) {
		t.Errorf("%s: error = %v; want %v", name, err, wantErr)
	}
}
func TestResolveEmailApplicationAuthConfig(t *testing.T) {
	t.Parallel()
	valid := emailTestConfig("smtp.example:587", "Alice@Example.com", "@team.example")
	checkValidEmailSettings(t, valid)
	for name, tc := range map[string]struct {
		change  func(*Config)
		wantErr error
	}{
		"no allowlist":           {func(c *Config) { c.EmailList = nil }, errEmailRequiresEmailList},
		"domain with a dot":      {func(c *Config) { c.EmailList = []string{"@example.com."} }, errEmailAddressIsInvalid},
		"domain with a comma":    {func(c *Config) { c.EmailList = []string{"@team.example,"} }, errEmailAddressIsInvalid},
		"subject entry":          {func(c *Config) { c.EmailList = []string{"sub:alice"} }, errEmailAllowsNoSubjectEntries},
		"no smtp address":        {func(c *Config) { c.SMTPAddr = "" }, errSMTPAddrIsRequired},
		"no smtp port":           {func(c *Config) { c.SMTPAddr = "smtp.example" }, errSMTPAddrMustHostPort},
		"smtp port 0":            {func(c *Config) { c.SMTPAddr = "smtp.example:0" }, errSMTPAddrMustHostPort},
		"smtp port out of range": {func(c *Config) { c.SMTPAddr = "smtp.example:65536" }, errSMTPAddrMustHostPort},
		"no sender":              {func(c *Config) { c.SMTPFrom = "" }, errSMTPFromIsRequired},
		"two senders":            {func(c *Config) { c.SMTPFrom = "a@example.com, b@example.com" }, errSMTPFromMustOneAddress},
		"sender with line break": {func(c *Config) { c.SMTPFrom = "a@example.com\r\nBcc: b@example.com" }, errSMTPFromMustOneAddress},
		"username only":          {func(c *Config) { c.SMTPPassword = "" }, errEmailSMTPCredentialsArePaired},
		"password only":          {func(c *Config) { c.SMTPUsername = "" }, errEmailSMTPCredentialsArePaired},
		"settings of another provider": {func(c *Config) {
			c.Provider, c.EmailList = ProviderCredential, nil
		}, errEmailSettingsRequireEmailApplicationAuth},
	} {
		checkInvalidEmailSettings(t, name, tc.change, tc.wantErr)
	}
}

func TestAllowlistKeys(t *testing.T) {
	t.Parallel()

	oidc := OIDCConfig{OIDCIssuerURL: "https://issuer.example", OIDCClientID: "portal"}
	saml := SAMLConfig{SAMLMetadataURL: "https://idp.example/metadata"}
	smtp := EmailConfig{SMTPAddr: "smtp.example:587", SMTPFrom: emailTestSender}
	list := []string{"Alice@Example.com"}
	for name, tc := range map[string]struct {
		cfg     Config
		wantErr error
	}{
		"oidc reads the email list":       {Config{Provider: ProviderOIDC, EmailList: list, OIDCConfig: oidc}, nil},
		"oidc keeps its released key":     {Config{Provider: ProviderOIDC, Allow: list, OIDCConfig: oidc}, nil},
		"saml reads the email list":       {Config{Provider: ProviderSAML, EmailList: list, SAMLConfig: saml}, nil},
		"saml keeps its released key":     {Config{Provider: ProviderSAML, Allow: list, SAMLConfig: saml}, nil},
		"email reads the email list":      {Config{Provider: ProviderEmail, EmailList: list, EmailConfig: smtp}, nil},
		"email has no released key":       {Config{Provider: ProviderEmail, Allow: list, EmailConfig: smtp}, errEmailProviderTakesEmailList},
		"credential cannot read the list": {Config{Provider: ProviderCredential, EmailList: list}, errEmailListRequiresEmailProvider},
		"siwe cannot read the list":       {Config{Provider: ProviderSIWE, EmailList: list}, errEmailListRequiresEmailProvider},
		"both keys":                       {Config{Provider: ProviderOIDC, Allow: list, EmailList: list, OIDCConfig: oidc}, errAllowlistIsSetTwice},
	} {
		settings, err := resolveApplicationAuthConfig(tc.cfg)
		if !errors.Is(err, tc.wantErr) {
			t.Errorf("%s: error = %v; want %v", name, err, tc.wantErr)
		}
		if tc.wantErr == nil && !slices.Equal(settings.allowed, []string{"alice@example.com"}) {
			t.Errorf("%s: allowed = %v", name, settings.allowed)
		}
	}

	normalized, err := Config{Provider: "OIDC", EmailList: list}.Normalize()
	if err != nil || !slices.Equal(normalized.EmailList, []string{"alice@example.com"}) {
		t.Fatalf("Normalize = %v, %v", normalized.EmailList, err)
	}
}
