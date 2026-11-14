package appauth

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/mail"
	"net/textproto"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
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

type smtpTestServer struct {
	addr       string
	username   string
	password   string
	messages   chan smtpTestMessage
	rcptReply  string
	dataReply  string
	dropAtQuit bool
	helloReply string
	startTLS   *tls.Config
}

type smtpTestMessage struct {
	from string
	to   []string
	data string
}

func newSMTPTestServer(t *testing.T, username, password string) *smtpTestServer {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	server := &smtpTestServer{addr: listener.Addr().String(), username: username, password: password, messages: make(chan smtpTestMessage, 64)}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go server.serve(conn)
		}
	}()
	return server
}

type serveSMTPSession struct {
	server   *smtpTestServer
	conn     net.Conn
	text     *textproto.Conn
	signedIn bool
	message  smtpTestMessage
}

func newServeSMTPSession(server *smtpTestServer, conn net.Conn) *serveSMTPSession {
	return &serveSMTPSession{server: server, conn: conn, text: textproto.NewConn(conn), signedIn: server.username == ""}
}
func (c *serveSMTPSession) serveSMTPSessionGreet() bool {
	return c.text.PrintfLine("%s", "220 smtp.test ESMTP") == nil
}
func (c *serveSMTPSession) serveSMTPSessionNext() (string, string, bool) {
	line, err := c.text.ReadLine()
	if err != nil {
		return "", "", false
	}
	verb, arg, _ := strings.Cut(line, " ")
	return strings.ToUpper(verb), arg, true
}
func (c *serveSMTPSession) serveSMTPSessionAnswerHelo() {
	if c.server.helloReply != "" {
		_ = c.text.PrintfLine("%s", c.server.helloReply)
		return
	}
	_ = c.text.PrintfLine("%s", "250-smtp.test")
	if c.server.startTLS != nil {
		_ = c.text.PrintfLine("%s", "250-STARTTLS")
	}
	_ = c.text.PrintfLine("%s", "250 AUTH PLAIN")
}
func (c *serveSMTPSession) serveSMTPSessionAnswerAuth(arg string) {
	_, encoded, _ := strings.Cut(arg, " ")
	credentials, _ := base64.StdEncoding.DecodeString(encoded)
	if string(credentials) != "\x00"+c.server.username+"\x00"+c.server.password {
		_ = c.text.PrintfLine("%s", "535 5.7.8 authentication failed")
		return
	}
	c.signedIn = true
	_ = c.text.PrintfLine("%s", "235 2.7.0 authenticated")
}
func (c *serveSMTPSession) serveSMTPSessionAnswerMail(arg string) {
	if !c.signedIn {
		_ = c.text.PrintfLine("%s", "530 5.7.0 authentication required")
		return
	}
	c.message = smtpTestMessage{from: strings.TrimSuffix(strings.TrimPrefix(arg, "FROM:<"), ">")}
	_ = c.text.PrintfLine("%s", "250 OK")
}
func (c *serveSMTPSession) serveSMTPSessionAnswerRcpt(arg string) {
	if c.server.rcptReply != "" {
		_ = c.text.PrintfLine("%s", c.server.rcptReply)
		return
	}
	c.message.to = append(c.message.to, strings.TrimSuffix(strings.TrimPrefix(arg, "TO:<"), ">"))
	_ = c.text.PrintfLine("%s", "250 OK")
}
func (c *serveSMTPSession) serveSMTPSessionAnswerData() bool {
	_ = c.text.PrintfLine("%s", "354 send the message")
	data, err := c.text.ReadDotBytes()
	if err != nil {
		return false
	}
	if c.server.dataReply != "" {
		_ = c.text.PrintfLine("%s", c.server.dataReply)
		return true
	}
	c.message.data = string(data)
	c.server.messages <- c.message
	_ = c.text.PrintfLine("%s", "250 OK")
	return true
}
func (c *serveSMTPSession) serveSMTPSessionAnswerQuit() {
	if !c.server.dropAtQuit {
		_ = c.text.PrintfLine("%s", "221 bye")
	}
}
func (c *serveSMTPSession) serveSMTPSessionDispatch(verb string, arg string) bool {
	switch verb {
	case "EHLO", "HELO":
		c.serveSMTPSessionAnswerHelo()
		return true
	case "STARTTLS":
		_ = c.text.PrintfLine("%s", "220 go ahead")
		_ = tls.Server(c.conn, c.server.startTLS).Handshake()
		return false
	case "AUTH":
		c.serveSMTPSessionAnswerAuth(arg)
		return true
	case "MAIL":
		c.serveSMTPSessionAnswerMail(arg)
		return true
	case "RCPT":
		c.serveSMTPSessionAnswerRcpt(arg)
		return true
	case "DATA":
		return c.serveSMTPSessionAnswerData()
	case "QUIT":
		c.serveSMTPSessionAnswerQuit()
		return false
	default:
		_ = c.text.PrintfLine("%s", "502 command not implemented")
		return true
	}
}
func (s *smtpTestServer) serve(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	session := newServeSMTPSession(s, conn)
	if !session.serveSMTPSessionGreet() {
		return
	}
	for {
		verb, arg, ok := session.serveSMTPSessionNext()
		if !ok {
			return
		}
		if !session.serveSMTPSessionDispatch(verb, arg) {
			return
		}
	}
}

func (s *smtpTestServer) next(t *testing.T) smtpTestMessage {
	t.Helper()
	select {
	case message := <-s.messages:
		return message
	case <-time.After(5 * time.Second):
		t.Fatal("no mail arrived")
		return smtpTestMessage{}
	}
}

func (s *smtpTestServer) expectNoMore(t *testing.T) {
	t.Helper()
	select {
	case message := <-s.messages:
		t.Fatalf("unexpected mail to %v", message.to)
	case <-time.After(200 * time.Millisecond):
	}
}
func newEmailTestAuthenticator(t *testing.T, addr string) *emailAuthenticator {
	t.Helper()
	settings, err := resolveApplicationAuthConfig(emailTestConfig(addr, "bob@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	return newEmailAuthenticator(settings)
}

func TestEmailDeliverKeepsTheRecipientOutOfItsError(t *testing.T) {
	t.Parallel()

	for name, change := range map[string]func(*smtpTestServer){
		"RCPT": func(s *smtpTestServer) { s.rcptReply = "550 5.1.1 <bob@example.com>: Recipient address rejected" },
		"DATA": func(s *smtpTestServer) { s.dataReply = "550 5.7.1 <bob@example.com>: message refused" },
	} {
		server := newSMTPTestServer(t, emailTestUsername, emailTestPassword)
		change(server)
		err := newEmailTestAuthenticator(t, server.addr).deliver(context.Background(), "bob@example.com", []byte("Subject: hi\r\n\r\nhi\r\n"))
		if err == nil || !strings.Contains(err.Error(), "550") || strings.Contains(err.Error(), "bob") {
			t.Errorf("%s: deliver error = %v; want the code without the address", name, err)
		}
	}
}

func TestEmailDeliverSurvivesAFailedQuit(t *testing.T) {
	t.Parallel()

	server := newSMTPTestServer(t, emailTestUsername, emailTestPassword)
	server.dropAtQuit = true
	if err := newEmailTestAuthenticator(t, server.addr).deliver(context.Background(), "bob@example.com", []byte("Subject: hi\r\n\r\nhi\r\n")); err != nil {
		t.Fatalf("deliver = %v", err)
	}
	server.next(t)
}

func TestEmailPortNumberPicksTheTransport(t *testing.T) {
	t.Parallel()

	for addr, want := range map[string]bool{
		"smtp.example.com:465":  true,
		"smtp.example.com:0465": true,
		"smtp.example.com:+465": true,
		"smtp.example.com:587":  false,
	} {
		if got := newEmailAuthenticator(applicationAuthSettings{emailSMTPAddr: addr}).implicitTLS; got != want {
			t.Errorf("%s: implicit TLS = %v; want %v", addr, got, want)
		}
	}
}

func TestEmailCheckSurvivesAFailedQuit(t *testing.T) {
	t.Parallel()

	server := newSMTPTestServer(t, emailTestUsername, emailTestPassword)
	server.dropAtQuit = true
	if err := newEmailTestAuthenticator(t, server.addr).check(context.Background()); err != nil {
		t.Fatalf("check = %v", err)
	}
}

func TestEmailCheckReportsARefusedHello(t *testing.T) {
	t.Parallel()

	server := newSMTPTestServer(t, emailTestUsername, emailTestPassword)
	server.helloReply = "421 4.3.2 try later"
	e := newEmailTestAuthenticator(t, server.addr)
	e.smtpHost = "smtp.test"
	err := e.check(context.Background())
	if err == nil || errors.Is(err, errEmailSMTPOffersNoSTARTTLS) || !strings.Contains(err.Error(), "421") {
		t.Fatalf("check = %v; want the server's refusal", err)
	}
}

func TestEmailRefusesAnUntrustedCertificate(t *testing.T) {
	t.Parallel()

	untrusted := httptest.NewUnstartedServer(http.NotFoundHandler())
	untrusted.StartTLS()
	t.Cleanup(untrusted.Close)
	var refused *tls.CertificateVerificationError

	implicit := newEmailTestAuthenticator(t, untrusted.Listener.Addr().String())
	implicit.implicitTLS = true
	if err := implicit.check(context.Background()); !errors.As(err, &refused) {
		t.Fatalf("implicit TLS check = %v; want a certificate refusal", err)
	}

	server := newSMTPTestServer(t, emailTestUsername, emailTestPassword)
	server.startTLS = &tls.Config{Certificates: untrusted.TLS.Certificates, MinVersion: tls.VersionTLS12}
	starttls := newEmailTestAuthenticator(t, server.addr)
	starttls.smtpHost = "smtp.test"
	if err := starttls.check(context.Background()); !errors.As(err, &refused) {
		t.Fatalf("STARTTLS check = %v; want a certificate refusal", err)
	}
}
func TestCheckEmailProviderSignsInWithoutSending(t *testing.T) {
	t.Parallel()

	server := newSMTPTestServer(t, emailTestUsername, emailTestPassword)
	ctx := context.Background()
	if err := Check(ctx, emailTestConfig(server.addr, "alice@example.com")); err != nil {
		t.Fatalf("check = %v", err)
	}
	wrong := emailTestConfig(server.addr, "alice@example.com")
	wrong.SMTPPassword = "wrong-smtp-secret"
	err := Check(ctx, wrong)
	if err == nil {
		t.Fatal("check with a wrong password passed")
	}
	if strings.Contains(err.Error(), wrong.SMTPPassword) {
		t.Fatalf("check error %q shows the password", err)
	}
	server.expectNoMore(t)
}

func TestEmailRefusesPlaintextToARemoteServer(t *testing.T) {
	t.Parallel()

	server := newSMTPTestServer(t, emailTestUsername, emailTestPassword)
	for _, name := range []string{"smtp.example", "127.0.0.2"} {
		e := newEmailAuthenticator(applicationAuthSettings{
			emailSMTPAddr:     server.addr,
			emailSMTPUsername: emailTestUsername,
			emailSMTPPassword: emailTestPassword,
		})
		e.smtpHost = name
		if err := e.check(context.Background()); !errors.Is(err, errEmailSMTPOffersNoSTARTTLS) {
			t.Fatalf("check as %s = %v; want a STARTTLS refusal", name, err)
		}
	}
}

type logLines chan string

func (l logLines) Write(line []byte) (int, error) {
	l <- string(line)
	return len(line), nil
}

func TestEmailFailureLogsNoSecret(t *testing.T) {
	const secret = "smtp-password-that-must-stay-out-of-the-log"
	lines := make(logLines, 8)
	previous := log.Logger
	log.Logger = zerolog.New(lines)
	t.Cleanup(func() { log.Logger = previous })

	server := newSMTPTestServer(t, emailTestUsername, "another-password")
	cfg := emailTestConfig(server.addr, "alice@example.com")
	cfg.SMTPPassword = secret
	gate := newEmailTestGate(t, cfg, http.NotFoundHandler())
	if rec := postEmailJSON(gate, emailTestHost, types.PathApplicationAuthEmailRequest, applicationAuthEmailRequest{Email: "alice@example.com"}); rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d; want 202", rec.Code)
	}
	select {
	case line := <-lines:
		if !strings.Contains(line, "email login link not sent") || strings.Contains(line, secret) {
			t.Fatalf("log line = %s", line)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the refused send was not logged")
	}
}
func TestEmailLinkIsRefusedAtAHostThatIsNoLongerPublic(t *testing.T) {
	t.Parallel()

	const alias = "alias.example"
	now := time.Now().UTC()
	var public atomic.Value
	public.Store([]PublicHost{{URL: "https://" + emailTestHost}, {URL: "https://" + alias, Since: now.Add(-time.Hour)}})
	cfg := emailTestConfig("127.0.0.1:25", "alice@example.com")
	cfg.PublicHosts = func() []PublicHost { return public.Load().([]PublicHost) }
	handler, err := New(http.NotFoundHandler(), applicationAuthTestIdentity(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	gate := handler.(*applicationAuth)
	token := gate.email.issue("alice@example.com", true, alias, "/", now)
	<-gate.email.sendSlots

	public.Store([]PublicHost{{URL: "https://" + emailTestHost}})
	if rec := postEmailJSON(gate, alias, types.PathApplicationAuthEmailRedeem, applicationAuthEmailRedeemRequest{Token: token}); rec.Code != http.StatusMisdirectedRequest {
		t.Fatalf("redeem at a lost alias = %d; want 421", rec.Code)
	}
	newHold := now.Add(time.Minute)
	public.Store([]PublicHost{{URL: "https://" + emailTestHost}, {URL: "https://" + alias, Since: newHold}})
	if rec := postEmailJSON(gate, alias, types.PathApplicationAuthEmailRedeem, applicationAuthEmailRedeemRequest{Token: token}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("redeem of a link from the earlier hold = %d; want 401", rec.Code)
	}
	fresh := gate.email.issue("alice@example.com", true, alias, "/", newHold)
	<-gate.email.sendSlots
	if rec := postEmailJSON(gate, alias, types.PathApplicationAuthEmailRedeem, applicationAuthEmailRedeemRequest{Token: fresh}); rec.Code != http.StatusOK {
		t.Fatalf("redeem of a link from this hold = %d; want 200", rec.Code)
	}
}

func TestLoginRedirectDropsAPathTooLongToPostBack(t *testing.T) {
	t.Parallel()

	gate := newEmailTestGate(t, emailTestConfig("127.0.0.1:25", "alice@example.com"), http.NotFoundHandler())
	for path, want := range map[string]string{
		"/" + strings.Repeat("a", applicationAuthNextLimit-1): "/" + strings.Repeat("a", applicationAuthNextLimit-1),
		"/" + strings.Repeat("a", applicationAuthNextLimit):   "/",
	} {
		rec := httptest.NewRecorder()
		gate.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://"+emailTestHost+path, nil))
		location, err := url.Parse(rec.Header().Get("Location"))
		if rec.Code != http.StatusSeeOther || err != nil {
			t.Fatalf("redirect = %d, %v", rec.Code, err)
		}
		if got := location.Query().Get("next"); got != want {
			t.Fatalf("a path of %d bytes returns to %d bytes; want %d", len(path), len(got), len(want))
		}
	}
}

func newAliasedSessionGate(t *testing.T) (*atomic.Value, *applicationAuth, []*http.Cookie) {
	t.Helper()
	const alias = "alias.example"
	var public atomic.Value
	public.Store([]PublicHost{{URL: "https://" + emailTestHost}, {URL: "https://" + alias}})
	cfg := emailTestConfig("127.0.0.1:25", "alice@example.com")
	cfg.PublicHosts = func() []PublicHost { return public.Load().([]PublicHost) }
	handler, err := New(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), applicationAuthTestIdentity(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	gate := handler.(*applicationAuth)
	token := gate.email.issue("alice@example.com", true, alias, "/", time.Now().UTC())
	<-gate.email.sendSlots
	redeem := postEmailJSON(gate, alias, types.PathApplicationAuthEmailRedeem, applicationAuthEmailRedeemRequest{Token: token})
	if redeem.Code != http.StatusOK || len(redeem.Result().Cookies()) != 1 {
		t.Fatalf("redeem = %d, cookies = %v", redeem.Code, redeem.Result().Cookies())
	}
	return &public, gate, redeem.Result().Cookies()
}
func checkAliasedSessionOpen(t *testing.T, gate *applicationAuth, cookies []*http.Cookie) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "https://alias.example/private", nil)
	req.AddCookie(cookies[0])
	rec := httptest.NewRecorder()
	gate.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("session on a public alias = %d; want 204", rec.Code)
	}
}
func checkAliasedSessionLost(t *testing.T, gate *applicationAuth, cookies []*http.Cookie) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "https://alias.example/private", nil)
	req.AddCookie(cookies[0])
	rec := httptest.NewRecorder()
	gate.ServeHTTP(rec, req)
	if rec.Code != http.StatusMisdirectedRequest {
		t.Fatalf("session on a lost alias = %d; want 421", rec.Code)
	}
}
func checkAliasedSessionBack(t *testing.T, gate *applicationAuth, cookies []*http.Cookie) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "https://alias.example/private", nil)
	req.AddCookie(cookies[0])
	rec := httptest.NewRecorder()
	gate.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("session after the alias came back = %d; want the login redirect", rec.Code)
	}
}
func TestEmailSessionEndsWithItsPublicHost(t *testing.T) {
	t.Parallel()
	const alias = "alias.example"
	public, gate, cookies := newAliasedSessionGate(t)
	checkAliasedSessionOpen(t, gate, cookies)
	public.Store([]PublicHost{{URL: "https://" + emailTestHost}})
	checkAliasedSessionLost(t, gate, cookies)
	public.Store([]PublicHost{{URL: "https://" + emailTestHost}, {URL: "https://" + alias, Since: time.Now().Add(time.Minute)}})
	checkAliasedSessionBack(t, gate, cookies)
}
func checkSessionAgainstAllowlist(t *testing.T, session string, allowed []string, want int) {
	t.Helper()
	gate := newEmailTestGate(t, emailTestConfig("127.0.0.1:25", allowed...), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodGet, "https://"+emailTestHost+"/", nil)
	req.AddCookie(&http.Cookie{Name: applicationAuthCookieName, Value: session})
	rec := httptest.NewRecorder()
	gate.ServeHTTP(rec, req)
	if rec.Code != want {
		t.Fatalf("allowlist %q: status = %d; want %d", allowed, rec.Code, want)
	}
}
func checkSessionAfterConfigChange(t *testing.T, session string, name string, change func(*Config)) {
	t.Helper()
	cfg := emailTestConfig("127.0.0.1:25", "alice@example.com")
	change(&cfg)
	gate := newEmailTestGate(t, cfg, http.NotFoundHandler())
	req := httptest.NewRequest(http.MethodGet, "https://"+emailTestHost+"/", nil)
	req.AddCookie(&http.Cookie{Name: applicationAuthCookieName, Value: session})
	rec := httptest.NewRecorder()
	gate.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("new %s: status = %d; want the session refused", name, rec.Code)
	}
}
func TestEmailSessionFollowsTheAllowlist(t *testing.T) {
	t.Parallel()
	issued := newEmailTestGate(t, emailTestConfig("127.0.0.1:25", "alice@example.com"), http.NotFoundHandler())
	session, err := issued.issueSession(Principal{Provider: ProviderEmail, Subject: "alice@example.com"}, emailTestHost, time.Now(), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		allowed []string
		want    int
	}{
		{[]string{"alice@example.com"}, http.StatusNoContent},
		{[]string{"@example.com"}, http.StatusNoContent},
		{[]string{"bob@example.com"}, http.StatusSeeOther},
	} {
		checkSessionAgainstAllowlist(t, session, tc.allowed, tc.want)
	}
	for name, change := range map[string]func(*Config){
		"server":   func(c *Config) { c.SMTPAddr = "127.0.0.1:587" },
		"username": func(c *Config) { c.SMTPUsername = "other" },
		"sender":   func(c *Config) { c.SMTPFrom = "other@portal.example" },
	} {
		checkSessionAfterConfigChange(t, session, name, change)
	}
}
func TestEmailPrincipalIsTheAddress(t *testing.T) {
	t.Parallel()

	gate := newEmailTestGate(t, emailTestConfig("127.0.0.1:25", "alice@example.com"), http.NotFoundHandler())
	token := gate.email.issue("alice@example.com", true, emailTestHost, "/", time.Now().UTC())
	<-gate.email.sendSlots
	rec := postEmailJSON(gate, emailTestHost, types.PathApplicationAuthEmailRedeem, applicationAuthEmailRedeemRequest{Token: token})
	if rec.Code != http.StatusOK {
		t.Fatalf("redeem status = %d, body = %s", rec.Code, rec.Body.String())
	}
	req := httptest.NewRequest(http.MethodGet, "https://"+emailTestHost+"/", nil)
	req.AddCookie(rec.Result().Cookies()[0])
	want := Principal{ProviderEmail, "alice@example.com", "alice@example.com"}
	if got, ok := gate.authenticateSession(req); !ok || got != want {
		t.Fatalf("principal = (%+v, %v); want %+v", got, ok, want)
	}
}
func issueListedEmailLink(t *testing.T, e *emailAuthenticator, start time.Time, email string, at time.Duration) bool {
	t.Helper()
	if e.issue(email, true, emailTestHost, "/", start.Add(at)) == "" {
		return false
	}
	<-e.sendSlots
	return true
}
func issueUnlistedEmailLink(t *testing.T, e *emailAuthenticator, start time.Time, email string, at time.Duration) bool {
	t.Helper()
	if e.issue(email, false, emailTestHost, "/", start.Add(at)) == "" {
		return false
	}
	<-e.sendSlots
	return true
}
func checkAddressSendLimits(t *testing.T) {
	t.Helper()
	e := newEmailAuthenticator(applicationAuthSettings{emailSMTPAddr: "127.0.0.1:25"})
	start := time.Now().UTC()
	if !issueListedEmailLink(t, e, start, "alice@example.com", 0) {
		t.Fatal("the first link was refused")
	}
	if issueListedEmailLink(t, e, start, "alice@example.com", emailAddressCooldown-time.Second) {
		t.Fatal("a second link within the cooldown was sent")
	}
	for i := 1; i < emailAddressHourlyLimit; i++ {
		if !issueListedEmailLink(t, e, start, "alice@example.com", time.Duration(i)*emailAddressCooldown) {
			t.Fatalf("link %d of the hour was refused", i+1)
		}
	}
	if issueListedEmailLink(t, e, start, "alice@example.com", emailAddressHourlyLimit*emailAddressCooldown) {
		t.Fatal("a link over the hourly limit of one address was sent")
	}
	if !issueListedEmailLink(t, e, start, "alice@example.com", time.Hour+time.Second) {
		t.Fatal("a link an hour after the first was refused")
	}
}
func checkDomainSendLimits(t *testing.T) {
	t.Helper()
	e := newEmailAuthenticator(applicationAuthSettings{emailSMTPAddr: "127.0.0.1:25"})
	start := time.Now().UTC()
	for i := range emailDomainHourlyLimit {
		if !issueUnlistedEmailLink(t, e, start, fmt.Sprintf("user%d@team.example", i), time.Duration(i)*time.Second) {
			t.Fatalf("domain link %d was refused", i+1)
		}
	}
	if issueUnlistedEmailLink(t, e, start, "late@team.example", time.Minute) {
		t.Fatal("a domain link over the hourly domain limit was sent")
	}
	if !issueListedEmailLink(t, e, start, "alice@example.com", time.Minute) {
		t.Fatal("a flood of domain addresses locked out an exactly listed address")
	}
	if !issueUnlistedEmailLink(t, e, start, "late@team.example", time.Hour+time.Second) {
		t.Fatal("a domain link after the hour was refused")
	}
}
func TestEmailSendLimits(t *testing.T) {
	t.Parallel()
	checkAddressSendLimits(t)
	checkDomainSendLimits(t)
}

func TestEmailSendDroppedForBusySlotsSpendsNoLimit(t *testing.T) {
	t.Parallel()

	e := newEmailAuthenticator(applicationAuthSettings{emailSMTPAddr: "127.0.0.1:25"})
	for range emailSendSlots {
		e.sendSlots <- struct{}{}
	}
	now := time.Now().UTC()
	e.send("alice@example.com", true, emailTestHost, "/", now)
	e.mu.Lock()
	links, sent := len(e.links), len(e.sent)
	e.mu.Unlock()
	if links != 0 || sent != 0 {
		t.Fatalf("a dropped send left %d links and %d recorded sends", links, sent)
	}
	for range emailSendSlots {
		<-e.sendSlots
	}
	if e.issue("alice@example.com", true, emailTestHost, "/", now) == "" {
		t.Fatal("the dropped send spent the cooldown of the address")
	}
}

func TestEmailRefusedSendsLeaveTheSlotsFree(t *testing.T) {
	t.Parallel()

	e := newEmailAuthenticator(applicationAuthSettings{emailSMTPAddr: "127.0.0.1:25"})
	now := time.Now().UTC()
	if e.issue("alice@example.com", true, emailTestHost, "/", now) == "" {
		t.Fatal("the first link was refused")
	}
	<-e.sendSlots
	for range emailSendSlots + 1 {
		if e.issue("alice@example.com", true, emailTestHost, "/", now) != "" {
			t.Fatal("the cooldown let a send through")
		}
	}
	if e.issue("bob@example.com", true, emailTestHost, "/", now) == "" {
		t.Fatal("refused sends took the slot of a real one")
	}
}

func TestEmailDomainBudgetSparesAListedAddress(t *testing.T) {
	t.Parallel()

	server := newSMTPTestServer(t, emailTestUsername, emailTestPassword)
	gate := newEmailTestGate(t, emailTestConfig(server.addr, "alice@team.example", "@team.example"), http.NotFoundHandler())
	now := time.Now().UTC()
	gate.email.mu.Lock()
	for i := range emailDomainHourlyLimit {
		gate.email.sent = append(gate.email.sent, emailSend{email: fmt.Sprintf("user%d@team.example", i), at: now})
	}
	gate.email.mu.Unlock()

	postEmailJSON(gate, emailTestHost, types.PathApplicationAuthEmailRequest, applicationAuthEmailRequest{Email: "late@team.example"})
	server.expectNoMore(t)
	postEmailJSON(gate, emailTestHost, types.PathApplicationAuthEmailRequest, applicationAuthEmailRequest{Email: "alice@team.example"})
	if message := server.next(t); !slices.Equal(message.to, []string{"alice@team.example"}) {
		t.Fatalf("mail to %v", message.to)
	}
}
