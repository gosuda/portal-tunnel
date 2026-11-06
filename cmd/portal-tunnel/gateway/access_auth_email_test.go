package gateway

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/mail"
	"net/textproto"
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

// smtpTestServer is a minimal SMTP server on a loopback address. It accepts a
// mail only after AUTH PLAIN with its username and password, when it has them,
// and hands each accepted mail to messages.
type smtpTestServer struct {
	addr     string
	username string
	password string
	messages chan smtpTestMessage
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

func (s *smtpTestServer) serve(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	text := textproto.NewConn(conn)
	reply := func(line string) bool { return text.PrintfLine("%s", line) == nil }
	if !reply("220 smtp.test ESMTP") {
		return
	}
	signedIn := s.username == ""
	var message smtpTestMessage
	for {
		line, err := text.ReadLine()
		if err != nil {
			return
		}
		verb, arg, _ := strings.Cut(line, " ")
		switch strings.ToUpper(verb) {
		case "EHLO", "HELO":
			reply("250-smtp.test")
			reply("250 AUTH PLAIN")
		case "AUTH":
			_, encoded, _ := strings.Cut(arg, " ")
			credentials, _ := base64.StdEncoding.DecodeString(encoded)
			if string(credentials) != "\x00"+s.username+"\x00"+s.password {
				reply("535 5.7.8 authentication failed")
				continue
			}
			signedIn = true
			reply("235 2.7.0 authenticated")
		case "MAIL":
			if !signedIn {
				reply("530 5.7.0 authentication required")
				continue
			}
			message = smtpTestMessage{from: strings.TrimSuffix(strings.TrimPrefix(arg, "FROM:<"), ">")}
			reply("250 OK")
		case "RCPT":
			message.to = append(message.to, strings.TrimSuffix(strings.TrimPrefix(arg, "TO:<"), ">"))
			reply("250 OK")
		case "DATA":
			reply("354 send the message")
			data, err := text.ReadDotBytes()
			if err != nil {
				return
			}
			message.data = string(data)
			s.messages <- message
			reply("250 OK")
		case "QUIT":
			reply("221 bye")
			return
		default:
			reply("502 command not implemented")
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

// expectNoMore fails when another mail arrives shortly.
func (s *smtpTestServer) expectNoMore(t *testing.T) {
	t.Helper()
	select {
	case message := <-s.messages:
		t.Fatalf("unexpected mail to %v", message.to)
	case <-time.After(200 * time.Millisecond):
	}
}

func emailTestConfig(smtpAddr string, allowed ...string) ApplicationAuthConfig {
	return ApplicationAuthConfig{
		Provider:       ApplicationAuthProviderEmail,
		AllowedWallets: allowed,
		EmailConfig: EmailConfig{
			SMTPAddr:     smtpAddr,
			SMTPUsername: emailTestUsername,
			SMTPPassword: emailTestPassword,
			SMTPFrom:     emailTestFrom,
		},
	}
}

func newEmailTestGate(t *testing.T, cfg ApplicationAuthConfig, next http.Handler) *applicationAuth {
	t.Helper()
	handler, err := NewApplicationAuth(next, applicationAuthTestIdentity(), cfg, func() []string {
		return []string{"https://" + emailTestHost, ""}
	})
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

// emailLinkToken reads the token from the login link in a mail.
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

// An allowed address receives one mail from the configured sender through the
// signed-in SMTP server, and its link creates the session every provider
// creates, once.
func TestEmailLoginLinkCreatesSessionOnce(t *testing.T) {
	t.Parallel()

	server := newSMTPTestServer(t, emailTestUsername, emailTestPassword)
	var upstreamUser, upstreamAuth string
	cfg := emailTestConfig(server.addr, "alice@example.com")
	cfg.IdentityHeaders = true
	gate := newEmailTestGate(t, cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamUser, upstreamAuth = r.Header.Get(types.HeaderPortalUser), r.Header.Get(types.HeaderPortalAuth)
		w.WriteHeader(http.StatusNoContent)
	}))

	rec := postEmailJSON(gate, emailTestHost, applicationAuthEmailRequestPath, applicationAuthEmailRequest{Email: " Alice@Example.com ", Next: "/inbox?view=all"})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("request status = %d, body = %s", rec.Code, rec.Body.String())
	}
	message := server.next(t)
	if message.from != emailTestSender || !slices.Equal(message.to, []string{"alice@example.com"}) {
		t.Fatalf("envelope = %q -> %q", message.from, message.to)
	}
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
	if !strings.Contains(message.data, "https://"+emailTestHost+applicationAuthLoginPath+"#email_token=") {
		t.Fatalf("mail does not link to the login page of %s:\n%s", emailTestHost, message.data)
	}
	token := emailLinkToken(t, message)
	if raw, err := base64.RawURLEncoding.DecodeString(token); err != nil || len(raw) != 32 {
		t.Fatalf("token %q is not 256 random bits", token)
	}

	rec = postEmailJSON(gate, emailTestHost, applicationAuthEmailRedeemPath, applicationAuthEmailRedeemRequest{Token: token})
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

	req := httptest.NewRequest(http.MethodGet, "https://"+emailTestHost+"/inbox", nil)
	req.AddCookie(cookies[0])
	rec = httptest.NewRecorder()
	gate.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent || upstreamUser != "alice@example.com" || upstreamAuth != ApplicationAuthProviderEmail {
		t.Fatalf("session request = %d as %q via %q", rec.Code, upstreamUser, upstreamAuth)
	}

	rec = postEmailJSON(gate, emailTestHost, applicationAuthEmailRedeemPath, applicationAuthEmailRedeemRequest{Token: token})
	if rec.Code != http.StatusUnauthorized || len(rec.Result().Cookies()) != 0 {
		t.Fatalf("second redeem status = %d with cookies %v; want 401 without a session", rec.Code, rec.Result().Cookies())
	}
}

// The answer to a link request must not tell who may sign in: an address that
// is not allowed, an allowed one, and an allowed one that a limit refuses all
// get the same status, headers and body, and only the allowed one is mailed.
func TestEmailRequestAnswersAlikeForEveryAddress(t *testing.T) {
	t.Parallel()

	server := newSMTPTestServer(t, emailTestUsername, emailTestPassword)
	gate := newEmailTestGate(t, emailTestConfig(server.addr, "alice@example.com", "@team.example"), http.NotFoundHandler())

	var answers []*httptest.ResponseRecorder
	for _, address := range []string{"mallory@evil.example", "alice@example.com", "alice@example.com", "bob@team.example"} {
		answers = append(answers, postEmailJSON(gate, emailTestHost, applicationAuthEmailRequestPath, applicationAuthEmailRequest{Email: address}))
	}
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

// The sender is configuration only, and no header of the mail can be given a
// line break by the visitor.
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
		if rec := postEmailJSON(gate, emailTestHost, applicationAuthEmailRequestPath, body); rec.Code != http.StatusBadRequest {
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
		"sub:alice@example.com":                   "",
		strings.Repeat("a", 250) + "@example.com": "",
	} {
		got, err := normalizeVisitorEmail(raw)
		if got != want || (err == nil) != (want != "") {
			t.Errorf("normalizeVisitorEmail(%q) = %q, %v; want %q", raw, got, err, want)
		}
	}
}

// A request names its own Host, so a link is mailed only for a host the tunnel
// is reachable at: a link for another host would hand the token to whoever
// answers there.
func TestEmailRequestRefusesHostThatIsNotPublic(t *testing.T) {
	t.Parallel()

	server := newSMTPTestServer(t, emailTestUsername, emailTestPassword)
	gate := newEmailTestGate(t, emailTestConfig(server.addr, "alice@example.com"), http.NotFoundHandler())
	rec := postEmailJSON(gate, "attacker.example", applicationAuthEmailRequestPath, applicationAuthEmailRequest{Email: "alice@example.com"})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d; want 403", rec.Code)
	}

	// The default port names the same host.
	rec = postEmailJSON(gate, emailTestHost+":443", applicationAuthEmailRequestPath, applicationAuthEmailRequest{Email: "alice@example.com"})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d; want 202", rec.Code)
	}
	if message := server.next(t); !strings.Contains(message.data, "https://"+emailTestHost+applicationAuthLoginPath+"#") {
		t.Fatalf("link does not use the canonical host:\n%s", message.data)
	}

	// Without the list of public URLs no host qualifies.
	handler, err := NewApplicationAuth(http.NotFoundHandler(), applicationAuthTestIdentity(), emailTestConfig(server.addr, "alice@example.com"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if rec := postEmailJSON(handler, emailTestHost, applicationAuthEmailRequestPath, applicationAuthEmailRequest{Email: "alice@example.com"}); rec.Code != http.StatusForbidden {
		t.Fatalf("status without public URLs = %d; want 403", rec.Code)
	}
	server.expectNoMore(t)
}

// A link works once, for its host, within emailLinkTTL.
func TestEmailLinkIsSingleUseAndExpires(t *testing.T) {
	t.Parallel()

	e := newEmailAuthenticator(applicationAuthSettings{emailSMTPAddr: "127.0.0.1:25"}, nil)
	now := time.Now().UTC()

	token := e.issue("alice@example.com", true, emailTestHost, "/next", now)
	if email, next, ok := e.redeem(token, emailTestHost, now.Add(emailLinkTTL-time.Second)); !ok || email != "alice@example.com" || next != "/next" {
		t.Fatalf("redeem = %q, %q, %v", email, next, ok)
	}
	if _, _, ok := e.redeem(token, emailTestHost, now); ok {
		t.Fatal("a used link worked again")
	}

	token = e.issue("bob@example.com", true, emailTestHost, "/", now)
	if _, _, ok := e.redeem(token, emailTestHost, now.Add(emailLinkTTL)); ok {
		t.Fatal("an expired link worked")
	}

	token = e.issue("carol@example.com", true, emailTestHost, "/", now)
	if _, _, ok := e.redeem(token, "other.example", now); ok {
		t.Fatal("a link worked at another host")
	}
	if _, _, ok := e.redeem(token, emailTestHost, now); ok {
		t.Fatal("a link tried at another host still worked")
	}
	if _, _, ok := e.redeem("not-a-token", emailTestHost, now); ok {
		t.Fatal("an unknown token worked")
	}
}

// One address gets one link per minute and five per hour. The addresses that
// only an @domain entry allows share fifty links per hour, and a flood of them
// does not lock out an exactly listed address.
func TestEmailSendLimits(t *testing.T) {
	t.Parallel()

	e := newEmailAuthenticator(applicationAuthSettings{emailSMTPAddr: "127.0.0.1:25"}, nil)
	start := time.Now().UTC()
	issueAs := func(email string, listed bool, at time.Duration) bool {
		return e.issue(email, listed, emailTestHost, "/", start.Add(at)) != ""
	}
	issue := func(email string, at time.Duration) bool { return issueAs(email, true, at) }
	if !issue("alice@example.com", 0) {
		t.Fatal("the first link was refused")
	}
	if issue("alice@example.com", emailAddressCooldown-time.Second) {
		t.Fatal("a second link within the cooldown was sent")
	}
	for i := 1; i < emailAddressHourlyLimit; i++ {
		if !issue("alice@example.com", time.Duration(i)*emailAddressCooldown) {
			t.Fatalf("link %d of the hour was refused", i+1)
		}
	}
	if issue("alice@example.com", emailAddressHourlyLimit*emailAddressCooldown) {
		t.Fatal("a link over the hourly limit of one address was sent")
	}
	if !issue("alice@example.com", time.Hour+time.Second) {
		t.Fatal("a link an hour after the first was refused")
	}

	e = newEmailAuthenticator(applicationAuthSettings{emailSMTPAddr: "127.0.0.1:25"}, nil)
	for i := range emailDomainHourlyLimit {
		if !issueAs(fmt.Sprintf("user%d@team.example", i), false, time.Duration(i)*time.Second) {
			t.Fatalf("domain link %d was refused", i+1)
		}
	}
	if issueAs("late@team.example", false, time.Minute) {
		t.Fatal("a domain link over the hourly domain limit was sent")
	}
	if !issue("alice@example.com", time.Minute) {
		t.Fatal("a flood of domain addresses locked out an exactly listed address")
	}
	if !issueAs("late@team.example", false, time.Hour+time.Second) {
		t.Fatal("a domain link after the hour was refused")
	}
}

// A send dropped because every send slot is busy spends no limit and leaves
// no link, so the visitor's retry can still get one.
func TestEmailSendDroppedForBusySlotsSpendsNoLimit(t *testing.T) {
	t.Parallel()

	e := newEmailAuthenticator(applicationAuthSettings{emailSMTPAddr: "127.0.0.1:25"}, nil)
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

// Sessions check the allowlist on every request, so an entry removed before a
// restart no longer admits its sessions.
func TestEmailSessionFollowsTheAllowlist(t *testing.T) {
	t.Parallel()

	issued := newEmailTestGate(t, emailTestConfig("127.0.0.1:25", "alice@example.com"), http.NotFoundHandler())
	session, err := issued.issueSession("alice@example.com", ApplicationAuthProviderEmail, emailTestHost, time.Now().Add(time.Hour))
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
		gate := newEmailTestGate(t, emailTestConfig("127.0.0.1:25", tc.allowed...), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
		req := httptest.NewRequest(http.MethodGet, "https://"+emailTestHost+"/", nil)
		req.AddCookie(&http.Cookie{Name: applicationAuthCookieName, Value: session})
		rec := httptest.NewRecorder()
		gate.ServeHTTP(rec, req)
		if rec.Code != tc.want {
			t.Fatalf("allowlist %q: status = %d; want %d", tc.allowed, rec.Code, tc.want)
		}
	}

	// A session is bound to the mail account that mailed its link, so a new
	// SMTP server, username or sender ends it.
	for name, change := range map[string]func(*ApplicationAuthConfig){
		"server":   func(c *ApplicationAuthConfig) { c.SMTPAddr = "127.0.0.1:587" },
		"username": func(c *ApplicationAuthConfig) { c.SMTPUsername = "other" },
		"sender":   func(c *ApplicationAuthConfig) { c.SMTPFrom = "other@portal.example" },
	} {
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
}

// The provider fails closed: it refuses to start without an allowlist, an SMTP
// server or a sender, and refuses settings it cannot use.
func TestResolveEmailApplicationAuthConfig(t *testing.T) {
	t.Parallel()

	valid := emailTestConfig("smtp.example:587", "Alice@Example.com", "@team.example")
	settings, err := resolveApplicationAuthConfig(valid)
	if err != nil {
		t.Fatal(err)
	}
	want := applicationAuthSettings{
		provider:          ApplicationAuthProviderEmail,
		allowed:           []string{"alice@example.com", "@team.example"},
		emailSMTPAddr:     "smtp.example:587",
		emailSMTPUsername: emailTestUsername,
		emailSMTPPassword: emailTestPassword,
		emailFrom:         mail.Address{Name: "Portal", Address: emailTestSender},
	}
	if !reflect.DeepEqual(settings, want) {
		t.Fatalf("settings = %+v; want %+v", settings, want)
	}

	for name, tc := range map[string]struct {
		change  func(*ApplicationAuthConfig)
		wantErr error
	}{
		"no allowlist":           {func(c *ApplicationAuthConfig) { c.AllowedWallets = nil }, errEmailRequiresLeastOneAuthAllow},
		"subject entry":          {func(c *ApplicationAuthConfig) { c.AllowedWallets = []string{"sub:alice"} }, errEmailAllowsNoSubjectEntries},
		"no smtp address":        {func(c *ApplicationAuthConfig) { c.SMTPAddr = "" }, errSMTPAddrIsRequired},
		"no smtp port":           {func(c *ApplicationAuthConfig) { c.SMTPAddr = "smtp.example" }, errSMTPAddrMustHostPort},
		"smtp port 0":            {func(c *ApplicationAuthConfig) { c.SMTPAddr = "smtp.example:0" }, errSMTPAddrMustHostPort},
		"smtp port out of range": {func(c *ApplicationAuthConfig) { c.SMTPAddr = "smtp.example:65536" }, errSMTPAddrMustHostPort},
		"no sender":              {func(c *ApplicationAuthConfig) { c.SMTPFrom = "" }, errSMTPFromIsRequired},
		"two senders":            {func(c *ApplicationAuthConfig) { c.SMTPFrom = "a@example.com, b@example.com" }, errSMTPFromMustOneAddress},
		"sender with line break": {func(c *ApplicationAuthConfig) { c.SMTPFrom = "a@example.com\r\nBcc: b@example.com" }, errSMTPFromMustOneAddress},
		"username only":          {func(c *ApplicationAuthConfig) { c.SMTPPassword = "" }, errEmailSMTPCredentialsArePaired},
		"password only":          {func(c *ApplicationAuthConfig) { c.SMTPUsername = "" }, errEmailSMTPCredentialsArePaired},
		"settings of another provider": {func(c *ApplicationAuthConfig) {
			c.Provider, c.AllowedWallets = ApplicationAuthProviderCredential, nil
		}, errEmailSettingsRequireEmailApplicationAuth},
	} {
		cfg := emailTestConfig("smtp.example:587", "alice@example.com")
		tc.change(&cfg)
		if _, err := resolveApplicationAuthConfig(cfg); !errors.Is(err, tc.wantErr) {
			t.Errorf("%s: error = %v; want %v", name, err, tc.wantErr)
		}
	}
}

// The startup check signs in to the SMTP server without sending, so a wrong
// password shows before any visitor asks for a link.
func TestCheckEmailProviderSignsInWithoutSending(t *testing.T) {
	t.Parallel()

	server := newSMTPTestServer(t, emailTestUsername, emailTestPassword)
	ctx := context.Background()
	if err := CheckApplicationAuthProvider(ctx, emailTestConfig(server.addr, "alice@example.com")); err != nil {
		t.Fatalf("check = %v", err)
	}
	wrong := emailTestConfig(server.addr, "alice@example.com")
	wrong.SMTPPassword = "wrong-smtp-secret"
	err := CheckApplicationAuthProvider(ctx, wrong)
	if err == nil {
		t.Fatal("check with a wrong password passed")
	}
	if strings.Contains(err.Error(), wrong.SMTPPassword) {
		t.Fatalf("check error %q shows the password", err)
	}
	server.expectNoMore(t)
}

// Only localhost, 127.0.0.1 and ::1, the names net/smtp sends a password to
// without TLS, may be reached in plaintext: any other server must offer
// STARTTLS before the password is sent.
func TestEmailRefusesPlaintextToARemoteServer(t *testing.T) {
	t.Parallel()

	server := newSMTPTestServer(t, emailTestUsername, emailTestPassword)
	for _, name := range []string{"smtp.example", "127.0.0.2"} {
		e := newEmailAuthenticator(applicationAuthSettings{
			emailSMTPAddr:     server.addr,
			emailSMTPUsername: emailTestUsername,
			emailSMTPPassword: emailTestPassword,
		}, nil)
		// The server listens on 127.0.0.1, but is named as another host.
		e.smtpHost = name
		if err := e.check(context.Background()); !errors.Is(err, errEmailSMTPOffersNoSTARTTLS) {
			t.Fatalf("check as %s = %v; want a STARTTLS refusal", name, err)
		}
	}
}
