package appauth

import (
	"bytes"
	"context"
	"crypto/tls"
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
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
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
// and hands each accepted mail to messages. The fields after messages change how
// it answers, and are set before the first connection.
type smtpTestServer struct {
	addr     string
	username string
	password string
	messages chan smtpTestMessage
	// rcptReply and dataReply, when set, refuse the recipient or the mail.
	rcptReply string
	dataReply string
	// dropAtQuit closes the connection instead of answering QUIT.
	dropAtQuit bool
	// startTLS, when set, is offered as STARTTLS with this certificate.
	startTLS *tls.Config
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
			if s.startTLS != nil {
				reply("250-STARTTLS")
			}
			reply("250 AUTH PLAIN")
		case "STARTTLS":
			reply("220 go ahead")
			_ = tls.Server(conn, s.startTLS).Handshake()
			return
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
			if s.rcptReply != "" {
				reply(s.rcptReply)
				continue
			}
			message.to = append(message.to, strings.TrimSuffix(strings.TrimPrefix(arg, "TO:<"), ">"))
			reply("250 OK")
		case "DATA":
			reply("354 send the message")
			data, err := text.ReadDotBytes()
			if err != nil {
				return
			}
			if s.dataReply != "" {
				reply(s.dataReply)
				continue
			}
			message.data = string(data)
			s.messages <- message
			reply("250 OK")
		case "QUIT":
			if !s.dropAtQuit {
				reply("221 bye")
			}
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
	cfg.PublicURLs = func() []string { return []string{"https://" + emailTestHost, ""} }
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
	if rec.Code != http.StatusNoContent || upstreamUser != "alice@example.com" || upstreamAuth != ProviderEmail {
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

	// While the application is reachable nowhere, no host qualifies.
	offline := emailTestConfig(server.addr, "alice@example.com")
	offline.PublicURLs = func() []string { return nil }
	handler, err := New(http.NotFoundHandler(), applicationAuthTestIdentity(), offline)
	if err != nil {
		t.Fatal(err)
	}
	if rec := postEmailJSON(handler, emailTestHost, applicationAuthEmailRequestPath, applicationAuthEmailRequest{Email: "alice@example.com"}); rec.Code != http.StatusForbidden {
		t.Fatalf("status without public URLs = %d; want 403", rec.Code)
	}
	server.expectNoMore(t)
}

// A gate that could never mail a link fails where the embedder sees it, not at
// the first visitor, who is told only that a link may be on its way.
func TestEmailGateRequiresPublicURLs(t *testing.T) {
	t.Parallel()

	if _, err := New(http.NotFoundHandler(), applicationAuthTestIdentity(), emailTestConfig("127.0.0.1:25", "alice@example.com")); !errors.Is(err, errEmailRequiresPublicURLs) {
		t.Fatalf("New without PublicURLs = %v; want %v", err, errEmailRequiresPublicURLs)
	}
}

// A mail client makes a link of any URL in the text, so the login link has to be
// the only one a visitor can tap.
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
	if got := strings.Count(body, emailTestHost); got != 1 || !strings.Contains(body, "https://"+emailTestHost+applicationAuthLoginPath+"#email_token=token") {
		t.Fatalf("body names the host %d times, want only in the login link:\n%s", got, body)
	}
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
		if e.issue(email, listed, emailTestHost, "/", start.Add(at)) == "" {
			return false
		}
		<-e.sendSlots
		return true
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

// A send takes its slot only after the limits pass. A request that waits for
// them holds none, so a flood of requests the limits refuse cannot crowd out a
// real send.
func TestEmailSendWaitingForTheLimitsHoldsNoSlot(t *testing.T) {
	t.Parallel()

	e := newEmailAuthenticator(applicationAuthSettings{emailSMTPAddr: "127.0.0.1:25"}, nil)
	now := time.Now().UTC()
	if e.issue("alice@example.com", true, emailTestHost, "/", now) == "" {
		t.Fatal("the first link was refused")
	}
	<-e.sendSlots

	e.mu.Lock()
	var waiting sync.WaitGroup
	for range emailSendSlots {
		waiting.Go(func() { e.send("alice@example.com", true, emailTestHost, "/", now) })
	}
	// Give the sends every chance to run up to the lock.
	for range 10_000 {
		if len(e.sendSlots) != 0 {
			break
		}
		runtime.Gosched()
	}
	held := len(e.sendSlots)
	e.mu.Unlock()
	waiting.Wait()
	if held != 0 {
		t.Fatalf("%d sends held a slot while they waited for the limits", held)
	}
	if held := len(e.sendSlots); held != 0 {
		t.Fatalf("%d refused sends kept a slot", held)
	}
}

// The gate tells an exactly listed address from one that only an @domain entry
// allows, so a flood that spends the domain budget leaves the listed address its
// link.
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

	postEmailJSON(gate, emailTestHost, applicationAuthEmailRequestPath, applicationAuthEmailRequest{Email: "late@team.example"})
	server.expectNoMore(t)
	postEmailJSON(gate, emailTestHost, applicationAuthEmailRequestPath, applicationAuthEmailRequest{Email: "alice@team.example"})
	if message := server.next(t); !slices.Equal(message.to, []string{"alice@team.example"}) {
		t.Fatalf("mail to %v", message.to)
	}
}

// A mail server may route on these characters, so the allowlist cannot vouch
// for where such an address ends up, and it never reaches the server.
func TestEmailRequestRefusesARoutedAddress(t *testing.T) {
	t.Parallel()

	server := newSMTPTestServer(t, emailTestUsername, emailTestPassword)
	gate := newEmailTestGate(t, emailTestConfig(server.addr, "@team.example"), http.NotFoundHandler())
	for _, address := range []string{"attacker%evil.example@team.example", "evil.example!attacker@team.example"} {
		if rec := postEmailJSON(gate, emailTestHost, applicationAuthEmailRequestPath, applicationAuthEmailRequest{Email: address}); rec.Code != http.StatusBadRequest {
			t.Fatalf("request for %s status = %d; want 400", address, rec.Code)
		}
	}
	server.expectNoMore(t)
}

// Another site cannot ask for a mail or spend a link from a visitor's browser,
// and the attempt leaves the link usable.
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

	if code := post(applicationAuthEmailRequestPath, applicationAuthEmailRequest{Email: "alice@example.com"}); code != http.StatusForbidden {
		t.Fatalf("request status = %d; want 403", code)
	}
	server.expectNoMore(t)

	token := gate.email.issue("bob@example.com", true, emailTestHost, "/", time.Now().UTC())
	<-gate.email.sendSlots
	if code := post(applicationAuthEmailRedeemPath, applicationAuthEmailRedeemRequest{Token: token}); code != http.StatusForbidden {
		t.Fatalf("redeem status = %d; want 403", code)
	}
	if rec := postEmailJSON(gate, emailTestHost, applicationAuthEmailRedeemPath, applicationAuthEmailRedeemRequest{Token: token}); rec.Code != http.StatusOK {
		t.Fatalf("same-origin redeem status = %d; want 200", rec.Code)
	}
}

// A link only ever returns a visitor to a path of this application.
func TestEmailLinkReturnsOnlyToLocalPaths(t *testing.T) {
	t.Parallel()

	server := newSMTPTestServer(t, emailTestUsername, emailTestPassword)
	gate := newEmailTestGate(t, emailTestConfig(server.addr, "@example.com"), http.NotFoundHandler())
	for i, next := range []string{"https://evil.example/", "//evil.example/", "/\\evil.example", "/\t/evil.example"} {
		email := fmt.Sprintf("user%d@example.com", i)
		postEmailJSON(gate, emailTestHost, applicationAuthEmailRequestPath, applicationAuthEmailRequest{Email: email, Next: next})
		rec := postEmailJSON(gate, emailTestHost, applicationAuthEmailRedeemPath, applicationAuthEmailRedeemRequest{Token: emailLinkToken(t, server.next(t))})
		var redeemed map[string]string
		if err := json.Unmarshal(rec.Body.Bytes(), &redeemed); err != nil || rec.Code != http.StatusOK {
			t.Fatalf("redeem = %d, %v", rec.Code, err)
		}
		if redeemed["next"] != "/" {
			t.Fatalf("next %q returned %q; want /", next, redeemed["next"])
		}
	}
}

// A link mailed for an alias stops working when the alias leaves the tunnel: the
// next owner of the name reads the link of whoever opens it, and must not be able
// to replay it here. A refused host does not use up the link.
func TestEmailLinkIsRefusedAtAHostThatIsNoLongerPublic(t *testing.T) {
	t.Parallel()

	const alias = "alias.example"
	var public atomic.Value
	public.Store([]string{"https://" + emailTestHost, "https://" + alias})
	cfg := emailTestConfig("127.0.0.1:25", "alice@example.com")
	cfg.PublicURLs = func() []string { return public.Load().([]string) }
	handler, err := New(http.NotFoundHandler(), applicationAuthTestIdentity(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	gate := handler.(*applicationAuth)
	token := gate.email.issue("alice@example.com", true, alias, "/", time.Now().UTC())
	<-gate.email.sendSlots

	public.Store([]string{"https://" + emailTestHost})
	if rec := postEmailJSON(gate, alias, applicationAuthEmailRedeemPath, applicationAuthEmailRedeemRequest{Token: token}); rec.Code != http.StatusForbidden {
		t.Fatalf("redeem at a lost alias = %d; want 403", rec.Code)
	}
	public.Store([]string{"https://" + emailTestHost, "https://" + alias})
	if rec := postEmailJSON(gate, alias, applicationAuthEmailRedeemPath, applicationAuthEmailRedeemRequest{Token: token}); rec.Code != http.StatusOK {
		t.Fatalf("redeem after the alias came back = %d; want 200", rec.Code)
	}
}

func newEmailTestAuthenticator(t *testing.T, addr string) *emailAuthenticator {
	t.Helper()
	settings, err := resolveApplicationAuthConfig(emailTestConfig(addr, "bob@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	return newEmailAuthenticator(settings, nil)
}

// A server's reply about the recipient can quote the address. The send log must
// not hold it, so an error keeps only the code.
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

// The server has the mail once it accepts DATA, so a connection lost at QUIT is
// not a failed send.
func TestEmailDeliverSurvivesAFailedQuit(t *testing.T) {
	t.Parallel()

	server := newSMTPTestServer(t, emailTestUsername, emailTestPassword)
	server.dropAtQuit = true
	if err := newEmailTestAuthenticator(t, server.addr).deliver(context.Background(), "bob@example.com", []byte("Subject: hi\r\n\r\nhi\r\n")); err != nil {
		t.Fatalf("deliver = %v", err)
	}
	server.next(t)
}

// Both TLS transports verify the server. The test cannot show a successful
// session, because the code takes no root certificate, but it shows that a
// certificate nobody vouches for ends the session before the password is sent.
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

// Sessions check the allowlist on every request, so an entry removed before a
// restart no longer admits its sessions.
func TestEmailSessionFollowsTheAllowlist(t *testing.T) {
	t.Parallel()

	issued := newEmailTestGate(t, emailTestConfig("127.0.0.1:25", "alice@example.com"), http.NotFoundHandler())
	session, err := issued.issueSession(Principal{Provider: ProviderEmail, Subject: "alice@example.com"}, emailTestHost, time.Now().Add(time.Hour))
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
	for name, change := range map[string]func(*Config){
		"server":   func(c *Config) { c.SMTPAddr = "127.0.0.1:587" },
		"username": func(c *Config) { c.SMTPUsername = "other" },
		"sender":   func(c *Config) { c.SMTPFrom = "other@portal.example" },
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

	for name, tc := range map[string]struct {
		change  func(*Config)
		wantErr error
	}{
		"no allowlist":           {func(c *Config) { c.EmailList = nil }, errEmailRequiresEmailList},
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
		cfg := emailTestConfig("smtp.example:587", "alice@example.com")
		tc.change(&cfg)
		if _, err := resolveApplicationAuthConfig(cfg); !errors.Is(err, tc.wantErr) {
			t.Errorf("%s: error = %v; want %v", name, err, tc.wantErr)
		}
	}
}

// One list has two names. auth_email_list is the list of every provider that
// names a visitor by email, and released oidc and saml configs hold it under
// auth_allowed_wallets. A config that sets both, or that gives the list to a
// provider that cannot read it, is refused rather than read one way.
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

// The startup check signs in to the SMTP server without sending, so a wrong
// password shows before any visitor asks for a link.
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

func TestEmailPrincipalIsTheAddress(t *testing.T) {
	t.Parallel()

	gate := newEmailTestGate(t, emailTestConfig("127.0.0.1:25", "alice@example.com"), http.NotFoundHandler())
	token := gate.email.issue("alice@example.com", true, emailTestHost, "/", time.Now().UTC())
	<-gate.email.sendSlots
	rec := postEmailJSON(gate, emailTestHost, applicationAuthEmailRedeemPath, applicationAuthEmailRedeemRequest{Token: token})
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

// logLines hands each line the global logger writes to a channel.
type logLines chan string

func (l logLines) Write(line []byte) (int, error) {
	l <- string(line)
	return len(line), nil
}

// The one place the gate logs is a mail that was not sent, with the SMTP error. A
// server that echoes what it was sent must not put the password in the log. Not
// parallel: it replaces the global logger.
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
	if rec := postEmailJSON(gate, emailTestHost, applicationAuthEmailRequestPath, applicationAuthEmailRequest{Email: "alice@example.com"}); rec.Code != http.StatusAccepted {
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
