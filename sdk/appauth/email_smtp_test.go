package appauth

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"strings"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

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
