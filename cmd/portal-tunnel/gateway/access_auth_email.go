package gateway

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/mail"
	"net/smtp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/rs/zerolog/log"
)

var (
	errEmailSMTPAddrMustHostPort = errors.New("email smtp address must be host:port with a port from 1 to 65535")
	errEmailFromMustOneAddress   = errors.New("email sender must be one ASCII email address, optionally with a display name")
	errEmailAddressIsInvalid     = errors.New("email address is invalid")
	errEmailSMTPOffersNoSTARTTLS = errors.New("smtp server does not offer STARTTLS; only a server on a loopback address may be reached without TLS")
	errEmailHeaderHasLineBreak   = errors.New("email header value contains a line break")
	errEmailRequestHostNotPublic = errors.New("request host is not a public address of this tunnel")
	errEmailLinkInvalidOrExpired = errors.New("email link is invalid, used, or expired")
	errEmailSendSlotsAreAllInUse = errors.New("every email send slot is in use")
)

const (
	applicationAuthEmailRequestPath = "/_portal/auth/email/request"
	applicationAuthEmailRedeemPath  = "/_portal/auth/email/redeem"
	// emailLinkTTL is how long a login link works.
	emailLinkTTL = 10 * time.Minute
	// emailSendTimeout bounds one SMTP conversation, from the dial to QUIT.
	emailSendTimeout = 30 * time.Second
	// emailSendSlots bounds the SMTP conversations in flight at once.
	emailSendSlots = 4
	// One address gets at most one link per emailAddressCooldown and
	// emailAddressHourlyLimit links per hour, and the tunnel sends at most
	// emailHourlyLimit links per hour, so a public URL can neither flood an
	// allowed mailbox nor use up the SMTP account's quota.
	emailAddressCooldown    = time.Minute
	emailAddressHourlyLimit = 5
	emailHourlyLimit        = 50
	// emailAddressLimit is the longest address SMTP delivers (RFC 5321 4.5.3.1.3).
	emailAddressLimit = 254
	// emailImplicitTLSPort is the submission port that starts with TLS (RFC 8314).
	emailImplicitTLSPort = "465"
	// emailLinkTokenBytes is the size of the secret in a login link: 256 bits.
	emailLinkTokenBytes = 32
)

// emailAuthenticator mails one-time login links through the operator's SMTP
// server. A link is a random token that is kept only as its SHA-256 digest,
// with the address and host it was mailed for; it works once, at that host,
// for emailLinkTTL. Each link is admitted by the send limits first, and the
// sends of the last hour are at most emailHourlyLimit, so the links and the
// sends it remembers stay bounded by that limit. A restart forgets them all.
type emailAuthenticator struct {
	smtpAddr    string
	smtpHost    string
	implicitTLS bool
	username    string
	password    string
	from        mail.Address
	publicURLs  func() []string

	sendSlots chan struct{}

	mu    sync.Mutex
	links map[[sha256.Size]byte]emailLink
	// sent holds the sends of the last hour, oldest first.
	sent []emailSend
}

// emailLink is what a login link stands for until it is used or expires.
type emailLink struct {
	email     string
	host      string
	next      string
	expiresAt time.Time
}

type emailSend struct {
	email string
	at    time.Time
}

type applicationAuthEmailRequest struct {
	Email string `json:"email"`
	Next  string `json:"next,omitempty"`
}

type applicationAuthEmailRedeemRequest struct {
	Token string `json:"token"`
}

func newEmailAuthenticator(settings applicationAuthSettings, publicURLs func() []string) *emailAuthenticator {
	host, port, _ := net.SplitHostPort(settings.emailSMTPAddr)
	return &emailAuthenticator{
		smtpAddr:    settings.emailSMTPAddr,
		smtpHost:    host,
		implicitTLS: port == emailImplicitTLSPort,
		username:    settings.emailSMTPUsername,
		password:    settings.emailSMTPPassword,
		from:        settings.emailFrom,
		publicURLs:  publicURLs,
		sendSlots:   make(chan struct{}, emailSendSlots),
		links:       make(map[[sha256.Size]byte]emailLink),
	}
}

// validateEmailSMTPAddr checks the host:port of the SMTP server. The transport
// follows from it: implicit TLS on port 465, STARTTLS on any other port, and
// plaintext only to a loopback host.
func validateEmailSMTPAddr(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("%w: %w", errEmailSMTPAddrMustHostPort, err)
	}
	number, err := strconv.Atoi(port)
	if host == "" || err != nil || number < 1 || number > 65535 || strings.ContainsFunc(host, unicode.IsControl) {
		return errEmailSMTPAddrMustHostPort
	}
	return nil
}

// parseEmailFrom reads the fixed sender, the From header and the envelope
// sender of every link. It must be one address; a display name is kept for the
// header only.
func parseEmailFrom(raw string) (mail.Address, error) {
	if strings.ContainsFunc(raw, unicode.IsControl) {
		return mail.Address{}, errEmailFromMustOneAddress
	}
	from, err := mail.ParseAddress(raw)
	if err != nil {
		return mail.Address{}, fmt.Errorf("%w: %w", errEmailFromMustOneAddress, err)
	}
	if strings.ContainsFunc(from.Address, func(r rune) bool { return r > unicode.MaxASCII }) {
		return mail.Address{}, errEmailFromMustOneAddress
	}
	return *from, nil
}

// normalizeVisitorEmail reads the address a visitor typed. It must be a bare
// address that net/mail reads back unchanged, so a display name, a comment, a
// quoted local part or a line break is refused, and it is normalized like an
// allowlist entry.
func normalizeVisitorEmail(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > emailAddressLimit || strings.ContainsFunc(raw, unicode.IsControl) {
		return "", errEmailAddressIsInvalid
	}
	parsed, err := mail.ParseAddress(raw)
	if err != nil || parsed.Name != "" || parsed.Address != raw {
		return "", errEmailAddressIsInvalid
	}
	email := providerEmail(parsed.Address)
	if email == "" {
		return "", errEmailAddressIsInvalid
	}
	return email, nil
}

// publicHost returns the host of the tunnel's current public URL that
// requestHost, a normalized request host, names. A link mailed for any other
// host would send its token to whoever answers there, so the mail takes its
// host from this list and never from the request.
func (e *emailAuthenticator) publicHost(requestHost string) (string, bool) {
	if e.publicURLs == nil {
		return "", false
	}
	for _, raw := range e.publicURLs() {
		if public, err := NormalizeApplicationAuthHost(raw); err == nil && public == requestHost {
			return public, true
		}
	}
	return "", false
}

// admit records a send to email at now if the limits allow one. The caller
// holds e.mu.
func (e *emailAuthenticator) admit(email string, now time.Time) bool {
	hourAgo := now.Add(-time.Hour)
	e.sent = slices.DeleteFunc(e.sent, func(send emailSend) bool { return !send.at.After(hourAgo) })
	if len(e.sent) >= emailHourlyLimit {
		return false
	}
	count := 0
	for _, send := range e.sent {
		if send.email != email {
			continue
		}
		if now.Sub(send.at) < emailAddressCooldown {
			return false
		}
		count++
	}
	if count >= emailAddressHourlyLimit {
		return false
	}
	e.sent = append(e.sent, emailSend{email: email, at: now})
	return true
}

// issue creates the link for a send to email at host that returns the visitor
// to next. It returns the token, or "" when a limit refuses the send.
func (e *emailAuthenticator) issue(email, host, next string, now time.Time) string {
	var secret [emailLinkTokenBytes]byte
	_, _ = rand.Read(secret[:])
	token := base64.RawURLEncoding.EncodeToString(secret[:])

	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.admit(email, now) {
		return ""
	}
	for key, link := range e.links {
		if !now.Before(link.expiresAt) {
			delete(e.links, key)
		}
	}
	e.links[sha256.Sum256([]byte(token))] = emailLink{email: email, host: host, next: next, expiresAt: now.Add(emailLinkTTL)}
	return token
}

// redeem uses up the link of token. It returns the address and target of a
// link that was mailed for host and has not expired. Any link it finds is
// forgotten, so a link works at most once.
func (e *emailAuthenticator) redeem(token, host string, now time.Time) (email, next string, ok bool) {
	key := sha256.Sum256([]byte(strings.TrimSpace(token)))
	e.mu.Lock()
	link, found := e.links[key]
	delete(e.links, key)
	e.mu.Unlock()
	if !found || !now.Before(link.expiresAt) || !sameApplicationHost(link.host, host) {
		return "", "", false
	}
	return link.email, link.next, true
}

// send mails a login link for email at host, unless a limit refuses it. The
// SMTP conversation runs in its own goroutine, so the caller answers before it
// starts and an allowed address answers as fast as a refused one. At most
// emailSendSlots conversations run at once, each within emailSendTimeout.
func (e *emailAuthenticator) send(email, host, next string, now time.Time) {
	token := e.issue(email, host, next, now)
	if token == "" {
		return
	}
	select {
	case e.sendSlots <- struct{}{}:
	default:
		log.Warn().Err(errEmailSendSlotsAreAllInUse).Str("smtp_addr", e.smtpAddr).Msg("email login link not sent")
		return
	}
	go func() {
		defer func() { <-e.sendSlots }()
		ctx, cancel := context.WithTimeout(context.Background(), emailSendTimeout)
		defer cancel()
		// The error comes from composing the mail, the SMTP server or the
		// connection and never holds the password; the recipient stays out of
		// the log.
		message, err := emailLoginMessage(e.from, email, host, token, now)
		if err == nil {
			err = e.deliver(ctx, email, message)
		}
		if err != nil {
			log.Warn().Err(err).Str("smtp_addr", e.smtpAddr).Msg("email login link not sent")
		}
	}()
}

// check signs in to the SMTP server and quits without sending, so that a wrong
// address, TLS setup or password shows when the tunnel starts.
func (e *emailAuthenticator) check(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, emailSendTimeout)
	defer cancel()
	client, err := e.dial(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()
	return client.Quit()
}

func (e *emailAuthenticator) deliver(ctx context.Context, to string, message []byte) error {
	client, err := e.dial(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()
	if err := client.Mail(e.from.Address); err != nil {
		return fmt.Errorf("smtp MAIL FROM: %w", err)
	}
	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("smtp RCPT TO: %w", err)
	}
	data, err := client.Data()
	if err != nil {
		return fmt.Errorf("smtp DATA: %w", err)
	}
	if _, err := data.Write(message); err != nil {
		return fmt.Errorf("smtp DATA: %w", err)
	}
	if err := data.Close(); err != nil {
		return fmt.Errorf("smtp DATA: %w", err)
	}
	return client.Quit()
}

// dial opens a signed-in SMTP session within the deadline of ctx: implicit TLS
// on port 465, otherwise STARTTLS, which the server must offer unless it is on
// a loopback host. Only there does the session stay plaintext.
func (e *emailAuthenticator) dial(ctx context.Context) (*smtp.Client, error) {
	tlsConfig := &tls.Config{ServerName: e.smtpHost, MinVersion: tls.VersionTLS12}
	var conn net.Conn
	var err error
	if e.implicitTLS {
		conn, err = (&tls.Dialer{Config: tlsConfig}).DialContext(ctx, "tcp", e.smtpAddr)
	} else {
		conn, err = (&net.Dialer{}).DialContext(ctx, "tcp", e.smtpAddr)
	}
	if err != nil {
		return nil, fmt.Errorf("connect to smtp server: %w", err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	client, err := smtp.NewClient(conn, e.smtpHost)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("smtp greeting: %w", err)
	}
	if err := e.secureAndSignIn(client); err != nil {
		_ = client.Close()
		return nil, err
	}
	return client, nil
}

func (e *emailAuthenticator) secureAndSignIn(client *smtp.Client) error {
	if !e.implicitTLS && !isLoopbackHost(e.smtpHost) {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return errEmailSMTPOffersNoSTARTTLS
		}
		if err := client.StartTLS(&tls.Config{ServerName: e.smtpHost, MinVersion: tls.VersionTLS12}); err != nil {
			return fmt.Errorf("smtp STARTTLS: %w", err)
		}
	}
	if e.username == "" {
		return nil
	}
	if err := client.Auth(smtp.PlainAuth("", e.username, e.password, e.smtpHost)); err != nil {
		return fmt.Errorf("smtp AUTH: %w", err)
	}
	return nil
}

// emailLoginMessage is the one mail the tunnel sends: fixed text, the host the
// link is for, and the link. The token is in the fragment, as in a credential
// redeem link, so a mail scanner or link preview that fetches the URL cannot
// use it up; only the sign-in page posts it.
func emailLoginMessage(from mail.Address, to, host, token string, now time.Time) ([]byte, error) {
	_, fromDomain, _ := strings.Cut(from.Address, "@")
	link := "https://" + host + applicationAuthLoginPath + "#email_token=" + token
	headers := [][2]string{
		{"From", from.String()},
		{"To", to},
		{"Subject", "Sign in to " + host},
		{"Date", now.Format(time.RFC1123Z)},
		{"Message-ID", "<" + rand.Text() + "@" + fromDomain + ">"},
		{"MIME-Version", "1.0"},
		{"Content-Type", "text/plain; charset=utf-8"},
		{"Content-Transfer-Encoding", "7bit"},
		{"Auto-Submitted", "auto-generated"},
	}
	var message strings.Builder
	for _, header := range headers {
		if strings.ContainsAny(header[1], "\r\n") {
			return nil, errEmailHeaderHasLineBreak
		}
		message.WriteString(header[0] + ": " + header[1] + "\r\n")
	}
	message.WriteString("\r\n")
	for _, line := range []string{
		"Use this link to sign in to https://" + host + ":",
		"",
		link,
		"",
		"The link works once and expires in " + strconv.Itoa(int(emailLinkTTL.Minutes())) + " minutes.",
		"If you did not ask to sign in, you can ignore this email.",
	} {
		message.WriteString(line + "\r\n")
	}
	return []byte(message.String()), nil
}

// serveEmailRequest mails a login link to an allowed address. Every address
// that is well formed gets the same answer, whether it is allowed, refused by
// a limit or mailed, and the mail goes out after the answer, so neither the
// answer nor its timing tells who may sign in.
func (a *applicationAuth) serveEmailRequest(w http.ResponseWriter, r *http.Request) {
	if a.provider != ApplicationAuthProviderEmail || a.email == nil {
		a.writeJSONError(w, http.StatusNotFound, "not found")
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		a.writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !sameOrigin(r) {
		a.writeJSONError(w, http.StatusForbidden, "request origin is not allowed")
		return
	}
	var req applicationAuthEmailRequest
	if err := decodeApplicationAuthJSON(w, r, &req); err != nil {
		a.writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	email, err := normalizeVisitorEmail(req.Email)
	if err != nil {
		a.writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	requestHost, err := NormalizeApplicationAuthHost(r.Host)
	if err != nil {
		a.writeJSONError(w, http.StatusForbidden, errEmailRequestHostNotPublic.Error())
		return
	}
	host, public := a.email.publicHost(requestHost)
	if !public {
		a.writeJSONError(w, http.StatusForbidden, errEmailRequestHostNotPublic.Error())
		return
	}
	if a.subjectAllowed(email) {
		a.email.send(email, host, sanitizeApplicationAuthNext(req.Next), time.Now().UTC())
	}
	a.writeJSON(w, http.StatusAccepted, struct{}{})
}

// serveEmailRedeem turns a login link into the session every provider
// creates. The allowlist is checked again, so an entry removed after the link
// was mailed refuses it.
func (a *applicationAuth) serveEmailRedeem(w http.ResponseWriter, r *http.Request) {
	if a.provider != ApplicationAuthProviderEmail || a.email == nil {
		a.writeJSONError(w, http.StatusNotFound, "not found")
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		a.writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !sameOrigin(r) {
		a.writeJSONError(w, http.StatusForbidden, "request origin is not allowed")
		return
	}
	var req applicationAuthEmailRedeemRequest
	if err := decodeApplicationAuthJSON(w, r, &req); err != nil {
		a.writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	now := time.Now().UTC()
	email, next, ok := a.email.redeem(req.Token, r.Host, now)
	if !ok || !a.subjectAllowed(email) {
		a.writeJSONError(w, http.StatusUnauthorized, errEmailLinkInvalidOrExpired.Error())
		return
	}
	if err := a.setSession(w, email, ApplicationAuthProviderEmail, strings.TrimSpace(r.Host), now, now.Add(applicationAuthSessionTTL)); err != nil {
		a.writeJSONError(w, http.StatusInternalServerError, "could not create session")
		return
	}
	a.writeJSON(w, http.StatusOK, map[string]string{"subject": email, "next": sanitizeApplicationAuthNext(next)})
}
