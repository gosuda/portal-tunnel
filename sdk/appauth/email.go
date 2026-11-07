package appauth

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
	"net/textproto"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/rs/zerolog/log"
)

var (
	errSMTPAddrMustHostPort      = errors.New("email smtp address must be host:port with a port from 1 to 65535")
	errSMTPFromMustOneAddress    = errors.New("email sender must be one ASCII email address, optionally with a display name")
	errEmailAddressIsInvalid     = errors.New("email address is invalid")
	errEmailSMTPOffersNoSTARTTLS = errors.New("smtp server does not offer STARTTLS; only a server at localhost, 127.0.0.1 or ::1 may be reached without TLS")
	errEmailHeaderHasLineBreak   = errors.New("email header value contains a line break")
	errEmailRequestHostNotPublic = errors.New("request host is not a public address of this tunnel")
	errEmailLinkInvalidOrExpired = errors.New("email link is invalid, used, or expired")
	errEmailSendSlotsAreAllInUse = errors.New("every email send slot is in use")
)

const (
	applicationAuthEmailRequestPath = ReservedPathPrefix + "email/request"
	applicationAuthEmailRedeemPath  = ReservedPathPrefix + "email/redeem"
	// emailLinkTTL is how long a login link works.
	emailLinkTTL = 10 * time.Minute
	// emailSendTimeout bounds one SMTP conversation, from the dial to QUIT.
	emailSendTimeout = 30 * time.Second
	// emailSendSlots bounds the SMTP conversations in flight at once.
	emailSendSlots = 4
	// One address gets at most one link per emailAddressCooldown and
	// emailAddressHourlyLimit links per hour, so a public URL cannot flood an
	// exactly listed mailbox. The addresses that only an @domain entry allows are
	// unbounded, and alice+1@ and alice+2@ can reach one mailbox, so together
	// they get at most emailDomainHourlyLimit links per hour, which bounds that
	// mailbox and the SMTP account's quota. An exactly listed address is outside
	// that budget, so a flood of made-up addresses in a domain cannot lock it out.
	emailAddressCooldown    = time.Minute
	emailAddressHourlyLimit = 5
	emailDomainHourlyLimit  = 50
	// emailAddressLimit is the longest address SMTP delivers (RFC 5321 4.5.3.1.3).
	emailAddressLimit = 254
	// emailImplicitTLSPort is the submission port that starts with TLS (RFC 8314).
	emailImplicitTLSPort = "465"
	// emailLinkTokenBytes is the size of the secret in a login link: 256 bits.
	emailLinkTokenBytes = 32
	// emailRoutingCharacters are ordinary address characters to net/mail, but a
	// mail server can route on them: user%evil.example@team.example passes an
	// @team.example entry, and such a server delivers it to evil.example.
	emailRoutingCharacters = "%!"
)

// emailAuthenticator mails one-time login links through the operator's SMTP
// server. A link is a random token that is kept only as its SHA-256 digest,
// with the address and host it was mailed for; it works once, at that host,
// for emailLinkTTL. Each link is admitted by the send limits first, so the
// links and the sends it remembers stay bounded by the limits and the number
// of exactly listed addresses. A restart forgets them all.
type emailAuthenticator struct {
	smtpAddr    string
	smtpHost    string
	implicitTLS bool
	username    string
	password    string
	from        mail.Address
	publicURLs  func() []string
	// binding digests the SMTP server, the username and the sender into every
	// email session, so a change of the mail account ends the sessions of the
	// links it mailed. The password stays out: a session cookie must not carry
	// anything to guess it from.
	binding string

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
	// listed says whether an exact allowlist entry allows the address, not
	// only an @domain entry.
	listed bool
	at     time.Time
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
	// None of the settings can hold a NUL, so the separators keep them unambiguous.
	binding := sha256.Sum256([]byte(settings.emailSMTPAddr + "\x00" + settings.emailSMTPUsername + "\x00" + settings.emailFrom.Address))
	return &emailAuthenticator{
		smtpAddr:    settings.emailSMTPAddr,
		smtpHost:    host,
		implicitTLS: port == emailImplicitTLSPort,
		username:    settings.emailSMTPUsername,
		password:    settings.emailSMTPPassword,
		from:        settings.emailFrom,
		publicURLs:  publicURLs,
		binding:     base64.RawURLEncoding.EncodeToString(binding[:]),
		sendSlots:   make(chan struct{}, emailSendSlots),
		links:       make(map[[sha256.Size]byte]emailLink),
	}
}

// validateSMTPAddr checks the host:port of the SMTP server. The transport
// follows from it: implicit TLS on port 465, STARTTLS on any other port, and
// plaintext only to a local host (see emailPlaintextHost).
func validateSMTPAddr(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("%w: %w", errSMTPAddrMustHostPort, err)
	}
	number, err := strconv.Atoi(port)
	if host == "" || err != nil || number < 1 || number > 65535 || strings.ContainsFunc(host, unicode.IsControl) {
		return errSMTPAddrMustHostPort
	}
	return nil
}

// parseSMTPFrom reads the fixed sender, the From header and the envelope
// sender of every link. It must be one address; a display name is kept for the
// header only.
func parseSMTPFrom(raw string) (mail.Address, error) {
	if strings.ContainsFunc(raw, unicode.IsControl) {
		return mail.Address{}, errSMTPFromMustOneAddress
	}
	from, err := mail.ParseAddress(raw)
	if err != nil {
		return mail.Address{}, fmt.Errorf("%w: %w", errSMTPFromMustOneAddress, err)
	}
	if strings.ContainsFunc(from.Address, func(r rune) bool { return r > unicode.MaxASCII }) {
		return mail.Address{}, errSMTPFromMustOneAddress
	}
	return *from, nil
}

// normalizeVisitorEmail reads the address a visitor typed. It must be a bare
// address that net/mail reads back unchanged, so a display name, a comment, a
// quoted local part or a line break is refused, and it is normalized like an
// allowlist entry. An address that names a route is refused too, because the
// allowlist only vouches for the domain after the last @.
func normalizeVisitorEmail(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > emailAddressLimit || strings.ContainsFunc(raw, unicode.IsControl) || strings.ContainsAny(raw, emailRoutingCharacters) {
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
// requestHost, a request's Host, names. A link mailed for any other host would
// send its token to whoever answers there, so the mail takes its host from this
// list and never from the request.
func (e *emailAuthenticator) publicHost(rawHost string) (string, bool) {
	requestHost, err := normalizeHost(rawHost)
	if err != nil || e.publicURLs == nil {
		return "", false
	}
	for _, raw := range e.publicURLs() {
		if public, err := normalizeHost(raw); err == nil && public == requestHost {
			return public, true
		}
	}
	return "", false
}

// admit records a send to email at now and takes a send slot for it, if the
// limits and the slots allow one. listed says whether an exact allowlist entry
// allows email. The slot comes last, so a request the limits refuse never holds
// one, and a send dropped for a busy slot spends no limit. The caller holds e.mu.
func (e *emailAuthenticator) admit(email string, listed bool, now time.Time) bool {
	hourAgo := now.Add(-time.Hour)
	e.sent = slices.DeleteFunc(e.sent, func(send emailSend) bool { return !send.at.After(hourAgo) })
	count, domainCount := 0, 0
	for _, send := range e.sent {
		if !send.listed {
			domainCount++
		}
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
	if !listed && domainCount >= emailDomainHourlyLimit {
		return false
	}
	select {
	case e.sendSlots <- struct{}{}:
	default:
		log.Warn().Err(errEmailSendSlotsAreAllInUse).Str("smtp_addr", e.smtpAddr).Msg("email login link not sent")
		return false
	}
	e.sent = append(e.sent, emailSend{email: email, listed: listed, at: now})
	return true
}

// issue creates the link for a send to email at host that returns the visitor
// to next. It returns the token, and the send owns a slot from then on, or ""
// when a limit or the slots refuse the send.
func (e *emailAuthenticator) issue(email string, listed bool, host, next string, now time.Time) string {
	var secret [emailLinkTokenBytes]byte
	_, _ = rand.Read(secret[:])
	token := base64.RawURLEncoding.EncodeToString(secret[:])

	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.admit(email, listed, now) {
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
func (e *emailAuthenticator) send(email string, listed bool, host, next string, now time.Time) {
	token := e.issue(email, listed, host, next, now)
	if token == "" {
		return
	}
	go func() {
		defer func() { <-e.sendSlots }()
		ctx, cancel := context.WithTimeout(context.Background(), emailSendTimeout)
		defer cancel()
		// The error comes from composing the mail, the SMTP server or the
		// connection and never holds the password, and deliver keeps the
		// recipient out of it.
		message, err := emailLoginMessage(e.from, host, token, now)
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

// deliver hands one mail to the SMTP server. The replies from RCPT on are about
// the recipient and can quote the address, so their errors keep only the code.
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
		return fmt.Errorf("smtp RCPT TO: %w", smtpReplyCode(err))
	}
	data, err := client.Data()
	if err != nil {
		return fmt.Errorf("smtp DATA: %w", smtpReplyCode(err))
	}
	if _, err := data.Write(message); err != nil {
		return fmt.Errorf("smtp DATA: %w", err)
	}
	if err := data.Close(); err != nil {
		return fmt.Errorf("smtp DATA: %w", smtpReplyCode(err))
	}
	// The server took the mail at the end of DATA, so a failed QUIT is not a
	// failed send.
	_ = client.Quit()
	return nil
}

// smtpReplyCode reduces an SMTP reply to its code.
func smtpReplyCode(err error) error {
	var reply *textproto.Error
	if errors.As(err, &reply) {
		return fmt.Errorf("server replied %d", reply.Code)
	}
	return err
}

// dial opens a signed-in SMTP session within the deadline of ctx: implicit TLS
// on port 465, otherwise STARTTLS, which the server must offer unless its host
// is a local one (see emailPlaintextHost). Only there does the session stay
// plaintext.
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

// emailPlaintextHost reports whether an SMTP session to host may stay
// plaintext: only for the names net/smtp itself sends a password to without
// TLS, so that a plaintext session can always sign in.
func emailPlaintextHost(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

func (e *emailAuthenticator) secureAndSignIn(client *smtp.Client) error {
	if !e.implicitTLS && !emailPlaintextHost(e.smtpHost) {
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
// link is for in its subject, and the link. A mail client makes a link of any URL
// in the text, so the login link is the only one: a visitor who taps another
// reaches the application, not the sign-in. The token is in the fragment, as in a credential
// redeem link, so a mail scanner or link preview that fetches the URL cannot
// use it up. The sign-in page posts it only after a click, so one that also runs
// the page cannot either. The recipient is named only in the SMTP envelope, with
// no To header, so nothing a visitor typed is part of the mail itself.
func emailLoginMessage(from mail.Address, host, token string, now time.Time) ([]byte, error) {
	_, fromDomain, _ := strings.Cut(from.Address, "@")
	link := "https://" + host + applicationAuthLoginPath + "#email_token=" + token
	headers := [][2]string{
		{"From", from.String()},
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
		"Use this link to sign in:",
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
	if a.provider != ProviderEmail || a.email == nil {
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
	host, public := a.email.publicHost(r.Host)
	if !public {
		a.writeJSONError(w, http.StatusForbidden, errEmailRequestHostNotPublic.Error())
		return
	}
	if a.subjectAllowed(email) {
		_, listed := a.allowedSubjects[email]
		a.email.send(email, listed, host, sanitizeApplicationAuthNext(req.Next), time.Now().UTC())
	}
	a.writeJSON(w, http.StatusAccepted, struct{}{})
}

// serveEmailRedeem turns a login link into the session every provider
// creates. The allowlist is checked again, so an entry removed after the link
// was mailed refuses it. So is the host: an alias this tunnel lost may have a new
// owner, who reads the link of whoever opens it there, and must not be able to
// replay it here.
func (a *applicationAuth) serveEmailRedeem(w http.ResponseWriter, r *http.Request) {
	if a.provider != ProviderEmail || a.email == nil {
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
	if _, public := a.email.publicHost(r.Host); !public {
		a.writeJSONError(w, http.StatusForbidden, errEmailRequestHostNotPublic.Error())
		return
	}
	now := time.Now().UTC()
	email, next, ok := a.email.redeem(req.Token, r.Host, now)
	if !ok || !a.subjectAllowed(email) {
		a.writeJSONError(w, http.StatusUnauthorized, errEmailLinkInvalidOrExpired.Error())
		return
	}
	if err := a.setSession(w, Principal{Provider: ProviderEmail, Subject: email, Email: email}, strings.TrimSpace(r.Host), now, now.Add(applicationAuthSessionTTL)); err != nil {
		a.writeJSONError(w, http.StatusInternalServerError, "could not create session")
		return
	}
	a.writeJSON(w, http.StatusOK, map[string]string{"subject": email, "next": sanitizeApplicationAuthNext(next)})
}
