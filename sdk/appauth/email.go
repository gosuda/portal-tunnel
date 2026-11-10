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

	"github.com/gosuda/portal-tunnel/v2/types"
)

var (
	errSMTPAddrMustHostPort      = errors.New("email smtp address must be host:port with a port from 1 to 65535")
	errSMTPFromMustOneAddress    = errors.New("email sender must be one ASCII email address, optionally with a display name")
	errEmailAddressIsInvalid     = errors.New("email address is invalid")
	errEmailSMTPOffersNoSTARTTLS = errors.New("smtp server does not offer STARTTLS; only a server at localhost, 127.0.0.1 or ::1 may be reached without TLS")
	errEmailHeaderHasLineBreak   = errors.New("email header value contains a line break")
	errEmailLinkInvalidOrExpired = errors.New("email link is invalid, used, or expired")
	errEmailSendSlotsAreAllInUse = errors.New("every email send slot is in use")
)

const (
	emailLinkTTL            = 10 * time.Minute
	emailSendTimeout        = 30 * time.Second
	emailSendSlots          = 4
	emailAddressCooldown    = time.Minute
	emailAddressHourlyLimit = 5
	emailDomainHourlyLimit  = 50
	emailAddressLimit       = 254
	emailImplicitTLSPort    = 465
	emailLinkTokenBytes     = 32
	emailRoutingCharacters  = "%!"
)

type emailAuthenticator struct {
	smtpAddr    string
	smtpHost    string
	implicitTLS bool
	username    string
	password    string
	from        mail.Address
	binding     string

	sendSlots chan struct{}

	mu    sync.Mutex
	links map[[sha256.Size]byte]emailLink
	sent  []emailSend
}

type emailLink struct {
	hostEpoch string
	email     string
	host      string
	next      string
	expiresAt time.Time
}

type emailSend struct {
	email  string
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

func newEmailAuthenticator(settings applicationAuthSettings) *emailAuthenticator {
	host, port, _ := net.SplitHostPort(settings.emailSMTPAddr)
	portNumber, _ := strconv.Atoi(port)
	binding := sha256.Sum256([]byte(settings.emailSMTPAddr + "\x00" + settings.emailSMTPUsername + "\x00" + settings.emailFrom.Address))
	return &emailAuthenticator{
		smtpAddr:    settings.emailSMTPAddr,
		smtpHost:    host,
		implicitTLS: portNumber == emailImplicitTLSPort,
		username:    settings.emailSMTPUsername,
		password:    settings.emailSMTPPassword,
		from:        settings.emailFrom,
		binding:     base64.RawURLEncoding.EncodeToString(binding[:]),
		sendSlots:   make(chan struct{}, emailSendSlots),
		links:       make(map[[sha256.Size]byte]emailLink),
	}
}

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

func (e *emailAuthenticator) issue(email string, listed bool, host, hostEpoch, next string, now time.Time) string {
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
	e.links[sha256.Sum256([]byte(token))] = emailLink{email: email, host: host, hostEpoch: hostEpoch, next: next, expiresAt: now.Add(emailLinkTTL)}
	return token
}

func (e *emailAuthenticator) redeem(token, host, hostEpoch string, heldSince, now time.Time) (email, next string, ok bool) {
	key := sha256.Sum256([]byte(strings.TrimSpace(token)))
	e.mu.Lock()
	link, found := e.links[key]
	delete(e.links, key)
	e.mu.Unlock()
	if !found || !now.Before(link.expiresAt) || !sameApplicationHost(link.host, host) || link.hostEpoch != hostEpoch || link.expiresAt.Add(-emailLinkTTL).Before(heldSince) {
		return "", "", false
	}
	return link.email, link.next, true
}

func (e *emailAuthenticator) send(email string, listed bool, host, hostEpoch, next string, now time.Time) {
	token := e.issue(email, listed, host, hostEpoch, next, now)
	if token == "" {
		return
	}
	go func() {
		defer func() { <-e.sendSlots }()
		ctx, cancel := context.WithTimeout(context.Background(), emailSendTimeout)
		defer cancel()
		message, err := emailLoginMessage(e.from, host, token, now)
		if err == nil {
			err = e.deliver(ctx, email, message)
		}
		if err != nil {
			log.Warn().Err(err).Str("smtp_addr", e.smtpAddr).Msg("email login link not sent")
		}
	}()
}

func (e *emailAuthenticator) check(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, emailSendTimeout)
	defer cancel()
	client, err := e.dial(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()
	_ = client.Quit()
	return nil
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
	_ = client.Quit()
	return nil
}

func smtpReplyCode(err error) error {
	var reply *textproto.Error
	if errors.As(err, &reply) {
		return fmt.Errorf("server replied %d", reply.Code)
	}
	return err
}

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
	if err := e.secureAndSignIn(client, tlsConfig); err != nil {
		_ = client.Close()
		return nil, err
	}
	return client, nil
}

func emailPlaintextHost(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

func (e *emailAuthenticator) secureAndSignIn(client *smtp.Client, tlsConfig *tls.Config) error {
	if !e.implicitTLS && !emailPlaintextHost(e.smtpHost) {
		if err := client.Hello("localhost"); err != nil {
			return fmt.Errorf("smtp EHLO: %w", err)
		}
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return errEmailSMTPOffersNoSTARTTLS
		}
		if err := client.StartTLS(tlsConfig); err != nil {
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

func emailLoginMessage(from mail.Address, host, token string, now time.Time) ([]byte, error) {
	_, fromDomain, _ := strings.Cut(from.Address, "@")
	link := "https://" + host + types.PathApplicationAuthLogin + "#email_token=" + token
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
	host, held, public := a.publicHost(r.Host)
	if !public {
		a.writeJSONError(w, http.StatusMisdirectedRequest, errRequestHostNotPublic.Error())
		return
	}
	if a.subjectAllowed(email) {
		_, listed := a.allowedSubjects[email]
		a.email.send(email, listed, host, held.Epoch, sanitizeApplicationAuthNext(req.Next), time.Now().UTC())
	}
	a.writeJSON(w, http.StatusAccepted, struct{}{})
}

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
	now := time.Now().UTC()
	email, next, ok := a.email.redeem(req.Token, r.Host, a.hostEpoch(r.Host), a.heldSince(r.Host), now)
	if !ok || !a.subjectAllowed(email) {
		a.writeJSONError(w, http.StatusUnauthorized, errEmailLinkInvalidOrExpired.Error())
		return
	}
	if err := a.setSession(w, Principal{Provider: ProviderEmail, Subject: email, Email: email}, strings.TrimSpace(r.Host), now, now.Add(applicationAuthSessionTTL)); err != nil {
		a.writeJSONError(w, http.StatusInternalServerError, "could not create session")
		return
	}
	a.writeJSON(w, http.StatusOK, map[string]string{"subject": email, "next": next})
}
