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
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
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

func (e *emailAuthenticator) redeem(token, host string, heldSince, now time.Time) (email, next string, ok bool) {
	key := sha256.Sum256([]byte(strings.TrimSpace(token)))
	e.mu.Lock()
	link, found := e.links[key]
	delete(e.links, key)
	e.mu.Unlock()
	if !found || !now.Before(link.expiresAt) || !sameApplicationHost(link.host, host) || link.expiresAt.Add(-emailLinkTTL).Before(heldSince) {
		return "", "", false
	}
	return link.email, link.next, true
}

func (e *emailAuthenticator) send(email string, listed bool, host, next string, now time.Time) {
	token := e.issue(email, listed, host, next, now)
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
	if err := writeEmailDeliverData(client, message); err != nil {
		return err
	}
	_ = client.Quit()
	return nil
}

func writeEmailDeliverData(client *smtp.Client, message []byte) error {
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
	host, _, public := a.publicHost(r.Host)
	if !public {
		a.writeJSONError(w, http.StatusMisdirectedRequest, errRequestHostNotPublic.Error())
		return
	}
	if a.subjectAllowed(email) {
		_, listed := a.allowedSubjects[email]
		a.email.send(email, listed, host, sanitizeApplicationAuthNext(req.Next), time.Now().UTC())
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
	email, next, ok := a.email.redeem(req.Token, r.Host, a.heldSince(r.Host), now)
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

var (
	errIdentityProofAuthIdentityProofAuth       = errors.New("identity proof (--auth-identity-proof / AUTH_IDENTITY_PROOF) requires --auth-identity-headers")
	errOIDCSettingsRequireOIDCApplicationAuth   = errors.New("oidc settings require the oidc application auth provider")
	errOIDCRequiresEmailList                    = errors.New("oidc requires at least one --auth-email-list entry: an email address, an @domain, or sub:<subject>")
	errOIDCClientIDIsRequired                   = errors.New("oidc client id is required")
	errSAMLSettingsRequireSAMLApplicationAuth   = errors.New("saml settings require the saml application auth provider")
	errSAMLRequiresEmailList                    = errors.New("saml requires at least one --auth-email-list entry: an email address, an @domain, or sub:<subject>")
	errSAMLMetadataIsRequired                   = errors.New("saml requires identity provider metadata: --auth-saml-metadata-url or --auth-saml-metadata-file")
	errSAMLMetadataSourcesConflict              = errors.New("saml metadata comes from --auth-saml-metadata-url or --auth-saml-metadata-file, not both")
	errEmailSettingsRequireEmailApplicationAuth = errors.New("email settings require the email application auth provider")
	errEmailRequiresEmailList                   = errors.New("email requires at least one --auth-email-list entry: an email address or an @domain")
	errEmailListRequiresEmailProvider           = errors.New("--auth-email-list works with oidc, saml, and email; siwe and credential use --auth-allow")
	errEmailProviderTakesEmailList              = errors.New("email reads its addresses from --auth-email-list, not --auth-allow")
	errAllowlistIsSetTwice                      = errors.New("--auth-email-list and --auth-allow are the same list: set one")
	errEmailAllowsNoSubjectEntries              = errors.New("email allows email addresses and @domain entries only, not sub:<subject>")
	errSMTPAddrIsRequired                       = errors.New("email requires an SMTP server: --auth-smtp-addr host:port")
	errSMTPFromIsRequired                       = errors.New("email requires a sender address: --auth-smtp-from")
	errEmailSMTPCredentialsArePaired            = errors.New("email smtp username and password are set together or not at all")
	errTunnelIdentityIsRequired                 = errors.New("tunnel identity is required")
	errApplicationCredentialExpiryMustFuture    = errors.New("application credential expiry must be in the future")
	errApplicationCredentialIsRequired          = errors.New("application credential is required")
	errApplicationAuthHostIsRequired            = errors.New("application auth host is required")
	errApplicationAuthHostMustHTTPSURL          = errors.New("application auth host must be an HTTPS URL or hostname without a path")
	errApplicationCredentialIsInvalid           = errors.New("application credential is invalid")
	errApplicationCredentialInvalidOrExpired    = errors.New("application credential is invalid or expired")
	errApplicationCredentialSubjectMust1256     = errors.New("application credential subject must be 1 to 256 printable characters")
)

const (
	ProviderSIWE       = "siwe"
	ProviderCredential = "credential"
	ProviderOIDC       = "oidc"
	ProviderSAML       = "saml"
	ProviderEmail      = "email"

	applicationCredentialPrefix  = "pcred_"
	applicationCredentialVersion = 1
	applicationCredentialKeyUse  = "application-access-credential"
)

type applicationCredentialClaims struct {
	Version   int    `json:"v"`
	Subject   string `json:"sub"`
	Tunnel    string `json:"tunnel"`
	Host      string `json:"host"`
	ExpiresAt int64  `json:"exp"`
}

func normalizeProvider(provider string) (string, error) {
	provider = strings.ToLower(strings.TrimSpace(provider))
	switch provider {
	case ProviderSIWE:
		return ProviderSIWE, nil
	case ProviderCredential:
		return ProviderCredential, nil
	case ProviderOIDC:
		return ProviderOIDC, nil
	case ProviderSAML:
		return ProviderSAML, nil
	case ProviderEmail:
		return ProviderEmail, nil
	default:
		return "", fmt.Errorf("unsupported application auth provider %q", provider)
	}
}

type applicationAuthSettings struct {
	provider             string
	allowed              []string
	identityProof        string
	issuerURL            string
	clientID             string
	clientSecret         string
	samlMetadataURL      string
	samlMetadataFile     string
	samlEntityID         string
	samlSubjectAttribute string
	emailSMTPAddr        string
	emailSMTPUsername    string
	emailSMTPPassword    string
	emailFrom            mail.Address
}

// Validate checks the complete configuration of a gate, including the
// provider-specific OIDC, SAML and email settings and the allowlist. New runs the
// same checks and also needs what a config file does not hold: the identity and,
// for email, PublicHosts.
func Validate(cfg Config) error {
	_, err := resolveApplicationAuthConfig(cfg)
	return err
}

const minIdentityProofLength = 16

func resolveApplicationAuthConfig(cfg Config) (applicationAuthSettings, error) {
	provider, allowed, proof, err := baseResolveApplicationAuthConfig(cfg)
	if err != nil {
		return applicationAuthSettings{}, err
	}
	return buildGateSettings(provider, allowed, proof, cfg)
}

func buildGateSettings(provider string, allowed []string, proof string, cfg Config) (applicationAuthSettings, error) {
	cfg.OIDCIssuerURL = strings.TrimSpace(cfg.OIDCIssuerURL)
	cfg.OIDCClientID = strings.TrimSpace(cfg.OIDCClientID)
	cfg.OIDCClientSecret = strings.TrimSpace(cfg.OIDCClientSecret)
	cfg.SAMLMetadataURL = strings.TrimSpace(cfg.SAMLMetadataURL)
	cfg.SAMLMetadataFile = strings.TrimSpace(cfg.SAMLMetadataFile)
	cfg.SAMLEntityID = strings.TrimSpace(cfg.SAMLEntityID)
	cfg.SAMLSubjectAttribute = strings.TrimSpace(cfg.SAMLSubjectAttribute)
	cfg.SMTPAddr = strings.TrimSpace(cfg.SMTPAddr)
	cfg.SMTPUsername = strings.TrimSpace(cfg.SMTPUsername)
	cfg.SMTPPassword = strings.TrimSpace(cfg.SMTPPassword)
	cfg.SMTPFrom = strings.TrimSpace(cfg.SMTPFrom)
	hasOIDCSettings := cfg.OIDCIssuerURL != "" || cfg.OIDCClientID != "" || cfg.OIDCClientSecret != ""
	hasSAMLSettings := cfg.SAMLMetadataURL != "" || cfg.SAMLMetadataFile != "" || cfg.SAMLEntityID != "" || cfg.SAMLSubjectAttribute != ""
	hasEmailSettings := cfg.SMTPAddr != "" || cfg.SMTPUsername != "" || cfg.SMTPPassword != "" || cfg.SMTPFrom != ""
	if hasOIDCSettings && provider != ProviderOIDC {
		return applicationAuthSettings{}, errOIDCSettingsRequireOIDCApplicationAuth
	}
	if hasSAMLSettings && provider != ProviderSAML {
		return applicationAuthSettings{}, errSAMLSettingsRequireSAMLApplicationAuth
	}
	if hasEmailSettings && provider != ProviderEmail {
		return applicationAuthSettings{}, errEmailSettingsRequireEmailApplicationAuth
	}
	settings := applicationAuthSettings{provider: provider, allowed: allowed, identityProof: proof}
	switch provider {
	case ProviderOIDC:
		if err := completeOIDCSettings(&settings, cfg); err != nil {
			return applicationAuthSettings{}, err
		}
	case ProviderSAML:
		if err := completeSAMLSettings(&settings, cfg); err != nil {
			return applicationAuthSettings{}, err
		}
	case ProviderEmail:
		if err := completeEmailSettings(&settings, cfg); err != nil {
			return applicationAuthSettings{}, err
		}
	}
	return settings, nil
}

func baseResolveApplicationAuthConfig(cfg Config) (string, []string, string, error) {
	provider, err := normalizeProvider(cfg.Provider)
	if err != nil {
		return "", nil, "", err
	}
	allowed, err := resolveAllowlist(provider, cfg)
	if err != nil {
		return "", nil, "", err
	}
	if err := validateIdentityProof(cfg); err != nil {
		return "", nil, "", err
	}
	return provider, allowed, cfg.IdentityProof, nil
}

func validateIdentityProof(cfg Config) error {
	proof := cfg.IdentityProof
	if proof == "" {
		return nil
	}
	if !cfg.IdentityHeaders {
		return errIdentityProofAuthIdentityProofAuth
	}
	if len(proof) < minIdentityProofLength || strings.ContainsFunc(proof, func(r rune) bool { return r < 0x21 || r > 0x7e }) {
		return fmt.Errorf("identity proof (--auth-identity-proof / AUTH_IDENTITY_PROOF) must be at least %d characters of visible ASCII without spaces", minIdentityProofLength)
	}
	return nil
}

func completeOIDCSettings(settings *applicationAuthSettings, cfg Config) error {
	if len(settings.allowed) == 0 {
		return errOIDCRequiresEmailList
	}
	issuerURL, err := normalizeOIDCIssuerURL(cfg.OIDCIssuerURL)
	if err != nil {
		return err
	}
	if cfg.OIDCClientID == "" {
		return errOIDCClientIDIsRequired
	}
	settings.issuerURL = issuerURL
	settings.clientID = cfg.OIDCClientID
	settings.clientSecret = cfg.OIDCClientSecret
	return nil
}

func completeSAMLSettings(settings *applicationAuthSettings, cfg Config) error {
	if len(settings.allowed) == 0 {
		return errSAMLRequiresEmailList
	}
	switch {
	case cfg.SAMLMetadataURL == "" && cfg.SAMLMetadataFile == "":
		return errSAMLMetadataIsRequired
	case cfg.SAMLMetadataURL != "" && cfg.SAMLMetadataFile != "":
		return errSAMLMetadataSourcesConflict
	case cfg.SAMLMetadataURL != "":
		samlMetadataURL, err := normalizeSAMLMetadataURL(cfg.SAMLMetadataURL)
		if err != nil {
			return err
		}
		settings.samlMetadataURL = samlMetadataURL
	default:
		settings.samlMetadataFile = cfg.SAMLMetadataFile
	}
	if err := validateSAMLName("saml entity id", cfg.SAMLEntityID, samlEntityIDLimit); err != nil {
		return err
	}
	if err := validateSAMLName("saml subject attribute", cfg.SAMLSubjectAttribute, samlSubjectAttributeLimit); err != nil {
		return err
	}
	settings.samlEntityID = cfg.SAMLEntityID
	settings.samlSubjectAttribute = cfg.SAMLSubjectAttribute
	return nil
}

func completeEmailSettings(settings *applicationAuthSettings, cfg Config) error {
	if len(settings.allowed) == 0 {
		return errEmailRequiresEmailList
	}
	if cfg.SMTPAddr == "" {
		return errSMTPAddrIsRequired
	}
	if err := validateSMTPAddr(cfg.SMTPAddr); err != nil {
		return err
	}
	if cfg.SMTPFrom == "" {
		return errSMTPFromIsRequired
	}
	emailFrom, err := parseSMTPFrom(cfg.SMTPFrom)
	if err != nil {
		return err
	}
	settings.emailFrom = emailFrom
	if (cfg.SMTPUsername == "") != (cfg.SMTPPassword == "") {
		return errEmailSMTPCredentialsArePaired
	}
	settings.emailSMTPAddr = cfg.SMTPAddr
	settings.emailSMTPUsername = cfg.SMTPUsername
	settings.emailSMTPPassword = cfg.SMTPPassword
	return nil
}

// ProviderTakesEmailList reports whether provider names a visitor
// by email, so that it reads `--auth-email-list` / `auth_email_list`.
func ProviderTakesEmailList(provider string) bool {
	switch provider {
	case ProviderOIDC, ProviderSAML, ProviderEmail:
		return true
	default:
		return false
	}
}

func resolveAllowlist(provider string, cfg Config) ([]string, error) {
	switch {
	case len(cfg.EmailList) > 0 && len(cfg.Allow) > 0:
		return nil, errAllowlistIsSetTwice
	case len(cfg.EmailList) > 0 && !ProviderTakesEmailList(provider):
		return nil, errEmailListRequiresEmailProvider
	case len(cfg.Allow) > 0 && provider == ProviderEmail:
		return nil, errEmailProviderTakesEmailList
	}
	return normalizeAllowed(provider, cfg.Allowed())
}

func normalizeAllowed(provider string, values []string) ([]string, error) {
	provider, err := normalizeProvider(provider)
	if err != nil {
		return nil, err
	}
	switch provider {
	case ProviderSIWE:
		return identity.NormalizeEVMAddresses(values)
	case ProviderCredential:
		return normalizeSubjects(values)
	case ProviderOIDC, ProviderSAML:
		return normalizeProviderPrincipals(values)
	case ProviderEmail:
		allowed, err := normalizeProviderPrincipals(values)
		if err != nil {
			return nil, err
		}
		if err := validateEmailPrincipals(allowed); err != nil {
			return nil, err
		}
		return allowed, nil
	default:
		return nil, fmt.Errorf("unsupported application auth provider %q", provider)
	}
}

func validateEmailPrincipals(allowed []string) error {
	for _, principal := range allowed {
		if strings.HasPrefix(principal, subjectPrincipalPrefix) {
			return errEmailAllowsNoSubjectEntries
		}
		address := principal
		if strings.HasPrefix(principal, "@") {
			address = "a" + principal
		}
		if _, err := normalizeVisitorEmail(address); err != nil {
			return fmt.Errorf("principal %q: %w", principal, err)
		}
	}
	return nil
}

func normalizeSubjects(values []string) ([]string, error) {
	if len(values) == 0 {
		return nil, nil
	}
	normalized := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, raw := range values {
		subject, err := normalizeApplicationAuthSubject(raw)
		if err != nil {
			return nil, err
		}
		if _, ok := seen[subject]; ok {
			continue
		}
		seen[subject] = struct{}{}
		normalized = append(normalized, subject)
	}
	return normalized, nil
}

// IssueCredential creates a credential for one host and one identity. A gate
// built from that identity accepts it in a request header and exchanges it for a
// session.
func IssueCredential(id types.Identity, host, subject string, expiresAt time.Time) (string, error) {
	if id.Key() == "" {
		return "", errTunnelIdentityIsRequired
	}
	host, err := normalizeHost(host)
	if err != nil {
		return "", err
	}
	subject, err = normalizeApplicationAuthSubject(subject)
	if err != nil {
		return "", err
	}
	if expiresAt.UTC().Unix() <= time.Now().UTC().Unix() {
		return "", errApplicationCredentialExpiryMustFuture
	}
	key, err := identity.DeriveToken(id, applicationCredentialKeyUse)
	if err != nil {
		return "", fmt.Errorf("derive application credential key: %w", err)
	}
	token, err := encodeSignedApplicationAuthJSON([]byte(key), applicationCredentialClaims{
		Version:   applicationCredentialVersion,
		Subject:   subject,
		Tunnel:    id.Key(),
		Host:      host,
		ExpiresAt: expiresAt.UTC().Unix(),
	})
	if err != nil {
		return "", err
	}
	return applicationCredentialPrefix + token, nil
}

// CredentialRedeemURL returns the sign-in link of a credential. The credential
// travels in the fragment, so it reaches neither a relay nor a server log.
func CredentialRedeemURL(host, credential string) (string, error) {
	host, err := normalizeHost(host)
	if err != nil {
		return "", err
	}
	credential = strings.TrimSpace(credential)
	if credential == "" {
		return "", errApplicationCredentialIsRequired
	}
	return "https://" + host + types.PathApplicationAuthLogin + "#credential=" + url.QueryEscape(credential), nil
}

func normalizeHost(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errApplicationAuthHostIsRequired
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("%w: %w", errApplicationAuthHostMustHTTPSURL, err)
	}
	validAuthority := strings.EqualFold(parsed.Scheme, "https") && parsed.Host != "" && parsed.User == nil
	rootPath := parsed.Path == "" || parsed.Path == "/"
	if !validAuthority || !rootPath || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errApplicationAuthHostMustHTTPSURL
	}
	host := strings.TrimSuffix(strings.ToLower(parsed.Host), ":443")
	return strings.TrimSuffix(host, "."), nil
}

func sameApplicationHost(a, b string) bool {
	if strings.Contains(a, "/") || strings.Contains(b, "/") {
		return false
	}
	normalizedA, errA := normalizeHost(a)
	normalizedB, errB := normalizeHost(b)
	return errA == nil && errB == nil && normalizedA == normalizedB
}

func verifyApplicationCredential(key []byte, tunnelIdentity types.Identity, host, credential string, now time.Time) (applicationCredentialClaims, error) {
	credential = strings.TrimSpace(credential)
	if !strings.HasPrefix(credential, applicationCredentialPrefix) {
		return applicationCredentialClaims{}, errApplicationCredentialIsInvalid
	}
	var claims applicationCredentialClaims
	if err := decodeSignedApplicationAuthJSON(key, strings.TrimPrefix(credential, applicationCredentialPrefix), &claims); err != nil || claims.Version != applicationCredentialVersion || claims.Tunnel != tunnelIdentity.Key() {
		return applicationCredentialClaims{}, errApplicationCredentialIsInvalid
	}
	if !sameApplicationHost(claims.Host, host) || !now.UTC().Before(time.Unix(claims.ExpiresAt, 0)) {
		return applicationCredentialClaims{}, errApplicationCredentialInvalidOrExpired
	}
	subject, err := normalizeApplicationAuthSubject(claims.Subject)
	if err != nil {
		return applicationCredentialClaims{}, errApplicationCredentialIsInvalid
	}
	claims.Subject = subject
	return claims, nil
}

func normalizeApplicationAuthSubject(subject string) (string, error) {
	subject = strings.TrimSpace(subject)
	if subject == "" || len(subject) > 256 || strings.ContainsFunc(subject, unicode.IsControl) {
		return "", errApplicationCredentialSubjectMust1256
	}
	return subject, nil
}
