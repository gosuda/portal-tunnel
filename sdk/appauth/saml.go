package appauth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"

	saml2 "github.com/russellhaering/gosaml2"
	samltypes "github.com/russellhaering/gosaml2/types"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/gosuda/portal-tunnel/v2/utils"

	"github.com/gosuda/portal-tunnel/v2/types"
)

var (
	errSAMLMetadataURLMustValidURL    = errors.New("saml metadata url must be a valid URL without user info or fragment")
	errSAMLMetadataURLMustUseHTTPS    = errors.New("saml metadata url must use https (or http on a loopback host)")
	errSAMLMetadataTooLarge           = fmt.Errorf("saml metadata is larger than %d bytes", samlMetadataBodyLimit)
	errSAMLMetadataNoIdentityProvider = errors.New("saml metadata must describe exactly one identity provider")
	errSAMLMetadataNoEntityID         = errors.New("saml metadata has no identity provider entity id")
	errSAMLMetadataNoRedirectSSO      = errors.New("saml metadata has no HTTP-Redirect single sign-on service")
	errSAMLMetadataNoSigningKey       = errors.New("saml metadata has no signing certificate")
	errSAMLMetadataNoValidSigningKey  = errors.New("saml metadata has no signing certificate that is valid now: every one has expired or is not yet valid")
	errSAMLDestinationMismatch        = errors.New("saml response destination is not this tunnel's acs url")
	errSAMLInResponseToMismatch       = errors.New("saml response does not answer this login")
	errSAMLNeedsOneAssertion          = errors.New("saml response must carry exactly one assertion")
	errSAMLAssertionIDIsRequired      = errors.New("saml assertion id is required")
	errSAMLConditionsAreRequired      = errors.New("saml assertion conditions with NotOnOrAfter are required")
	errSAMLAssertionNotYetValid       = errors.New("saml assertion is not yet valid")
	errSAMLAssertionExpired           = errors.New("saml assertion has expired")
	errSAMLAudienceMismatch           = errors.New("saml assertion is not restricted to this service provider")
	errSAMLAssertionReplayed          = errors.New("saml assertion was already used")
	errSAMLReplaySetFull              = errors.New("too many saml logins in progress")
	errSAMLSubjectIsRequired          = errors.New("saml assertion has no subject value")
)

const (
	applicationAuthSAMLStateCookie = "__Host-portal_saml_state"
	samlMetadataBodyLimit          = 1 << 20
	samlResponseBodyLimit          = 512 << 10
	samlReplayLimit                = 10000
	samlClockLeeway                = time.Minute
	samlEntityIDLimit              = 1024
	samlSubjectAttributeLimit      = 256
)

type samlAuthenticator struct {
	metadataURL      string
	metadataFile     string
	entityID         string
	subjectAttribute string
	binding          string
	stateKey         []byte
	httpClient       *http.Client

	metadata providerCache[samlIdentityProvider]
	replay   samlReplaySet
}

type samlIdentityProvider struct {
	entityID string
	ssoURL   string
	certs    []*x509.Certificate
}

type samlStateClaims struct {
	RequestID string `json:"rid"`
	Host      string `json:"host"`
	HostEpoch string `json:"host_epoch,omitempty"`
	Next      string `json:"next"`
	ExpiresAt int64  `json:"exp"`
}

type samlReplaySet struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

type samlSPMetadata struct {
	XMLName         xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntityDescriptor"`
	EntityID        string   `xml:"entityID,attr"`
	SPSSODescriptor samltypes.SPSSODescriptor
}

type samlEntitiesDescriptor struct {
	XMLName  xml.Name                     `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntitiesDescriptor"`
	Entities []samltypes.EntityDescriptor `xml:"EntityDescriptor"`
}

func newSAMLAuthenticator(settings applicationAuthSettings, stateKey []byte) *samlAuthenticator {
	binding := sha256.Sum256([]byte(settings.samlMetadataURL + "\x00" + settings.samlMetadataFile + "\x00" + settings.samlEntityID + "\x00" + settings.samlSubjectAttribute))
	return &samlAuthenticator{
		metadataURL:      settings.samlMetadataURL,
		metadataFile:     settings.samlMetadataFile,
		entityID:         settings.samlEntityID,
		subjectAttribute: settings.samlSubjectAttribute,
		binding:          base64.RawURLEncoding.EncodeToString(binding[:]),
		stateKey:         stateKey,
		httpClient:       utils.NewHTTPClient(utils.WithHTTPTimeout(providerHTTPTimeout), utils.WithHTTPCheckRedirect(checkProviderRedirect)),
	}
}

func normalizeSAMLMetadataURL(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("%w: %w", errSAMLMetadataURLMustValidURL, err)
	}
	if parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return "", errSAMLMetadataURLMustValidURL
	}
	if !secureSAMLProviderURL(parsed) {
		return "", errSAMLMetadataURLMustUseHTTPS
	}
	return raw, nil
}

func secureSAMLProviderURL(u *url.URL) bool {
	return u.Scheme == "https" || isLoopbackHTTP(u)
}

func validateSAMLName(what, value string, limit int) error {
	if len(value) > limit || strings.ContainsFunc(value, unicode.IsControl) {
		return fmt.Errorf("%s must be at most %d characters without control characters", what, limit)
	}
	return nil
}

func (s *samlAuthenticator) identityProvider(ctx context.Context) (samlIdentityProvider, error) {
	return s.metadata.get(ctx, providerMetadataCacheTTL, s.fetchMetadata)
}

func (s *samlAuthenticator) fetchMetadata(ctx context.Context) (samlIdentityProvider, error) {
	var data []byte
	var err error
	if s.metadataFile != "" {
		data, err = readSAMLMetadataFile(s.metadataFile)
	} else {
		data, err = fetchSAMLMetadata(ctx, s.httpClient, s.metadataURL)
	}
	if err != nil {
		return samlIdentityProvider{}, fmt.Errorf("read saml metadata: %w", err)
	}
	return parseSAMLMetadata(data)
}

func readSAMLMetadataFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	return readSAMLMetadata(file)
}

func fetchSAMLMetadata(ctx context.Context, client *http.Client, targetURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/samlmetadata+xml, application/xml, text/xml")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	return readSAMLMetadata(resp.Body)
}

func readSAMLMetadata(r io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, samlMetadataBodyLimit+1))
	if err == nil && len(data) > samlMetadataBodyLimit {
		err = errSAMLMetadataTooLarge
	}
	return data, err
}

func parseSAMLMetadata(data []byte) (samlIdentityProvider, error) {
	var entities []samltypes.EntityDescriptor
	var entity samltypes.EntityDescriptor
	if err := xml.Unmarshal(data, &entity); err == nil {
		entities = []samltypes.EntityDescriptor{entity}
	} else {
		var list samlEntitiesDescriptor
		if xml.Unmarshal(data, &list) != nil {
			return samlIdentityProvider{}, fmt.Errorf("parse saml metadata: %w", err)
		}
		entities = list.Entities
	}
	var idps []samltypes.EntityDescriptor
	for _, entity := range entities {
		if entity.IDPSSODescriptor != nil {
			idps = append(idps, entity)
		}
	}
	if len(idps) != 1 {
		return samlIdentityProvider{}, errSAMLMetadataNoIdentityProvider
	}
	idp := samlIdentityProvider{entityID: strings.TrimSpace(idps[0].EntityID)}
	if idp.entityID == "" {
		return samlIdentityProvider{}, errSAMLMetadataNoEntityID
	}
	descriptor := idps[0].IDPSSODescriptor
	for _, service := range descriptor.SingleSignOnServices {
		if service.Binding != saml2.BindingHttpRedirect {
			continue
		}
		location, err := url.Parse(strings.TrimSpace(service.Location))
		wellFormed := err == nil && location.Host != "" && location.User == nil && location.Fragment == ""
		if !wellFormed || !secureSAMLProviderURL(location) {
			return samlIdentityProvider{}, fmt.Errorf("saml single sign-on service must be an https url (or http on a loopback host): %q", service.Location)
		}
		idp.ssoURL = location.String()
		break
	}
	if idp.ssoURL == "" {
		return samlIdentityProvider{}, errSAMLMetadataNoRedirectSSO
	}
	for _, key := range descriptor.KeyDescriptors {
		if key.Use != "" && key.Use != "signing" {
			continue
		}
		for _, cert := range key.KeyInfo.X509Data.X509Certificates {
			der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(cert.Data), ""))
			if err != nil {
				return samlIdentityProvider{}, fmt.Errorf("saml metadata signing certificate: %w", err)
			}
			parsed, err := x509.ParseCertificate(der)
			if err != nil {
				return samlIdentityProvider{}, fmt.Errorf("saml metadata signing certificate: %w", err)
			}
			idp.certs = append(idp.certs, parsed)
		}
	}
	if len(idp.certs) == 0 {
		return samlIdentityProvider{}, errSAMLMetadataNoSigningKey
	}
	now := time.Now()
	if !slices.ContainsFunc(idp.certs, func(cert *x509.Certificate) bool {
		return !now.Before(cert.NotBefore) && !now.After(cert.NotAfter)
	}) {
		return samlIdentityProvider{}, errSAMLMetadataNoValidSigningKey
	}
	return idp, nil
}

func (s *samlAuthenticator) spEntityID(host string) string {
	if s.entityID != "" {
		return s.entityID
	}
	return "https://" + host + types.PathApplicationAuthSAMLMetadata
}

func (s *samlAuthenticator) serviceProvider(idp samlIdentityProvider, host string) *saml2.SAMLServiceProvider {
	entityID := s.spEntityID(host)
	return &saml2.SAMLServiceProvider{
		IdentityProviderSSOURL:      idp.ssoURL,
		IdentityProviderSSOBinding:  saml2.BindingHttpRedirect,
		IdentityProviderIssuer:      idp.entityID,
		AssertionConsumerServiceURL: "https://" + host + types.PathApplicationAuthSAMLACS,
		ServiceProviderIssuer:       entityID,
		AudienceURI:                 entityID,
		IDPCertificateStore:         &dsig.MemoryX509CertificateStore{Roots: idp.certs},
		AllowMissingAttributes:      true,
	}
}

func (s *samlAuthenticator) issuerHost(idp samlIdentityProvider) string {
	switch {
	case idp.ssoURL != "":
		return urlHost(idp.ssoURL)
	case s.metadataURL != "":
		return urlHost(s.metadataURL)
	default:
		return "the identity provider"
	}
}

func (s *samlAuthenticator) serveLogin(w http.ResponseWriter, r *http.Request, hostEpoch string) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	idp, err := s.identityProvider(r.Context())
	if err != nil {
		if acceptsHTML(r) {
			writeSigninFailurePage(w, r, http.StatusBadGateway, signinProviderFailedPage, s.issuerHost(idp), r.URL.Query().Get("next"))
			return
		}
		http.Error(w, "saml metadata is not available", http.StatusBadGateway)
		return
	}
	host, err := normalizeHost(r.Host)
	if err != nil {
		http.Error(w, "invalid request host", http.StatusBadRequest)
		return
	}
	sp := s.serviceProvider(idp, host)
	sp.ForceAuthn = r.URL.Query().Get("prompt") == accountChooserPrompt
	request, err := sp.BuildAuthRequestDocumentNoSig()
	if err != nil {
		http.Error(w, "could not create login request", http.StatusInternalServerError)
		return
	}
	stateClaims := samlStateClaims{
		HostEpoch: hostEpoch,
		RequestID: request.Root().SelectAttrValue("ID", ""),
		Host:      host,
		Next:      sanitizeApplicationAuthNext(r.URL.Query().Get("next")),
		ExpiresAt: time.Now().UTC().Add(applicationAuthLoginStateTTL).Unix(),
	}
	stateToken, err := encodeApplicationAuthLoginState(s.stateKey, &stateClaims, &stateClaims.Next)
	if err != nil || stateClaims.RequestID == "" {
		http.Error(w, "could not create login state", http.StatusInternalServerError)
		return
	}
	authURL, err := sp.BuildAuthURLRedirect("", request)
	if err != nil {
		http.Error(w, "could not create login request", http.StatusInternalServerError)
		return
	}
	setSAMLStateCookie(w, stateToken, int(applicationAuthLoginStateTTL.Seconds()))
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, authURL, http.StatusSeeOther)
}

func setSAMLStateCookie(w http.ResponseWriter, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     applicationAuthSAMLStateCookie,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
	})
}

func (a *applicationAuth) serveSAMLACS(w http.ResponseWriter, r *http.Request) {
	if a.provider != ProviderSAML || a.saml == nil {
		a.writeJSONError(w, http.StatusNotFound, "not found")
		return
	}
	var idp samlIdentityProvider
	fail := func(message, page, next string, fields ...string) {
		if acceptsHTML(r) {
			writeSigninFailurePage(w, r, http.StatusUnauthorized, page, a.saml.issuerHost(idp), next, fields...)
			return
		}
		a.writeJSONError(w, http.StatusUnauthorized, message)
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		a.writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	stateCookie, err := r.Cookie(applicationAuthSAMLStateCookie)
	setSAMLStateCookie(w, "", -1)
	if err != nil {
		fail("missing saml login state", signinProviderExpiredPage, "/")
		return
	}

	now := time.Now().UTC()
	host, err := normalizeHost(r.Host)
	if err != nil {
		a.writeJSONError(w, http.StatusBadRequest, "invalid request host")
		return
	}
	var state samlStateClaims
	if err := decodeSignedApplicationAuthJSON(a.saml.stateKey, stateCookie.Value, &state); err != nil ||
		!sameApplicationHost(state.Host, host) ||
		state.HostEpoch != a.hostEpoch(host) ||
		now.Unix() >= state.ExpiresAt ||
		loginStateIssuedAt(state.ExpiresAt).Before(a.heldSince(host)) {
		next := "/"
		if err == nil {
			next = state.Next
		}
		fail("invalid or expired saml login state", signinProviderExpiredPage, next)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, samlResponseBodyLimit)
	if err := r.ParseForm(); err != nil {
		fail("invalid saml response", signinProviderFailedPage, state.Next)
		return
	}
	idp, err = a.saml.identityProvider(r.Context())
	if err != nil {
		fail("saml metadata is not available", signinProviderFailedPage, state.Next)
		return
	}
	assertion, err := a.saml.verify(idp, r.PostForm.Get("SAMLResponse"), state, now)
	if err != nil {
		fail("saml response verification failed", signinProviderFailedPage, state.Next)
		return
	}
	value, err := a.saml.subject(assertion)
	if err != nil {
		fail("saml response verification failed", signinProviderFailedPage, state.Next)
		return
	}
	subject, ok := a.resolveAllowedPrincipal(value, value)
	if !ok {
		fail("saml principal is not allowed", signinProviderDeniedPage, state.Next, "@@ACCOUNT@@", providerAccount(value, value))
		return
	}

	lifetime := applicationAuthSessionTTL
	if statement := assertion.AuthnStatement; statement != nil && statement.SessionNotOnOrAfter != nil {
		lifetime = min(max(statement.SessionNotOnOrAfter.Sub(now), providerMinSessionTTL), applicationAuthSessionTTL)
	}
	if err := a.setSession(w, Principal{Provider: ProviderSAML, Subject: subject, Email: providerEmail(value)}, strings.TrimSpace(r.Host), now, now.Add(lifetime)); err != nil {
		a.writeJSONError(w, http.StatusInternalServerError, "could not create session")
		return
	}
	http.Redirect(w, r, sanitizeApplicationAuthNext(state.Next), http.StatusSeeOther)
}

func (s *samlAuthenticator) verify(idp samlIdentityProvider, encodedResponse string, state samlStateClaims, now time.Time) (samltypes.Assertion, error) {
	sp := s.serviceProvider(idp, state.Host)
	response, err := sp.ValidateEncodedResponse(strings.TrimSpace(encodedResponse))
	if err != nil {
		return samltypes.Assertion{}, err
	}
	if response.Destination != sp.AssertionConsumerServiceURL {
		return samltypes.Assertion{}, errSAMLDestinationMismatch
	}
	if !sameSAMLRequestID(response.InResponseTo, state.RequestID) {
		return samltypes.Assertion{}, errSAMLInResponseToMismatch
	}
	if len(response.Assertions) != 1 {
		return samltypes.Assertion{}, errSAMLNeedsOneAssertion
	}
	assertion := response.Assertions[0]
	if assertion.ID == "" {
		return samltypes.Assertion{}, errSAMLAssertionIDIsRequired
	}
	if !sameSAMLRequestID(assertion.Subject.SubjectConfirmation.SubjectConfirmationData.InResponseTo, state.RequestID) {
		return samltypes.Assertion{}, errSAMLInResponseToMismatch
	}
	if err := checkSAMLConditions(assertion.Conditions, sp.AudienceURI, now); err != nil {
		return samltypes.Assertion{}, err
	}
	if err := s.replay.claim(assertion.ID, time.Unix(state.ExpiresAt, 0), now); err != nil {
		return samltypes.Assertion{}, err
	}
	return assertion, nil
}

func sameSAMLRequestID(got, want string) bool {
	return got != "" && subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func checkSAMLConditions(conditions *samltypes.Conditions, audience string, now time.Time) error {
	if conditions == nil || conditions.NotOnOrAfter == "" {
		return errSAMLConditionsAreRequired
	}
	notOnOrAfter, err := time.Parse(time.RFC3339, conditions.NotOnOrAfter)
	if err != nil {
		return fmt.Errorf("saml assertion NotOnOrAfter: %w", err)
	}
	if !now.Add(-samlClockLeeway).Before(notOnOrAfter) {
		return errSAMLAssertionExpired
	}
	if conditions.NotBefore != "" {
		notBefore, err := time.Parse(time.RFC3339, conditions.NotBefore)
		if err != nil {
			return fmt.Errorf("saml assertion NotBefore: %w", err)
		}
		if now.Add(samlClockLeeway).Before(notBefore) {
			return errSAMLAssertionNotYetValid
		}
	}
	if len(conditions.AudienceRestrictions) == 0 {
		return errSAMLAudienceMismatch
	}
	for _, restriction := range conditions.AudienceRestrictions {
		if !slices.ContainsFunc(restriction.Audiences, func(candidate samltypes.Audience) bool {
			return strings.TrimSpace(candidate.Value) == audience
		}) {
			return errSAMLAudienceMismatch
		}
	}
	return nil
}

func (s *samlAuthenticator) subject(assertion samltypes.Assertion) (string, error) {
	if s.subjectAttribute == "" {
		if assertion.Subject.NameID == nil || assertion.Subject.NameID.Value == "" {
			return "", errSAMLSubjectIsRequired
		}
		return assertion.Subject.NameID.Value, nil
	}
	var values []string
	if statement := assertion.AttributeStatement; statement != nil {
		for _, attribute := range statement.Attributes {
			if attribute.Name != s.subjectAttribute {
				continue
			}
			for _, value := range attribute.Values {
				values = append(values, value.Value)
			}
		}
	}
	if len(values) != 1 || values[0] == "" {
		return "", fmt.Errorf("saml attribute %q must carry exactly one value", s.subjectAttribute)
	}
	return values[0], nil
}

func (r *samlReplaySet) claim(id string, until, now time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if expiry, ok := r.seen[id]; ok && now.Before(expiry) {
		return errSAMLAssertionReplayed
	}
	if len(r.seen) >= samlReplayLimit {
		for seenID, expiry := range r.seen {
			if !now.Before(expiry) {
				delete(r.seen, seenID)
			}
		}
	}
	if len(r.seen) >= samlReplayLimit {
		return errSAMLReplaySetFull
	}
	if r.seen == nil {
		r.seen = make(map[string]time.Time)
	}
	r.seen[id] = until
	return nil
}

func (a *applicationAuth) serveSAMLMetadata(w http.ResponseWriter, r *http.Request) {
	if a.provider != ProviderSAML || a.saml == nil {
		a.writeJSONError(w, http.StatusNotFound, "not found")
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		a.writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	host, err := normalizeHost(r.Host)
	if err != nil {
		a.writeJSONError(w, http.StatusBadRequest, "invalid request host")
		return
	}
	var body bytes.Buffer
	body.WriteString(xml.Header)
	encoder := xml.NewEncoder(&body)
	encoder.Indent("", "  ")
	err = encoder.Encode(samlSPMetadata{
		EntityID: a.saml.spEntityID(host),
		SPSSODescriptor: samltypes.SPSSODescriptor{
			ProtocolSupportEnumeration: saml2.SAMLProtocolNamespace,
			AssertionConsumerServices: []samltypes.IndexedEndpoint{{
				Binding:  saml2.BindingHttpPost,
				Location: "https://" + host + types.PathApplicationAuthSAMLACS,
				Index:    1,
			}},
		},
	})
	if err != nil {
		a.writeJSONError(w, http.StatusInternalServerError, "could not create metadata")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(body.Bytes())
}
