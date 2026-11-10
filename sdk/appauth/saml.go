package appauth

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/url"
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

func (s *samlAuthenticator) serveLogin(w http.ResponseWriter, r *http.Request) {
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
	authURL := s.buildServeLoginAuthRedirect(w, r, idp, host)
	if authURL == "" {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, authURL, http.StatusSeeOther)
}

func (s *samlAuthenticator) buildServeLoginAuthRedirect(w http.ResponseWriter, r *http.Request, idp samlIdentityProvider, host string) string {
	sp := s.serviceProvider(idp, host)
	sp.ForceAuthn = r.URL.Query().Get("prompt") == accountChooserPrompt
	request, err := sp.BuildAuthRequestDocumentNoSig()
	if err != nil {
		http.Error(w, "could not create login request", http.StatusInternalServerError)
		return ""
	}
	stateClaims := samlStateClaims{
		RequestID: request.Root().SelectAttrValue("ID", ""),
		Host:      host,
		Next:      sanitizeApplicationAuthNext(r.URL.Query().Get("next")),
		ExpiresAt: time.Now().UTC().Add(applicationAuthLoginStateTTL).Unix(),
	}
	stateToken, err := encodeApplicationAuthLoginState(s.stateKey, &stateClaims, &stateClaims.Next)
	if err != nil || stateClaims.RequestID == "" {
		http.Error(w, "could not create login state", http.StatusInternalServerError)
		return ""
	}
	authURL, err := sp.BuildAuthURLRedirect("", request)
	if err != nil {
		http.Error(w, "could not create login request", http.StatusInternalServerError)
		return ""
	}
	setSAMLStateCookie(w, stateToken, int(applicationAuthLoginStateTTL.Seconds()))
	return authURL
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

type serveSAMLACSRequest struct {
	state samlStateClaims
	host  string
	now   time.Time
}

func (a *applicationAuth) serveSAMLACS(w http.ResponseWriter, r *http.Request) {
	if a.provider != ProviderSAML || a.saml == nil {
		a.writeJSONError(w, http.StatusNotFound, "not found")
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		a.writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	stateCookie, err := r.Cookie(applicationAuthSAMLStateCookie)
	setSAMLStateCookie(w, "", -1)
	if err != nil {
		a.failServeSAMLACS(w, r, serveSAMLACSFailure{message: "missing saml login state", page: signinProviderExpiredPage, next: "/", idp: samlIdentityProvider{}})
		return
	}
	now := time.Now().UTC()
	host, err := normalizeHost(r.Host)
	if err != nil {
		a.writeJSONError(w, http.StatusBadRequest, "invalid request host")
		return
	}
	state, next, ok := a.decodeServeSAMLACSState(stateCookie.Value, host, now)
	if !ok {
		a.failServeSAMLACS(w, r, serveSAMLACSFailure{message: "invalid or expired saml login state", page: signinProviderExpiredPage, next: next, idp: samlIdentityProvider{}})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, samlResponseBodyLimit)
	if err := r.ParseForm(); err != nil {
		a.failServeSAMLACS(w, r, serveSAMLACSFailure{message: "invalid saml response", page: signinProviderFailedPage, next: state.Next, idp: samlIdentityProvider{}})
		return
	}
	a.finishServeSAMLACSLogin(w, r, serveSAMLACSRequest{state: state, host: host, now: now})
}

type serveSAMLACSFailure struct {
	message string
	page    string
	next    string
	fields  []string
	idp     samlIdentityProvider
}

func (a *applicationAuth) failServeSAMLACS(w http.ResponseWriter, r *http.Request, failure serveSAMLACSFailure) {
	if acceptsHTML(r) {
		writeSigninFailurePage(w, r, http.StatusUnauthorized, failure.page, a.saml.issuerHost(failure.idp), failure.next, failure.fields...)
		return
	}
	a.writeJSONError(w, http.StatusUnauthorized, failure.message)
}

func (a *applicationAuth) verifyServeSAMLACSAssertion(idp samlIdentityProvider, encodedResponse string, state samlStateClaims, now time.Time) (samltypes.Assertion, string, *serveSAMLACSFailure) {
	assertion, err := a.saml.verify(idp, encodedResponse, state, now)
	if err != nil {
		return samltypes.Assertion{}, "", &serveSAMLACSFailure{message: "saml response verification failed", page: signinProviderFailedPage, next: state.Next, idp: idp}
	}
	value, err := a.saml.subject(assertion)
	if err != nil {
		return samltypes.Assertion{}, "", &serveSAMLACSFailure{message: "saml response verification failed", page: signinProviderFailedPage, next: state.Next, idp: idp}
	}
	return assertion, value, nil
}

func (a *applicationAuth) decodeServeSAMLACSState(cookieValue, host string, now time.Time) (samlStateClaims, string, bool) {
	var state samlStateClaims
	if err := decodeSignedApplicationAuthJSON(a.saml.stateKey, cookieValue, &state); err != nil {
		return samlStateClaims{}, "/", false
	}
	if !sameApplicationHost(state.Host, host) ||
		now.Unix() >= state.ExpiresAt ||
		loginStateIssuedAt(state.ExpiresAt).Before(a.heldSince(host)) {
		return state, state.Next, false
	}
	return state, state.Next, true
}

func (a *applicationAuth) finishServeSAMLACSLogin(w http.ResponseWriter, r *http.Request, req serveSAMLACSRequest) {
	var idp samlIdentityProvider
	idp, err := a.saml.identityProvider(r.Context())
	if err != nil {
		a.failServeSAMLACS(w, r, serveSAMLACSFailure{message: "saml metadata is not available", page: signinProviderFailedPage, next: req.state.Next, idp: idp})
		return
	}
	assertion, value, failure := a.verifyServeSAMLACSAssertion(idp, r.PostForm.Get("SAMLResponse"), req.state, req.now)
	if failure != nil {
		a.failServeSAMLACS(w, r, *failure)
		return
	}
	subject, ok := a.resolveAllowedPrincipal(value, value)
	if !ok {
		a.failServeSAMLACS(w, r, serveSAMLACSFailure{message: "saml principal is not allowed", page: signinProviderDeniedPage, next: req.state.Next, fields: []string{"@@ACCOUNT@@", providerAccount(value, value)}, idp: idp})
		return
	}
	lifetime := applicationAuthSessionTTL
	if statement := assertion.AuthnStatement; statement != nil && statement.SessionNotOnOrAfter != nil {
		lifetime = min(max(statement.SessionNotOnOrAfter.Sub(req.now), providerMinSessionTTL), applicationAuthSessionTTL)
	}
	if err := a.setSession(w, Principal{Provider: ProviderSAML, Subject: subject, Email: providerEmail(value)}, strings.TrimSpace(r.Host), req.now, req.now.Add(lifetime)); err != nil {
		a.writeJSONError(w, http.StatusInternalServerError, "could not create session")
		return
	}
	http.Redirect(w, r, sanitizeApplicationAuthNext(req.state.Next), http.StatusSeeOther)
}

func (s *samlAuthenticator) verify(idp samlIdentityProvider, encodedResponse string, state samlStateClaims, now time.Time) (samltypes.Assertion, error) {
	sp := s.serviceProvider(idp, state.Host)
	response, err := sp.ValidateEncodedResponse(strings.TrimSpace(encodedResponse))
	if err != nil {
		return samltypes.Assertion{}, err
	}
	if err := checkVerifySAMLResponseBinding(response, sp.AssertionConsumerServiceURL, state.RequestID); err != nil {
		return samltypes.Assertion{}, err
	}
	assertion := response.Assertions[0]
	if err := checkSAMLConditions(assertion.Conditions, sp.AudienceURI, now); err != nil {
		return samltypes.Assertion{}, err
	}
	if err := s.replay.claim(assertion.ID, time.Unix(state.ExpiresAt, 0), now); err != nil {
		return samltypes.Assertion{}, err
	}
	return assertion, nil
}

func checkVerifySAMLResponseBinding(response *samltypes.Response, consumerURL, requestID string) error {
	if response.Destination != consumerURL {
		return errSAMLDestinationMismatch
	}
	if !sameSAMLRequestID(response.InResponseTo, requestID) {
		return errSAMLInResponseToMismatch
	}
	if len(response.Assertions) != 1 {
		return errSAMLNeedsOneAssertion
	}
	assertion := response.Assertions[0]
	if assertion.ID == "" {
		return errSAMLAssertionIDIsRequired
	}
	if !sameSAMLRequestID(assertion.Subject.SubjectConfirmation.SubjectConfirmationData.InResponseTo, requestID) {
		return errSAMLInResponseToMismatch
	}
	return nil
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
	if err := checkSAMLConditionsNotBefore(conditions, now); err != nil {
		return err
	}
	return checkSAMLConditionsAudience(conditions.AudienceRestrictions, audience)
}

func checkSAMLConditionsNotBefore(conditions *samltypes.Conditions, now time.Time) error {
	if conditions.NotBefore == "" {
		return nil
	}
	notBefore, err := time.Parse(time.RFC3339, conditions.NotBefore)
	if err != nil {
		return fmt.Errorf("saml assertion NotBefore: %w", err)
	}
	if now.Add(samlClockLeeway).Before(notBefore) {
		return errSAMLAssertionNotYetValid
	}
	return nil
}

func checkSAMLConditionsAudience(restrictions []samltypes.AudienceRestriction, audience string) error {
	if len(restrictions) == 0 {
		return errSAMLAudienceMismatch
	}
	for _, restriction := range restrictions {
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
	values := collectSubjectSAMLAttributeValues(assertion, s.subjectAttribute)
	if len(values) != 1 || values[0] == "" {
		return "", fmt.Errorf("saml attribute %q must carry exactly one value", s.subjectAttribute)
	}
	return values[0], nil
}

func collectSubjectSAMLAttributeValues(assertion samltypes.Assertion, subjectAttribute string) []string {
	var values []string
	statement := assertion.AttributeStatement
	if statement == nil {
		return values
	}
	for _, attribute := range statement.Attributes {
		if attribute.Name != subjectAttribute {
			continue
		}
		for _, value := range attribute.Values {
			values = append(values, value.Value)
		}
	}
	return values
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
	body, err := buildServeSAMLMetadataBody(a.saml.spEntityID(host), host)
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
func buildServeSAMLMetadataBody(entityID, host string) (bytes.Buffer, error) {
	var body bytes.Buffer
	body.WriteString(xml.Header)
	encoder := xml.NewEncoder(&body)
	encoder.Indent("", "  ")
	if err := encoder.Encode(samlSPMetadata{
		EntityID: entityID,
		SPSSODescriptor: samltypes.SPSSODescriptor{
			ProtocolSupportEnumeration: saml2.SAMLProtocolNamespace,
			AssertionConsumerServices: []samltypes.IndexedEndpoint{{
				Binding:  saml2.BindingHttpPost,
				Location: "https://" + host + types.PathApplicationAuthSAMLACS,
				Index:    1,
			}},
		},
	}); err != nil {
		return bytes.Buffer{}, err
	}
	return body, nil
}
