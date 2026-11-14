package appauth

import (
	"bytes"
	"compress/flate"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"github.com/beevik/etree"
	"github.com/gosuda/portal-tunnel/v2/types"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	dsig "github.com/russellhaering/goxmldsig"
)

const (
	samlTestHost       = "app.example"
	samlTestACSURL     = "https://" + samlTestHost + types.PathApplicationAuthSAMLACS
	samlTestAudience   = "https://" + samlTestHost + types.PathApplicationAuthSAMLMetadata
	samlTestAssertNS   = "urn:oasis:names:tc:SAML:2.0:assertion"
	samlTestProtocolNS = "urn:oasis:names:tc:SAML:2.0:protocol"
)

type samlTestIdP struct {
	server   *httptest.Server
	entityID string
	key      *rsa.PrivateKey
	cert     []byte
	metadata string
}

func newSAMLTestKey(t *testing.T, notAfter time.Time) (*rsa.PrivateKey, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "saml test idp"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
	}
	cert, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return key, cert
}

func newSAMLTestIdP(t *testing.T) *samlTestIdP {
	t.Helper()
	idp := &samlTestIdP{}
	idp.key, idp.cert = newSAMLTestKey(t, time.Now().Add(24*time.Hour))
	idp.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/metadata" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/samlmetadata+xml")
		_, _ = io.WriteString(w, idp.metadata)
	}))
	t.Cleanup(idp.server.Close)
	idp.entityID = idp.server.URL + "/realms/test"
	idp.metadata = idp.metadataXML(base64.StdEncoding.EncodeToString(idp.cert))
	return idp
}

func (p *samlTestIdP) metadataURL() string { return p.server.URL + "/metadata" }

func (p *samlTestIdP) metadataXML(cert string) string {
	return fmt.Sprintf(`<?xml version="1.0"?>
<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" Name="urn:test">
<md:EntityDescriptor entityID="%s">
<md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
<md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>%s</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>
<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="%[3]s/sso/post"/>
<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="%[3]s/sso"/>
</md:IDPSSODescriptor>
</md:EntityDescriptor>
</md:EntitiesDescriptor>`, p.entityID, cert, p.server.URL)
}

type samlTestResponse struct {
	issuer              string
	status              string
	destination         string
	inResponseTo        string
	assertionID         string
	nameID              string
	attributes          map[string][]string
	recipient           string
	confirmationExpiry  time.Time
	confirmationAnswer  string
	notBefore           time.Time
	notOnOrAfter        time.Time
	audience            string
	sessionNotOnOrAfter time.Time

	signAssertion bool
	signResponse  bool
	signKey       *rsa.PrivateKey
	signCert      []byte
	tamper        func(response *etree.Element)
}

func (p *samlTestIdP) validResponse(login samlLogin) samlTestResponse {
	now := time.Now()
	return samlTestResponse{
		issuer:             p.entityID,
		status:             "urn:oasis:names:tc:SAML:2.0:status:Success",
		destination:        samlTestACSURL,
		inResponseTo:       login.requestID,
		assertionID:        "_a" + rand.Text(),
		nameID:             "alice@example.com",
		recipient:          samlTestACSURL,
		confirmationExpiry: now.Add(5 * time.Minute),
		confirmationAnswer: login.requestID,
		notBefore:          now.Add(-30 * time.Second),
		notOnOrAfter:       now.Add(5 * time.Minute),
		audience:           samlTestAudience,
		signAssertion:      true,
	}
}

func samlTestInstant(at time.Time) string { return at.UTC().Format("2006-01-02T15:04:05Z") }

func setSAMLTestAttr(el *etree.Element, name, value string) {
	if value != "" {
		el.CreateAttr(name, value)
	}
}
func (p *samlTestIdP) sign(t *testing.T, r samlTestResponse, el *etree.Element) *etree.Element {
	t.Helper()
	key, cert := p.key, p.cert
	if r.signKey != nil {
		key, cert = r.signKey, r.signCert
	}
	ctx, err := dsig.NewSigningContext(key, [][]byte{cert})
	if err != nil {
		t.Fatal(err)
	}
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	signed, err := ctx.SignEnveloped(el)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func newSAMLAssertionShellForEncodeSAML(t *testing.T, r samlTestResponse, now time.Time) *etree.Element {
	t.Helper()
	assertion := etree.NewElement("saml:Assertion")
	assertion.CreateAttr("xmlns:saml", samlTestAssertNS)
	setSAMLTestAttr(assertion, "ID", r.assertionID)
	assertion.CreateAttr("Version", "2.0")
	assertion.CreateAttr("IssueInstant", samlTestInstant(now))
	assertion.CreateElement("saml:Issuer").SetText(r.issuer)
	return assertion
}

func appendSAMLSubjectForEncodeSAML(t *testing.T, assertion *etree.Element, r samlTestResponse) {
	t.Helper()
	subject := assertion.CreateElement("saml:Subject")
	if r.nameID != "" {
		subject.CreateElement("saml:NameID").SetText(r.nameID)
	}
	confirmation := subject.CreateElement("saml:SubjectConfirmation")
	confirmation.CreateAttr("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer")
	data := confirmation.CreateElement("saml:SubjectConfirmationData")
	data.CreateAttr("NotOnOrAfter", samlTestInstant(r.confirmationExpiry))
	setSAMLTestAttr(data, "Recipient", r.recipient)
	setSAMLTestAttr(data, "InResponseTo", r.confirmationAnswer)
}

func appendSAMLConditionsForEncodeSAML(t *testing.T, assertion *etree.Element, r samlTestResponse, now time.Time) {
	t.Helper()
	conditions := assertion.CreateElement("saml:Conditions")
	if !r.notBefore.IsZero() {
		conditions.CreateAttr("NotBefore", samlTestInstant(r.notBefore))
	}
	if !r.notOnOrAfter.IsZero() {
		conditions.CreateAttr("NotOnOrAfter", samlTestInstant(r.notOnOrAfter))
	}
	if r.audience != "" {
		conditions.CreateElement("saml:AudienceRestriction").CreateElement("saml:Audience").SetText(r.audience)
	}
	statement := assertion.CreateElement("saml:AuthnStatement")
	statement.CreateAttr("AuthnInstant", samlTestInstant(now))
	if !r.sessionNotOnOrAfter.IsZero() {
		statement.CreateAttr("SessionNotOnOrAfter", samlTestInstant(r.sessionNotOnOrAfter))
	}
}

func appendSAMLAttributesForEncodeSAML(t *testing.T, assertion *etree.Element, r samlTestResponse) {
	t.Helper()
	if len(r.attributes) == 0 {
		return
	}
	attributes := assertion.CreateElement("saml:AttributeStatement")
	for name, values := range r.attributes {
		attribute := attributes.CreateElement("saml:Attribute")
		attribute.CreateAttr("Name", name)
		for _, value := range values {
			attribute.CreateElement("saml:AttributeValue").SetText(value)
		}
	}
}

func (p *samlTestIdP) buildSAMLAssertionForEncodeSAML(t *testing.T, r samlTestResponse, now time.Time) *etree.Element {
	t.Helper()
	assertion := newSAMLAssertionShellForEncodeSAML(t, r, now)
	appendSAMLSubjectForEncodeSAML(t, assertion, r)
	appendSAMLConditionsForEncodeSAML(t, assertion, r, now)
	appendSAMLAttributesForEncodeSAML(t, assertion, r)
	if r.signAssertion {
		assertion = p.sign(t, r, assertion)
	}
	return assertion
}

func (p *samlTestIdP) buildSAMLResponseForEncodeSAML(t *testing.T, r samlTestResponse, now time.Time, assertion *etree.Element) *etree.Element {
	t.Helper()
	response := etree.NewElement("samlp:Response")
	response.CreateAttr("xmlns:samlp", samlTestProtocolNS)
	response.CreateAttr("xmlns:saml", samlTestAssertNS)
	response.CreateAttr("ID", "_r"+rand.Text())
	response.CreateAttr("Version", "2.0")
	response.CreateAttr("IssueInstant", samlTestInstant(now))
	setSAMLTestAttr(response, "Destination", r.destination)
	setSAMLTestAttr(response, "InResponseTo", r.inResponseTo)
	response.CreateElement("saml:Issuer").SetText(r.issuer)
	response.CreateElement("samlp:Status").CreateElement("samlp:StatusCode").CreateAttr("Value", r.status)
	response.AddChild(assertion)
	if r.signResponse {
		response = p.sign(t, r, response)
	}
	if r.tamper != nil {
		r.tamper(response)
	}
	return response
}

func (p *samlTestIdP) encode(t *testing.T, r samlTestResponse) string {
	t.Helper()
	now := time.Now()
	assertion := p.buildSAMLAssertionForEncodeSAML(t, r, now)
	response := p.buildSAMLResponseForEncodeSAML(t, r, now, assertion)
	doc := etree.NewDocument()
	doc.SetRoot(response)
	raw, err := doc.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}
func TestApplicationAuthSAMLLogin(t *testing.T) {
	t.Parallel()

	idp := newSAMLTestIdP(t)
	var upstream http.Header
	gate := newSAMLLoginGateSAML(t, idp, &upstream)
	rec := checkSAMLLoginUnauthenticatedSAML(t, gate)
	login := startSAMLLogin(t, gate, rec.Header().Get("Location"))
	checkSAMLLoginRequestSAML(t, login, idp)

	session := assertSAMLACS(t, login.post(gate, idp.encode(t, idp.validResponse(login))), http.StatusSeeOther)
	checkSAMLLoginSessionSAML(t, gate, session, &upstream)
}

func TestApplicationAuthSAMLLandsOnNext(t *testing.T) {
	t.Parallel()

	idp := newSAMLTestIdP(t)
	gate := newSAMLTestGate(t, idp, nil, nil)
	for target, want := range map[string]string{
		types.PathApplicationAuthLogin + "?next=" + url.QueryEscape("/reports?year=2026"): "/reports?year=2026",
		types.PathApplicationAuthLogin + "?next=" + url.QueryEscape("//evil.example/"):    "/",
	} {
		login := startSAMLLogin(t, gate, target)
		rec := login.post(gate, idp.encode(t, idp.validResponse(login)))
		assertSAMLACS(t, rec, http.StatusSeeOther)
		if got := rec.Header().Get("Location"); got != want {
			t.Fatalf("login from %q lands on %q; want %q", target, got, want)
		}
	}
}

func assertSAMLRefusalSAML(t *testing.T, change func(*samlTestResponse)) {
	t.Helper()
	idp := newSAMLTestIdP(t)
	gate := newSAMLTestGate(t, idp, nil, nil)
	login := startSAMLLogin(t, gate, types.PathApplicationAuthLogin)
	response := idp.validResponse(login)
	change(&response)
	assertSAMLACS(t, login.post(gate, idp.encode(t, response)), http.StatusUnauthorized)
}

func assertSAMLRefusalWithoutCookieSAML(t *testing.T) {
	t.Helper()
	idp := newSAMLTestIdP(t)
	gate := newSAMLTestGate(t, idp, nil, nil)
	login := startSAMLLogin(t, gate, types.PathApplicationAuthLogin)
	encoded := idp.encode(t, idp.validResponse(login))
	login.cookie = nil
	assertSAMLACS(t, login.post(gate, encoded), http.StatusUnauthorized)
}

func assertSAMLRefusalExpiredStateSAML(t *testing.T) {
	t.Helper()
	idp := newSAMLTestIdP(t)
	gate := newSAMLTestGate(t, idp, nil, nil)
	login := startSAMLLogin(t, gate, types.PathApplicationAuthLogin)
	var state samlStateClaims
	if err := decodeSignedApplicationAuthJSON(gate.saml.stateKey, login.cookie.Value, &state); err != nil {
		t.Fatal(err)
	}
	state.ExpiresAt = time.Now().Add(-time.Second).Unix()
	expired, err := encodeSignedApplicationAuthJSON(gate.saml.stateKey, state)
	if err != nil {
		t.Fatal(err)
	}
	encoded := idp.encode(t, idp.validResponse(login))
	login.cookie = &http.Cookie{Name: applicationAuthSAMLStateCookie, Value: expired}
	assertSAMLACS(t, login.post(gate, encoded), http.StatusUnauthorized)
}

func assertSAMLRefusalForeignHostSAML(t *testing.T) {
	t.Helper()
	idp := newSAMLTestIdP(t)
	gate := newSAMLTestGate(t, idp, nil, nil)
	rec := httptest.NewRecorder()
	gate.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://other.example"+types.PathApplicationAuthLogin, nil))
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("login cookies = %#v", cookies)
	}
	login := startSAMLLogin(t, gate, types.PathApplicationAuthLogin)
	encoded := idp.encode(t, idp.validResponse(login))
	login.cookie = cookies[0]
	assertSAMLACS(t, login.post(gate, encoded), http.StatusUnauthorized)
}

func TestApplicationAuthSAMLRefusals(t *testing.T) {
	t.Parallel()

	otherKey, otherCert := newSAMLTestKey(t, time.Now().Add(24*time.Hour))
	past := time.Now().Add(-10 * time.Minute)
	future := time.Now().Add(10 * time.Minute)
	tests := []struct {
		name   string
		change func(r *samlTestResponse)
	}{
		{"unsigned response and assertion", func(r *samlTestResponse) { r.signAssertion = false }},
		{"assertion signed by a key the metadata does not list", func(r *samlTestResponse) { r.signKey, r.signCert = otherKey, otherCert }},
		{"response signed by a key the metadata does not list", func(r *samlTestResponse) {
			r.signAssertion, r.signResponse, r.signKey, r.signCert = false, true, otherKey, otherCert
		}},
		{"assertion changed after signing", func(r *samlTestResponse) {
			r.tamper = func(response *etree.Element) {
				response.FindElement("./Assertion/Subject/NameID").SetText("mallory@example.com")
			}
		}},
		{"signed response changed after signing", func(r *samlTestResponse) {
			r.signAssertion, r.signResponse = false, true
			r.tamper = func(response *etree.Element) {
				response.FindElement("./Assertion/Subject/NameID").SetText("mallory@example.com")
			}
		}},
		{"unsigned assertion next to a signed one", func(r *samlTestResponse) {
			r.tamper = func(response *etree.Element) {
				forged := response.FindElement("./Assertion").Copy()
				forged.RemoveChild(forged.FindElement("./Signature"))
				forged.CreateAttr("ID", "_forged")
				forged.FindElement("./Subject/NameID").SetText("mallory@example.com")
				response.InsertChildAt(response.FindElement("./Assertion").Index(), forged)
			}
		}},
		{"wrong issuer", func(r *samlTestResponse) { r.issuer = "https://evil.example/idp" }},
		{"identity provider reports a failure", func(r *samlTestResponse) { r.status = "urn:oasis:names:tc:SAML:2.0:status:Responder" }},
		{"audience of another service provider", func(r *samlTestResponse) { r.audience = "https://other.example/_portal/auth/saml/metadata" }},
		{"no audience restriction", func(r *samlTestResponse) { r.audience = "" }},
		{"recipient of another service provider", func(r *samlTestResponse) { r.recipient = "https://other.example" + types.PathApplicationAuthSAMLACS }},
		{"destination of another service provider", func(r *samlTestResponse) { r.destination = "https://other.example" + types.PathApplicationAuthSAMLACS }},
		{"no destination", func(r *samlTestResponse) { r.destination = "" }},
		{"expired assertion", func(r *samlTestResponse) { r.notOnOrAfter = past }},
		{"assertion without NotOnOrAfter", func(r *samlTestResponse) { r.notOnOrAfter = time.Time{} }},
		{"assertion not yet valid", func(r *samlTestResponse) { r.notBefore = future }},
		{"expired subject confirmation", func(r *samlTestResponse) { r.confirmationExpiry = past }},
		{"response to another login", func(r *samlTestResponse) { r.inResponseTo = "_other" }},
		{"assertion for another login", func(r *samlTestResponse) { r.confirmationAnswer = "_other" }},
		{"unsolicited response", func(r *samlTestResponse) { r.inResponseTo, r.confirmationAnswer = "", "" }},
		{"assertion without an ID", func(r *samlTestResponse) { r.assertionID = "" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assertSAMLRefusalSAML(t, tt.change)
		})
	}

	t.Run("response without the login state of this browser", func(t *testing.T) {
		t.Parallel()
		assertSAMLRefusalWithoutCookieSAML(t)
	})
	t.Run("expired login state", func(t *testing.T) {
		t.Parallel()
		assertSAMLRefusalExpiredStateSAML(t)
	})
	t.Run("login state of another host", func(t *testing.T) {
		t.Parallel()
		assertSAMLRefusalForeignHostSAML(t)
	})
}

func TestApplicationAuthSAMLAcceptsEitherSignature(t *testing.T) {
	t.Parallel()

	for name, change := range map[string]func(*samlTestResponse){
		"signed response":            func(r *samlTestResponse) { r.signAssertion, r.signResponse = false, true },
		"signed assertion":           func(*samlTestResponse) {},
		"both signed":                func(r *samlTestResponse) { r.signResponse = true },
		"clock skew within leeway":   func(r *samlTestResponse) { r.notBefore = time.Now().Add(30 * time.Second) },
		"no NotBefore in conditions": func(r *samlTestResponse) { r.notBefore = time.Time{} },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			idp := newSAMLTestIdP(t)
			gate := newSAMLTestGate(t, idp, nil, nil)
			login := startSAMLLogin(t, gate, types.PathApplicationAuthLogin)
			response := idp.validResponse(login)
			change(&response)
			assertSAMLACS(t, login.post(gate, idp.encode(t, response)), http.StatusSeeOther)
		})
	}
}

func TestApplicationAuthSAMLRefusesReplay(t *testing.T) {
	t.Parallel()

	idp := newSAMLTestIdP(t)
	gate := newSAMLTestGate(t, idp, nil, nil)
	login := startSAMLLogin(t, gate, types.PathApplicationAuthLogin)
	encoded := idp.encode(t, idp.validResponse(login))
	assertSAMLACS(t, login.post(gate, encoded), http.StatusSeeOther)
	assertSAMLACS(t, login.post(gate, encoded), http.StatusUnauthorized)
}
func TestSAMLReplaySetIsBounded(t *testing.T) {
	t.Parallel()

	now := time.Now()
	var set samlReplaySet
	for i := range samlReplayLimit {
		if err := set.claim(fmt.Sprintf("_a%d", i), now.Add(time.Minute), now); err != nil {
			t.Fatalf("claim %d: %v", i, err)
		}
	}
	if err := set.claim("_full", now.Add(time.Minute), now); !errors.Is(err, errSAMLReplaySetFull) {
		t.Fatalf("claim on a full set = %v; want %v", err, errSAMLReplaySetFull)
	}
	later := now.Add(2 * time.Minute)
	if err := set.claim("_a0", later.Add(time.Minute), later); err != nil {
		t.Fatalf("claim after the entries expired = %v", err)
	}
	if len(set.seen) != 1 {
		t.Fatalf("set holds %d entries after expiry; want 1", len(set.seen))
	}
	if err := set.claim("_a0", later.Add(time.Minute), later); !errors.Is(err, errSAMLAssertionReplayed) {
		t.Fatalf("second claim = %v; want %v", err, errSAMLAssertionReplayed)
	}
}

type samlPrincipalCase struct {
	name      string
	allow     []string
	attribute string
	change    func(*samlTestResponse)
	want      string
}

func assertSAMLPrincipalCaseSAML(t *testing.T, tt samlPrincipalCase) {
	t.Helper()
	idp := newSAMLTestIdP(t)
	gate := newSAMLTestGate(t, idp, nil, func(cfg *Config) {
		cfg.Allow, cfg.SAMLSubjectAttribute = tt.allow, tt.attribute
	})
	login := startSAMLLogin(t, gate, types.PathApplicationAuthLogin)
	response := idp.validResponse(login)
	if tt.change != nil {
		tt.change(&response)
	}
	rec := login.post(gate, idp.encode(t, response))
	if tt.want == "" {
		assertSAMLACS(t, rec, http.StatusUnauthorized)
		return
	}
	session := assertSAMLACS(t, rec, http.StatusSeeOther)
	req := httptest.NewRequest(http.MethodGet, "https://"+samlTestHost+"/", nil)
	req.AddCookie(session)
	if got, ok := gate.authenticateSession(req); !ok || got.Subject != tt.want || got.Provider != ProviderSAML {
		t.Fatalf("session = (%+v, %v); want %q from saml", got, ok, tt.want)
	}
}

func assertSAMLPrincipalRevocationSAML(t *testing.T) {
	t.Helper()
	idp := newSAMLTestIdP(t)
	gate := newSAMLTestGate(t, idp, nil, func(cfg *Config) {
		cfg.Allow = []string{"alice@example.com", "bob@example.com"}
	})
	login := startSAMLLogin(t, gate, types.PathApplicationAuthLogin)
	session := assertSAMLACS(t, login.post(gate, idp.encode(t, idp.validResponse(login))), http.StatusSeeOther)
	for name, configure := range map[string]func(*Config){
		"same settings": func(cfg *Config) {
			cfg.Allow = []string{"alice@example.com", "bob@example.com"}
		},
		"entry removed":          func(cfg *Config) { cfg.Allow = []string{"bob@example.com"} },
		"another subject source": func(cfg *Config) { cfg.SAMLSubjectAttribute = "email" },
		"another SP entity ID":   func(cfg *Config) { cfg.SAMLEntityID = "urn:portal:other" },
	} {
		restarted := newSAMLTestGate(t, idp, nil, configure)
		req := httptest.NewRequest(http.MethodGet, "https://"+samlTestHost+"/", nil)
		req.AddCookie(session)
		_, ok := restarted.authenticateSession(req)
		if ok != (name == "same settings") {
			t.Errorf("%s: session accepted = %v", name, ok)
		}
	}
}

func TestApplicationAuthSAMLPrincipals(t *testing.T) {
	t.Parallel()

	tests := []samlPrincipalCase{
		{"email NameID matches its email entry", []string{"alice@example.com"}, "", func(r *samlTestResponse) { r.nameID = "Alice@Example.com" }, "alice@example.com"},
		{"email NameID matches its domain", []string{"@example.com"}, "", nil, "alice@example.com"},
		{"domain excludes subdomains", []string{"@example.com"}, "", func(r *samlTestResponse) { r.nameID = "bob@sub.example.com" }, ""},
		{"email NameID matches a sub: entry", []string{"sub:alice@example.com"}, "", nil, "sub:alice@example.com"},
		{"opaque NameID matches its sub: entry exactly", []string{"sub:G-7f3a"}, "", func(r *samlTestResponse) { r.nameID = "G-7f3a" }, "sub:G-7f3a"},
		{"opaque NameID differing in case is refused", []string{"sub:G-7f3a"}, "", func(r *samlTestResponse) { r.nameID = "g-7f3a" }, ""},
		{"NameID with surrounding space is refused", []string{"sub:G-7f3a"}, "", func(r *samlTestResponse) { r.nameID = " G-7f3a " }, ""},
		{"NameID shaped like a sub: entry is not an email", []string{"sub:alice@example.com"}, "", func(r *samlTestResponse) { r.nameID = "sub:alice@example.com" }, ""},
		{"named attribute is the subject", []string{"alice@example.com"}, "email", func(r *samlTestResponse) {
			r.nameID = "G-7f3a"
			r.attributes = map[string][]string{"email": {"alice@example.com"}}
		}, "alice@example.com"},
		{"named attribute ignores the NameID", []string{"alice@example.com"}, "email", func(r *samlTestResponse) {
			r.attributes = map[string][]string{"email": {"bob@example.com"}}
		}, ""},
		{"named attribute with two values is refused", []string{"@example.com"}, "email", func(r *samlTestResponse) {
			r.attributes = map[string][]string{"email": {"alice@example.com", "bob@example.com"}}
		}, ""},
		{"missing named attribute is refused", []string{"alice@example.com"}, "email", nil, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assertSAMLPrincipalCaseSAML(t, tt)
		})
	}

	t.Run("removing an entry ends its sessions", func(t *testing.T) {
		t.Parallel()
		assertSAMLPrincipalRevocationSAML(t)
	})
}

func TestApplicationAuthSAMLFailureScreens(t *testing.T) {
	t.Parallel()

	idp := newSAMLTestIdP(t)
	gate := newSAMLTestGate(t, idp, nil, nil)
	login := startSAMLLogin(t, gate, types.PathApplicationAuthLogin+"?next=%2Freports")
	response := idp.validResponse(login)
	response.nameID = "bob@example.com"
	req := httptest.NewRequest(http.MethodPost, samlTestACSURL, strings.NewReader(url.Values{"SAMLResponse": {idp.encode(t, response)}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "text/html")
	req.AddCookie(login.cookie)
	rec := httptest.NewRecorder()
	gate.ServeHTTP(rec, req)
	body := rec.Body.String()
	if rec.Code != http.StatusUnauthorized || rec.Header().Get("Content-Security-Policy") != signinContentSecurityPolicy {
		t.Fatalf("denied screen = %d with CSP %q", rec.Code, rec.Header().Get("Content-Security-Policy"))
	}
	for _, want := range []string{"This account is not allowed", "bob@example.com", strings.TrimPrefix(idp.server.URL, "http://"), "next=%2Freports"} {
		if !strings.Contains(body, want) {
			t.Fatalf("denied screen is missing %q", want)
		}
	}
	if strings.Contains(body, "alice@example.com") {
		t.Fatal("denied screen reveals the allowlist")
	}
}

func TestApplicationAuthSAMLMetadata(t *testing.T) {
	t.Parallel()

	idp := newSAMLTestIdP(t)
	for entityID, want := range map[string]string{"": samlTestAudience, "urn:portal:app": "urn:portal:app"} {
		gate := newSAMLTestGate(t, idp, nil, func(cfg *Config) { cfg.SAMLEntityID = entityID })
		rec := httptest.NewRecorder()
		gate.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, samlTestAudience, nil))
		if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/samlmetadata+xml" {
			t.Fatalf("metadata = %d, %q", rec.Code, rec.Header().Get("Content-Type"))
		}
		var got struct {
			EntityID string `xml:"entityID,attr"`
			SP       struct {
				WantAssertionsSigned bool `xml:"WantAssertionsSigned,attr"`
				ACS                  []struct {
					Binding  string `xml:"Binding,attr"`
					Location string `xml:"Location,attr"`
				} `xml:"AssertionConsumerService"`
			} `xml:"SPSSODescriptor"`
		}
		if err := xml.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if got.EntityID != want || got.SP.WantAssertionsSigned || len(got.SP.ACS) != 1 ||
			got.SP.ACS[0].Location != samlTestACSURL || got.SP.ACS[0].Binding != "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" {
			t.Fatalf("metadata = %+v; want entity ID %q and the POST ACS at %s", got, want, samlTestACSURL)
		}
	}
}

func TestApplicationAuthSAMLSessionLifetime(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name    string
		session time.Duration
		want    time.Duration
	}{
		{"no IdP session limit", 0, applicationAuthSessionTTL},
		{"IdP session of two hours", 2 * time.Hour, 2 * time.Hour},
		{"IdP session shorter than the minimum", time.Minute, providerMinSessionTTL},
		{"IdP session longer than the maximum", 72 * time.Hour, applicationAuthSessionTTL},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			idp := newSAMLTestIdP(t)
			gate := newSAMLTestGate(t, idp, nil, nil)
			login := startSAMLLogin(t, gate, types.PathApplicationAuthLogin)
			response := idp.validResponse(login)
			if tt.session != 0 {
				response.sessionNotOnOrAfter = time.Now().Add(tt.session)
			}
			session := assertSAMLACS(t, login.post(gate, idp.encode(t, response)), http.StatusSeeOther)
			if got := time.Duration(session.MaxAge) * time.Second; got < tt.want-5*time.Second || got > tt.want {
				t.Fatalf("session lifetime = %s; want %s", got, tt.want)
			}
		})
	}
}

func writeSAMLCheckFixturesSAML(t *testing.T, idp *samlTestIdP) (file, noKey, expired string) {
	t.Helper()
	file = filepath.Join(t.TempDir(), "idp.xml")
	if err := os.WriteFile(file, []byte(idp.metadata), 0o600); err != nil {
		t.Fatal(err)
	}
	noKey = filepath.Join(t.TempDir(), "no-key.xml")
	if err := os.WriteFile(noKey, []byte(strings.Replace(idp.metadata, `use="signing"`, `use="encryption"`, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	_, expiredCert := newSAMLTestKey(t, time.Now().Add(-time.Minute))
	expired = filepath.Join(t.TempDir(), "expired.xml")
	if err := os.WriteFile(expired, []byte(idp.metadataXML(base64.StdEncoding.EncodeToString(expiredCert))), 0o600); err != nil {
		t.Fatal(err)
	}
	return file, noKey, expired
}

func runSAMLProviderChecksSAML(t *testing.T, idp *samlTestIdP, file, noKey, expired string) {
	t.Helper()
	samlConfig := func(configure func(*Config)) Config {
		cfg := Config{Provider: ProviderSAML, Allow: []string{"alice@example.com"}}
		configure(&cfg)
		return cfg
	}
	for name, tt := range map[string]struct {
		cfg    Config
		usable bool
	}{
		"metadata URL":                 {samlConfig(func(cfg *Config) { cfg.SAMLMetadataURL = idp.metadataURL() }), true},
		"metadata file":                {samlConfig(func(cfg *Config) { cfg.SAMLMetadataFile = file }), true},
		"metadata URL that is missing": {samlConfig(func(cfg *Config) { cfg.SAMLMetadataURL = idp.server.URL + "/missing" }), false},
		"metadata file that is missing": {samlConfig(func(cfg *Config) {
			cfg.SAMLMetadataFile = filepath.Join(t.TempDir(), "absent.xml")
		}), false},
		"metadata without a signing key":    {samlConfig(func(cfg *Config) { cfg.SAMLMetadataFile = noKey }), false},
		"metadata with only an expired key": {samlConfig(func(cfg *Config) { cfg.SAMLMetadataFile = expired }), false},
	} {
		if err := Check(t.Context(), tt.cfg); (err == nil) != tt.usable {
			t.Errorf("%s: Check() = %v; want usable = %v", name, err, tt.usable)
		}
	}
}

func TestCheckApplicationAuthProviderSAML(t *testing.T) {
	t.Parallel()

	idp := newSAMLTestIdP(t)
	file, noKey, expired := writeSAMLCheckFixturesSAML(t, idp)
	runSAMLProviderChecksSAML(t, idp, file, noKey, expired)
}

func TestSAMLPrincipalCarriesTheVouchedEmail(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name   string
		nameID string
		allow  string
		want   Principal
	}{
		{"email entry", "alice@example.com", "alice@example.com", Principal{ProviderSAML, "alice@example.com", "alice@example.com"}},
		{"sub entry with an email NameID", "alice@example.com", "sub:alice@example.com", Principal{ProviderSAML, "sub:alice@example.com", "alice@example.com"}},
		{"sub entry with an opaque NameID", "G-7f3a", "sub:G-7f3a", Principal{ProviderSAML, "sub:G-7f3a", ""}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			idp := newSAMLTestIdP(t)
			gate := newSAMLTestGate(t, idp, nil, func(cfg *Config) { cfg.Allow = []string{tt.allow} })
			login := startSAMLLogin(t, gate, types.PathApplicationAuthLogin)
			response := idp.validResponse(login)
			response.nameID = tt.nameID
			session := assertSAMLACS(t, login.post(gate, idp.encode(t, response)), http.StatusSeeOther)
			req := httptest.NewRequest(http.MethodGet, "https://"+samlTestHost+"/", nil)
			req.AddCookie(session)
			if got, ok := gate.authenticateSession(req); !ok || got != tt.want {
				t.Fatalf("principal = (%+v, %v); want %+v", got, ok, tt.want)
			}
		})
	}
}

func TestParseSAMLMetadataSelectsRedirectBinding(t *testing.T) {
	t.Parallel()

	idp := newSAMLTestIdP(t)
	parsed, err := parseSAMLMetadata([]byte(idp.metadata))
	if err != nil {
		t.Fatal(err)
	}
	if parsed.ssoURL != idp.server.URL+"/sso" {
		t.Fatalf("ssoURL = %q; want the HTTP-Redirect service at %q", parsed.ssoURL, idp.server.URL+"/sso")
	}
	postOnly := strings.Replace(idp.metadata, ` Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"`, ``, 1)
	if _, err := parseSAMLMetadata([]byte(postOnly)); !errors.Is(err, errSAMLMetadataNoRedirectSSO) {
		t.Fatalf("metadata without a redirect binding: error = %v; want %v", err, errSAMLMetadataNoRedirectSSO)
	}
}
func newSAMLTestGate(t *testing.T, idp *samlTestIdP, next http.Handler, configure func(*Config)) *applicationAuth {
	t.Helper()
	cfg := Config{
		Provider:   ProviderSAML,
		Allow:      []string{"alice@example.com"},
		SAMLConfig: SAMLConfig{SAMLMetadataURL: idp.metadataURL()},
	}
	if configure != nil {
		configure(&cfg)
	}
	if next == nil {
		next = http.NotFoundHandler()
	}
	handler, err := New(next, applicationAuthTestIdentity(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	return handler.(*applicationAuth)
}

type samlLogin struct {
	requestID string
	cookie    *http.Cookie
	request   *etree.Element
}

func startSAMLLogin(t *testing.T, gate *applicationAuth, target string) samlLogin {
	t.Helper()
	rec := httptest.NewRecorder()
	gate.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://"+samlTestHost+target, nil))
	location, err := url.Parse(rec.Header().Get("Location"))
	if err != nil || rec.Code != http.StatusSeeOther {
		t.Fatalf("login = %d, %q, %v", rec.Code, rec.Header().Get("Location"), err)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != applicationAuthSAMLStateCookie {
		t.Fatalf("login cookies = %#v", cookies)
	}
	deflated, err := base64.StdEncoding.DecodeString(location.Query().Get("SAMLRequest"))
	if err != nil {
		t.Fatal(err)
	}
	inflated, err := io.ReadAll(flate.NewReader(bytes.NewReader(deflated)))
	if err != nil {
		t.Fatal(err)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(inflated); err != nil {
		t.Fatal(err)
	}
	return samlLogin{requestID: doc.Root().SelectAttrValue("ID", ""), cookie: cookies[0], request: doc.Root()}
}

func (l samlLogin) post(gate *applicationAuth, encoded string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, samlTestACSURL, strings.NewReader(url.Values{"SAMLResponse": {encoded}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if l.cookie != nil {
		req.AddCookie(l.cookie)
	}
	rec := httptest.NewRecorder()
	gate.ServeHTTP(rec, req)
	return rec
}

func assertSAMLACS(t *testing.T, rec *httptest.ResponseRecorder, want int) *http.Cookie {
	t.Helper()
	if rec.Code != want {
		t.Fatalf("acs status = %d, body %q; want %d", rec.Code, strings.TrimSpace(rec.Body.String()), want)
	}
	var session *http.Cookie
	clearedState := false
	for _, c := range rec.Result().Cookies() {
		switch c.Name {
		case applicationAuthCookieName:
			if c.MaxAge >= 0 && c.Value != "" {
				session = c
			}
		case applicationAuthSAMLStateCookie:
			clearedState = c.MaxAge < 0
		}
	}
	if (session != nil) != (want == http.StatusSeeOther) {
		t.Fatalf("session cookie issued = %v for status %d", session != nil, rec.Code)
	}
	if !clearedState {
		t.Fatal("one-time state cookie was not cleared")
	}
	return session
}

func newSAMLLoginGateSAML(t *testing.T, idp *samlTestIdP, upstream *http.Header) *applicationAuth {
	t.Helper()
	return newSAMLTestGate(t, idp, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		*upstream = r.Header.Clone()
	}), func(cfg *Config) { cfg.IdentityHeaders = true })
}

func checkSAMLLoginUnauthenticatedSAML(t *testing.T, gate *applicationAuth) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	gate.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://"+samlTestHost+"/reports?year=2026", nil))
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != types.PathApplicationAuthLogin+"?next="+url.QueryEscape("/reports?year=2026") {
		t.Fatalf("unauthenticated GET = %d, %q", rec.Code, rec.Header().Get("Location"))
	}
	return rec
}

func checkSAMLLoginRequestSAML(t *testing.T, login samlLogin, idp *samlTestIdP) {
	t.Helper()
	if login.cookie.SameSite != http.SameSiteNoneMode || !login.cookie.Secure || !login.cookie.HttpOnly {
		t.Fatalf("state cookie = %+v; the identity provider's cross-site POST must carry it", login.cookie)
	}
	for attr, want := range map[string]string{
		"Destination":                 idp.server.URL + "/sso",
		"AssertionConsumerServiceURL": samlTestACSURL,
		"ProtocolBinding":             "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
	} {
		if got := login.request.SelectAttrValue(attr, ""); got != want {
			t.Fatalf("AuthnRequest %s = %q; want %q", attr, got, want)
		}
	}
	if issuer := login.request.FindElement("./Issuer"); issuer == nil || issuer.Text() != samlTestAudience {
		t.Fatal("AuthnRequest does not name this service provider as its issuer")
	}
	if login.requestID == "" || login.request.FindElement("./Signature") != nil {
		t.Fatalf("AuthnRequest ID = %q; it must be set and the request unsigned", login.requestID)
	}
}

func checkSAMLLoginSessionSAML(t *testing.T, gate *applicationAuth, session *http.Cookie, upstream *http.Header) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "https://"+samlTestHost+"/reports?year=2026", nil)
	req.AddCookie(session)
	req.Header.Set(types.HeaderPortalUser, "mallory@example.com")
	req.Header.Set(types.HeaderPortalAuth, "credential")
	req.Header.Set(types.HeaderPortalProof, "forged-proof-0123456789")
	rec := httptest.NewRecorder()
	gate.ServeHTTP(rec, req)
	if *upstream == nil {
		t.Fatalf("session request = %d; it did not reach the application", rec.Code)
	}
	if got := (*upstream).Get(types.HeaderPortalUser); got != "alice@example.com" {
		t.Fatalf("%s = %q; want alice@example.com", types.HeaderPortalUser, got)
	}
	if got := (*upstream).Get(types.HeaderPortalAuth); got != ProviderSAML {
		t.Fatalf("%s = %q; want saml", types.HeaderPortalAuth, got)
	}
	if got := (*upstream).Values(types.HeaderPortalProof); len(got) != 0 {
		t.Fatalf("%s = %q; the inbound copy must not reach the application", types.HeaderPortalProof, got)
	}
	if strings.Contains((*upstream).Get("Cookie"), applicationAuthCookieName) {
		t.Fatal("the session cookie reached the application")
	}
}
