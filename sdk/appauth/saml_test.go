package appauth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/beevik/etree"

	"github.com/gosuda/portal-tunnel/v2/types"
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
