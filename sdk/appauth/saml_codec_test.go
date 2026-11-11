package appauth

import (
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

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
