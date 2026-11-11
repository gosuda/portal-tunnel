package appauth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/beevik/etree"

	"github.com/gosuda/portal-tunnel/v2/types"
)

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
