package appauth

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/beevik/etree"

	"github.com/gosuda/portal-tunnel/v2/types"
)

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
