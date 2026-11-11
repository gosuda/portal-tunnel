package appauth

import (
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
)

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
