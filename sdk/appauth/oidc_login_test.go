package appauth

import (
	"cmp"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestApplicationAuthOIDCCallbackRefusals(t *testing.T) {
	t.Parallel()

	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	unsigned := func(string) string {
		header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
		payload := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"x","sub":"user-123","aud":"` + oidcTestClientID + `"}`))
		return header + "." + payload + "."
	}

	tests := []struct {
		name      string
		configure func(p *oidcTestIdP)
		tamper    oidcTamper
		loginHost string
		want      int
	}{
		{name: "control: valid login issues a session", want: http.StatusSeeOther},
		{name: "state parameter differs from the state cookie", tamper: withQuery("code=authcode&state=forged"), want: http.StatusUnauthorized},
		{name: "state cookie is missing", tamper: withStateCookie(nil), want: http.StatusUnauthorized},
		{
			name: "state cookie was tampered with",
			tamper: withStateCookie(func(_ *testing.T, _ *applicationAuth, value string) string {
				if value[0] == 'A' {
					return "B" + value[1:]
				}
				return "A" + value[1:]
			}),
			want: http.StatusUnauthorized,
		},
		{name: "state cookie has expired", tamper: withStateCookie(expireOIDCState), want: http.StatusUnauthorized},
		{name: "state cookie was issued for another host", loginHost: "other.example", want: http.StatusUnauthorized},
		{name: "identity provider reports an error", tamper: withQuery("error=access_denied"), want: http.StatusUnauthorized},
		{name: "token endpoint rejects the code", configure: func(p *oidcTestIdP) { p.tokenStatus = http.StatusBadRequest }, want: http.StatusUnauthorized},
		{name: "token response has no id_token", configure: func(p *oidcTestIdP) { p.omitToken = true }, want: http.StatusUnauthorized},
		{name: "nonce does not match", configure: func(p *oidcTestIdP) { p.mutate = func(c *oidcIDTokenClaims) { c.Nonce = "replayed" } }, want: http.StatusUnauthorized},
		{name: "audience is another client", configure: func(p *oidcTestIdP) {
			p.mutate = func(c *oidcIDTokenClaims) { c.Audience = jwt.Audience{"someone-else"} }
		}, want: http.StatusUnauthorized},
		{name: "issuer is another provider", configure: func(p *oidcTestIdP) {
			p.mutate = func(c *oidcIDTokenClaims) { c.Issuer = "https://evil.example" }
		}, want: http.StatusUnauthorized},
		{name: "id token has expired", configure: func(p *oidcTestIdP) {
			p.mutate = func(c *oidcIDTokenClaims) { c.Expiry = jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)) }
		}, want: http.StatusUnauthorized},
		{name: "id token has no expiry", configure: func(p *oidcTestIdP) {
			p.mutate = func(c *oidcIDTokenClaims) { c.Expiry = nil }
		}, want: http.StatusUnauthorized},
		{name: "id token is signed with an unknown key", configure: func(p *oidcTestIdP) {
			p.signWith = newOIDCTestSigner(t, jose.ES256, otherKey, "k1")
		}, want: http.StatusUnauthorized},
		{name: "id token uses a symmetric algorithm", configure: func(p *oidcTestIdP) {
			p.signWith = newOIDCTestSigner(t, jose.HS256, []byte("shared-secret-of-sufficient-length"), "k1")
		}, want: http.StatusUnauthorized},
		{name: "id token is unsigned", configure: func(p *oidcTestIdP) { p.rawToken = unsigned }, want: http.StatusUnauthorized},
		{name: "id token has no subject", configure: func(p *oidcTestIdP) {
			p.mutate = func(c *oidcIDTokenClaims) { c.Subject = "" }
		}, want: http.StatusUnauthorized},
		{name: "account is not on the allowlist", configure: func(p *oidcTestIdP) {
			p.mutate = func(c *oidcIDTokenClaims) { c.Subject, c.Email = "user-999", "mallory@example.com" }
		}, want: http.StatusUnauthorized},
		{name: "allowed email is not verified", configure: func(p *oidcTestIdP) {
			p.mutate = func(c *oidcIDTokenClaims) { c.EmailVerified = false }
		}, want: http.StatusUnauthorized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			idp := newOIDCTestIdP(t, tt.configure)
			gate := newOIDCTestGate(t, idp)
			login := startRefusedCallbackLogin(t, gate, idp, tt.loginHost)
			rec := httptest.NewRecorder()
			gate.ServeHTTP(rec, login.callbackRequest(t, gate, tt.tamper))
			assertOIDCCallback(t, rec, tt.want)
		})
	}
}

type TestApplicationAuthOIDCFailureScreensCase struct {
	name      string
	configure func(p *oidcTestIdP)
	tamper    oidcTamper
	title     string
	retry     string
}

func TestApplicationAuthOIDCFailureScreens(t *testing.T) {
	t.Parallel()

	tests := []TestApplicationAuthOIDCFailureScreensCase{
		{name: "visitor canceled at the provider", tamper: withQuery("error=access_denied"), title: "Sign-in was canceled"},
		{name: "provider reported another error", tamper: withQuery("error=server_error"), title: "Sign-in could not be completed"},
		{name: "state cookie is missing", tamper: withStateCookie(nil), title: "Sign-in took too long"},
		{name: "state cookie has expired", tamper: withStateCookie(expireOIDCState), title: "Sign-in took too long"},
		{name: "state belongs to another login", tamper: withQuery("code=authcode&state=other"), title: "Sign-in took too long"},
		{name: "token endpoint rejects the code", configure: func(p *oidcTestIdP) { p.tokenStatus = http.StatusBadRequest }, title: "Sign-in could not be completed"},
		{name: "account is not on the allowlist", configure: func(p *oidcTestIdP) {
			p.mutate = func(c *oidcIDTokenClaims) { c.Subject, c.Email = "user-999", "mallory@example.com" }
		}, title: "This account is not allowed", retry: types.PathApplicationAuthLogin + "?prompt=select_account"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			exerciseFailureScreens(t, tt)
		})
	}
}
func exerciseFailureScreens(t *testing.T, tt TestApplicationAuthOIDCFailureScreensCase) {
	t.Helper()
	for _, browser := range []bool{true, false} {
		idp := newOIDCTestIdP(t, tt.configure)
		gate := newOIDCTestGate(t, idp)
		login := startOIDCLogin(t, gate, idp, "app.example", types.PathApplicationAuthLogin)
		req := login.callbackRequest(t, gate, tt.tamper)
		if browser {
			req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		}
		rec := httptest.NewRecorder()
		gate.ServeHTTP(rec, req)
		assertOIDCCallback(t, rec, http.StatusUnauthorized)
		body := rec.Body.String()
		if !browser {
			checkScriptedFailureScreen(t, rec, body)
			continue
		}
		checkBrowserFailureScreen(t, rec, body, tt.title, tt.retry)
	}
}
func checkScriptedFailureScreen(t *testing.T, rec *httptest.ResponseRecorder, body string) {
	t.Helper()
	var answer map[string]string
	if rec.Header().Get("Content-Type") != "application/json" || json.Unmarshal(rec.Body.Bytes(), &answer) != nil || answer["error"] == "" {
		t.Fatalf("scripted caller got %q: %q", rec.Header().Get("Content-Type"), body)
	}
}

func checkBrowserFailureScreen(t *testing.T, rec *httptest.ResponseRecorder, body string, title string, retry string) {
	t.Helper()
	if rec.Header().Get("Content-Type") != "text/html; charset=utf-8" || rec.Header().Get("Content-Security-Policy") != signinContentSecurityPolicy {
		t.Fatalf("browser got %q under CSP %q", rec.Header().Get("Content-Type"), rec.Header().Get("Content-Security-Policy"))
	}
	retry = cmp.Or(retry, types.PathApplicationAuthLogin)
	for _, want := range []string{"<h1>" + title + "</h1>", "app.example", `href="` + retry + `"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("page is missing %q", want)
		}
	}
}

func TestApplicationAuthOIDCDeniedScreenShowsOnlyTheVisitorsAccount(t *testing.T) {
	t.Parallel()

	allowed := []string{"alice@example.com", "@corp.example", "sub:admin-1"}
	tests := []struct {
		name    string
		mutate  func(c *oidcIDTokenClaims)
		account string
	}{
		{name: "verified email", mutate: func(c *oidcIDTokenClaims) { c.Email = "mallory@example.com" }, account: "mallory@example.com"},
		{name: "unverified email", mutate: func(c *oidcIDTokenClaims) {
			c.Subject, c.Email, c.EmailVerified = "user-999", "mallory@example.com", false
		}, account: "sub:user-999"},
		{name: "subject with markup", mutate: func(c *oidcIDTokenClaims) {
			c.Subject, c.EmailVerified = `<img src=x onerror=alert(1)>`, false
		}, account: "sub:&lt;img src=x onerror=alert(1)&gt;"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			idp := newOIDCTestIdP(t, func(p *oidcTestIdP) { p.mutate = tt.mutate })
			gate := newOIDCTestGate(t, idp, allowed...)
			req := startOIDCLogin(t, gate, idp, "app.example", types.PathApplicationAuthLogin).callbackRequest(t, gate, nil)
			req.Header.Set("Accept", "text/html")
			rec := httptest.NewRecorder()
			gate.ServeHTTP(rec, req)
			assertOIDCCallback(t, rec, http.StatusUnauthorized)

			checkDeniedScreenAccount(t, rec.Body.String(), tt.account, allowed)
		})
	}
}
func checkDeniedScreenAccount(t *testing.T, body string, account string, allowed []string) {
	t.Helper()
	if !strings.Contains(body, "<b>"+account+"</b>") {
		t.Fatalf("page does not show the account %q", account)
	}
	if strings.Contains(body, "<img") {
		t.Fatal("account reached the page unescaped")
	}
	for _, entry := range allowed {
		if strings.Contains(body, entry) {
			t.Fatalf("page reveals the allowlist entry %q", entry)
		}
	}
}

func TestApplicationAuthOIDCRetryAsksForAccountChooser(t *testing.T) {
	t.Parallel()

	idp := newOIDCTestIdP(t, func(p *oidcTestIdP) {
		p.mutate = func(c *oidcIDTokenClaims) { c.Subject, c.Email = "user-999", "mallory@example.com" }
	})
	gate := newOIDCTestGate(t, idp)
	login := startOIDCLogin(t, gate, idp, "app.example", types.PathApplicationAuthLogin+"?next="+url.QueryEscape("/docs?page=2"))
	req := login.callbackRequest(t, gate, nil)
	req.Header.Set("Accept", "text/html")
	denied := httptest.NewRecorder()
	gate.ServeHTTP(denied, req)
	assertOIDCCallback(t, denied, http.StatusUnauthorized)
	retry := `href="` + types.PathApplicationAuthLogin + `?next=%2Fdocs%3Fpage%3D2&amp;prompt=select_account"`
	if !strings.Contains(denied.Body.String(), retry) {
		t.Fatalf("retry link is not the account-chooser login: %q", denied.Body.String())
	}

	verifyRetryAccountChooser(t, gate)
}
func verifyRetryAccountChooser(t *testing.T, gate *applicationAuth) {
	t.Helper()
	for _, tt := range []struct {
		name, path string
		chooser    bool
	}{
		{name: "plain login", path: types.PathApplicationAuthLogin},
		{name: "prompt none", path: types.PathApplicationAuthLogin + "?prompt=none"},
		{name: "prompt login", path: types.PathApplicationAuthLogin + "?prompt=login"},
		{name: "account chooser", path: types.PathApplicationAuthLogin + "?prompt=select_account", chooser: true},
	} {
		rec := httptest.NewRecorder()
		gate.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://app.example"+tt.path, nil))
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("%s: login = %d", tt.name, rec.Code)
		}
		authorize, err := url.Parse(rec.Header().Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		prompt, sent := authorize.Query()["prompt"]
		if sent != tt.chooser {
			t.Fatalf("%s: provider got prompt %q, want account chooser %v", tt.name, prompt, tt.chooser)
		}
		if tt.chooser && strings.Join(prompt, ",") != "select_account" {
			t.Fatalf("%s: provider got prompt %q, want select_account", tt.name, prompt)
		}
	}
}

func TestApplicationAuthOIDCUnreachableProviderScreen(t *testing.T) {
	t.Parallel()

	idp := newOIDCTestIdP(t, nil)
	gate := newOIDCTestGate(t, idp)
	idp.server.Close()

	for accept, contentType := range map[string]string{"text/html": "text/html; charset=utf-8", "": "text/plain; charset=utf-8"} {
		req := httptest.NewRequest(http.MethodGet, "https://app.example"+types.PathApplicationAuthLogin+"?next="+url.QueryEscape("/docs?page=2"), nil)
		req.Header.Set("Accept", accept)
		rec := httptest.NewRecorder()
		gate.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadGateway || rec.Header().Get("Content-Type") != contentType || len(rec.Result().Cookies()) != 0 {
			t.Fatalf("Accept %q: %d %q with cookies %v", accept, rec.Code, rec.Header().Get("Content-Type"), rec.Result().Cookies())
		}
		if accept == "" {
			continue
		}
		body := rec.Body.String()
		for _, want := range []string{"<h1>Sign-in could not be completed</h1>", `href="` + types.PathApplicationAuthLogin + `?next=%2Fdocs%3Fpage%3D2"`} {
			if !strings.Contains(body, want) {
				t.Fatalf("page is missing %q", want)
			}
		}
	}
}

func TestApplicationAuthOIDCEndpointQueries(t *testing.T) {
	t.Parallel()
	idp := newOIDCTestIdP(t, func(p *oidcTestIdP) { p.query = "?tenant=team" })
	gate := newOIDCTestGate(t, idp)
	login := httptest.NewRecorder()
	gate.ServeHTTP(login, httptest.NewRequest(http.MethodGet, "https://app.example"+types.PathApplicationAuthLogin, nil))
	if login.Code != http.StatusSeeOther {
		t.Fatalf("login status = %d, body %q; want 303", login.Code, login.Body.String())
	}
	authURL, err := url.Parse(login.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if got := authURL.Query().Get("tenant"); got != "team" {
		t.Fatalf("authorization endpoint tenant = %q; want team", got)
	}
	idp.expect(authURL.Query().Get("code_challenge"), authURL.Query().Get("nonce"))
	state := oidcLogin{state: authURL.Query().Get("state"), cookie: login.Result().Cookies()[0]}
	callback := httptest.NewRecorder()
	gate.ServeHTTP(callback, state.callbackRequest(t, gate, nil))
	assertOIDCCallback(t, callback, http.StatusSeeOther)
}

func TestApplicationAuthOIDCLoginStartsOnlyOnGet(t *testing.T) {
	t.Parallel()
	gate := newOIDCTestGate(t, newOIDCTestIdP(t, nil))
	rec := httptest.NewRecorder()
	gate.ServeHTTP(rec, httptest.NewRequest(http.MethodHead, "https://app.example"+types.PathApplicationAuthLogin, nil))
	if rec.Code != http.StatusMethodNotAllowed || len(rec.Result().Cookies()) != 0 {
		t.Fatalf("HEAD login = %d with cookies %v; want 405 and no state cookie", rec.Code, rec.Result().Cookies())
	}
}

func TestApplicationAuthOIDCStateCookieStaysWithinBrowserLimit(t *testing.T) {
	t.Parallel()

	long := "/" + strings.Repeat("a", 1500)
	tests := []struct {
		name string
		next string
		want string
	}{
		{"short link is kept", "/dashboard?tab=1", "/dashboard?tab=1"},
		{"long link that fits is kept", long, long},
		{"link too long for the cookie", "/" + strings.Repeat("a", 5000), "/"},
		{"link that grows when it is escaped", "/" + strings.Repeat("<", 1000), "/"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			idp := newOIDCTestIdP(t, nil)
			gate := newOIDCTestGate(t, idp)
			rec := httptest.NewRecorder()
			gate.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://app.example"+types.PathApplicationAuthLogin+"?next="+url.QueryEscape(tt.next), nil))
			authURL, err := url.Parse(rec.Header().Get("Location"))
			cookies := rec.Result().Cookies()
			if err != nil || rec.Code != http.StatusSeeOther || len(cookies) != 1 {
				t.Fatalf("login = %d, %q, %v, %d cookies", rec.Code, rec.Header().Get("Location"), err, len(cookies))
			}
			if size := len(cookies[0].String()); size > 4096 {
				t.Fatalf("state cookie is %d bytes; a browser drops one of about 4096", size)
			}
			idp.expect(authURL.Query().Get("code_challenge"), authURL.Query().Get("nonce"))
			login := oidcLogin{state: authURL.Query().Get("state"), cookie: cookies[0]}
			callback := httptest.NewRecorder()
			gate.ServeHTTP(callback, login.callbackRequest(t, gate, nil))
			assertOIDCCallback(t, callback, http.StatusSeeOther)
			if got := callback.Header().Get("Location"); got != tt.want {
				t.Fatalf("login returned to %q; want %q", got, tt.want)
			}
		})
	}
}

func TestApplicationAuthOIDCSessionLifetime(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		tokenLifetime time.Duration
		want          time.Duration
	}{
		{"token already inside the verification leeway", -30 * time.Second, providerMinSessionTTL},
		{"token shorter than the minimum", 5 * time.Minute, providerMinSessionTTL},
		{"token between the bounds", time.Hour, time.Hour},
		{"token longer than the maximum", 72 * time.Hour, applicationAuthSessionTTL},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			idp := newOIDCTestIdP(t, func(p *oidcTestIdP) {
				p.mutate = func(c *oidcIDTokenClaims) { c.Expiry = jwt.NewNumericDate(time.Now().Add(tt.tokenLifetime)) }
			})
			gate := newOIDCTestGate(t, idp)
			start := time.Now()
			login := startOIDCLogin(t, gate, idp, "app.example", types.PathApplicationAuthLogin)
			callback := httptest.NewRecorder()
			gate.ServeHTTP(callback, login.callbackRequest(t, gate, nil))
			assertOIDCCallback(t, callback, http.StatusSeeOther)
			if got := oidcSessionExpiry(t, gate, callback).Sub(start); got < tt.want-5*time.Second || got > tt.want+5*time.Second {
				t.Fatalf("session lasts %v; want about %v", got, tt.want)
			}
		})
	}
}

func oidcSessionExpiry(t *testing.T, gate *applicationAuth, rec *httptest.ResponseRecorder) time.Time {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name != applicationAuthCookieName {
			continue
		}
		var claims applicationAuthClaims
		if err := decodeSignedApplicationAuthJSON(gate.signingKey, c.Value, &claims); err != nil {
			t.Fatal(err)
		}
		return time.Unix(claims.ExpiresAt, 0)
	}
	t.Fatal("no session cookie")
	return time.Time{}
}

func TestCheckApplicationAuthProvider(t *testing.T) {
	t.Parallel()

	t.Run("reachable provider", func(t *testing.T) {
		t.Parallel()
		checkReachableProvider(t)
	})
	t.Run("issuer that publishes no discovery document", func(t *testing.T) {
		t.Parallel()
		checkProviderWithoutDiscovery(t)
	})
	t.Run("provider that is down", func(t *testing.T) {
		t.Parallel()
		checkProviderDown(t)
	})
	t.Run("configuration the resolver rejects", func(t *testing.T) {
		t.Parallel()
		checkAllowlistRejection(t)
	})
	t.Run("providers with nothing outside the tunnel", func(t *testing.T) {
		t.Parallel()
		checkLocalProviders(t)
	})
}
func newProviderCheckConfig(issuer string) Config {
	return Config{
		Provider:   ProviderOIDC,
		Allow:      []string{"alice@example.com"},
		OIDCConfig: OIDCConfig{OIDCIssuerURL: issuer, OIDCClientID: oidcTestClientID},
	}
}
func checkReachableProvider(t *testing.T) {
	t.Helper()
	idp := newOIDCTestIdP(t, nil)
	if err := Check(t.Context(), newProviderCheckConfig(idp.issuerURL)); err != nil {
		t.Fatalf("Check() = %v; want nil", err)
	}
}

func checkProviderWithoutDiscovery(t *testing.T) {
	t.Helper()
	idp := newOIDCTestIdP(t, nil)
	if err := Check(t.Context(), newProviderCheckConfig(idp.issuerURL+"/missing")); err == nil {
		t.Fatal("Check() = nil for an issuer without a discovery document")
	}
}

func checkProviderDown(t *testing.T) {
	t.Helper()
	idp := newOIDCTestIdP(t, nil)
	idp.server.Close()
	if err := Check(t.Context(), newProviderCheckConfig(idp.issuerURL)); err == nil {
		t.Fatal("Check() = nil for a provider that is down")
	}
}

func checkAllowlistRejection(t *testing.T) {
	t.Helper()
	cfg := Config{Provider: ProviderOIDC, OIDCConfig: OIDCConfig{OIDCIssuerURL: "https://idp.example", OIDCClientID: oidcTestClientID}}
	if err := Check(t.Context(), cfg); err == nil || !strings.Contains(err.Error(), "--auth-email-list") {
		t.Fatalf("Check() = %v; want the resolver's error about the missing allowlist", err)
	}
}

func checkLocalProviders(t *testing.T) {
	t.Helper()
	for _, provider := range []string{ProviderSIWE, ProviderCredential} {
		if err := Check(t.Context(), Config{Provider: provider}); err != nil {
			t.Errorf("Check(%s) = %v; want nil", provider, err)
		}
	}
}

func TestOIDCPrincipalCarriesTheVouchedEmail(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name     string
		allow    string
		verified oidcEmailVerified
		want     Principal
	}{
		{"email entry", "alice@example.com", true, Principal{ProviderOIDC, "alice@example.com", "alice@example.com"}},
		{"sub entry with a verified email", "sub:user-123", true, Principal{ProviderOIDC, "sub:user-123", "alice@example.com"}},
		{"sub entry with an unverified email", "sub:user-123", false, Principal{ProviderOIDC, "sub:user-123", ""}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			idp := newOIDCTestIdP(t, func(p *oidcTestIdP) {
				p.mutate = func(c *oidcIDTokenClaims) { c.EmailVerified = tt.verified }
			})
			gate := newOIDCTestGate(t, idp, tt.allow)
			rec := completeOIDCLogin(t, gate, idp)
			assertOIDCCallback(t, rec, http.StatusSeeOther)
			req := httptest.NewRequest(http.MethodGet, "https://app.example/", nil)
			for _, cookie := range rec.Result().Cookies() {
				req.AddCookie(cookie)
			}
			if got, ok := gate.authenticateSession(req); !ok || got != tt.want {
				t.Fatalf("principal = (%+v, %v); want %+v", got, ok, tt.want)
			}
		})
	}
}
