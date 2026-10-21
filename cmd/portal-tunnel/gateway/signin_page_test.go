package gateway

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newSigninTestHandler(t *testing.T, provider string) http.Handler {
	t.Helper()
	handler, err := NewApplicationAuth(http.NotFoundHandler(), applicationAuthTestIdentity(), ApplicationAuthConfig{Provider: provider})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func getSigninPage(handler http.Handler, host string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "https://app.example"+applicationAuthLoginPath, nil)
	req.Host = host
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

// Both providers answer with the shared Portal shell and their own controls,
// under a content policy that admits scripts and styles from the page itself and
// fonts from one host only.
func TestSigninPagesShareOneShell(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		provider string
		control  string
	}{
		{ApplicationAuthProviderCredential, `id="credential"`},
		{ApplicationAuthProviderSIWE, `data-connect`},
	} {
		t.Run(tc.provider, func(t *testing.T) {
			t.Parallel()
			rec := getSigninPage(newSigninTestHandler(t, tc.provider), "app.example")
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d; want 200", rec.Code)
			}
			if got := rec.Header().Get("Content-Security-Policy"); got != signinContentSecurityPolicy {
				t.Fatalf("Content-Security-Policy = %q", got)
			}
			for header, want := range map[string]string{
				"Content-Type":           "text/html; charset=utf-8",
				"Cache-Control":          "no-store",
				"X-Content-Type-Options": "nosniff",
			} {
				if got := rec.Header().Get(header); got != want {
					t.Fatalf("%s = %q; want %q", header, got, want)
				}
			}
			body := rec.Body.String()
			for _, want := range []string{"Protected by Portal", `id="mark"`, "app.example", tc.control} {
				if !strings.Contains(body, want) {
					t.Fatalf("page is missing %q", want)
				}
			}
		})
	}
}

func TestSigninPageHeadCarriesNoBody(t *testing.T) {
	t.Parallel()

	handler := newSigninTestHandler(t, ApplicationAuthProviderCredential)
	req := httptest.NewRequest(http.MethodHead, "https://app.example"+applicationAuthLoginPath, nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Body.Len() != 0 || rec.Header().Get("Content-Security-Policy") == "" {
		t.Fatalf("HEAD = %d with %d body bytes and CSP %q", rec.Code, rec.Body.Len(), rec.Header().Get("Content-Security-Policy"))
	}
}

// The host comes from the request, so it must never reach the page unescaped,
// and a long identity-bound host is shortened for display only.
func TestSigninPageEscapesAndShortensHost(t *testing.T) {
	t.Parallel()

	handler := newSigninTestHandler(t, ApplicationAuthProviderCredential)

	hostile := `x"><script>alert(1)</script>.example`
	body := getSigninPage(handler, hostile).Body.String()
	if strings.Contains(body, "<script>alert(1)") || strings.Contains(body, `x"><`) {
		t.Fatal("request host reached the page unescaped")
	}

	canonical := "home-ha-377e330d882679f6c2728b47aab51a14164083d4.relay.example"
	body = getSigninPage(handler, canonical).Body.String()
	if !strings.Contains(body, "<span>home-ha-377e…83d4.relay.example</span>") {
		t.Fatal("host chip does not show the shortened host")
	}
	if !strings.Contains(body, `title="`+canonical+`"`) {
		t.Fatal("full host is not available as the chip title")
	}
}

// Browsers drop tabs and newlines from URLs, so a post-login target such as
// "/<TAB>/host" would become "//host". Every page refuses control characters.
func TestSigninPagesRefuseControlCharactersInNext(t *testing.T) {
	t.Parallel()

	for _, page := range []string{signinCredentialPage, signinWalletPage} {
		if got := strings.Count(page, `/[\u0000-\u001f\u007f]/.test(value)`); got != 1 {
			t.Fatalf("control-character check appears %d times in a page; want once", got)
		}
	}
}
