package agent

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gosuda/portal-tunnel/v2/types"
)

// The wallet session cookie is the browser-side transport of the server-side
// session, so its lifetime and security attributes are part of the session
// contract: it must never outlive walletSessionTTL and must stay scoped to the
// agent control plane with the HttpOnly, Secure, and SameSite=Strict flags.
func TestWalletSessionCookieMatchesSessionPolicy(t *testing.T) {
	auth := &walletAuthenticator{sessions: make(map[string]walletAuthSession)}

	issued := httptest.NewRecorder()
	auth.setSessionCookie(issued, "was_test")

	cookies := issued.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("issued cookies = %d, want 1", len(cookies))
	}
	cookie := cookies[0]
	if cookie.Name != walletSessionCookieName {
		t.Fatalf("cookie name = %q, want %q", cookie.Name, walletSessionCookieName)
	}
	if want := int(walletSessionTTL.Seconds()); cookie.MaxAge != want {
		t.Fatalf("cookie MaxAge = %d, want session TTL %d", cookie.MaxAge, want)
	}
	if cookie.Value != "was_test" {
		t.Fatalf("cookie value = %q, want the session token", cookie.Value)
	}
	if cookie.Path != types.PathAgentPrefix || !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("cookie attributes = path %q httpOnly %v secure %v sameSite %v, want scoped HttpOnly+Secure+Strict",
			cookie.Path, cookie.HttpOnly, cookie.Secure, cookie.SameSite)
	}

	req := httptest.NewRequest(http.MethodGet, types.PathAgentStatus, nil)
	req.AddCookie(cookie)
	if got := auth.sessionToken(req); got != "was_test" {
		t.Fatalf("sessionToken() = %q, want the issued token", got)
	}

	cleared := httptest.NewRecorder()
	auth.clearSessionCookie(cleared)
	cookies = cleared.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Value != "" || cookies[0].MaxAge >= 0 {
		t.Fatalf("cleared cookie = %+v, want empty value with MaxAge < 0", cookies)
	}
}
