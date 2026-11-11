package appauth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestEmailLinkIsRefusedAtAHostThatIsNoLongerPublic(t *testing.T) {
	t.Parallel()

	const alias = "alias.example"
	now := time.Now().UTC()
	var public atomic.Value
	public.Store([]PublicHost{{URL: "https://" + emailTestHost}, {URL: "https://" + alias, Since: now.Add(-time.Hour)}})
	cfg := emailTestConfig("127.0.0.1:25", "alice@example.com")
	cfg.PublicHosts = func() []PublicHost { return public.Load().([]PublicHost) }
	handler, err := New(http.NotFoundHandler(), applicationAuthTestIdentity(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	gate := handler.(*applicationAuth)
	token := gate.email.issue("alice@example.com", true, alias, "/", now)
	<-gate.email.sendSlots

	public.Store([]PublicHost{{URL: "https://" + emailTestHost}})
	if rec := postEmailJSON(gate, alias, types.PathApplicationAuthEmailRedeem, applicationAuthEmailRedeemRequest{Token: token}); rec.Code != http.StatusMisdirectedRequest {
		t.Fatalf("redeem at a lost alias = %d; want 421", rec.Code)
	}
	newHold := now.Add(time.Minute)
	public.Store([]PublicHost{{URL: "https://" + emailTestHost}, {URL: "https://" + alias, Since: newHold}})
	if rec := postEmailJSON(gate, alias, types.PathApplicationAuthEmailRedeem, applicationAuthEmailRedeemRequest{Token: token}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("redeem of a link from the earlier hold = %d; want 401", rec.Code)
	}
	fresh := gate.email.issue("alice@example.com", true, alias, "/", newHold)
	<-gate.email.sendSlots
	if rec := postEmailJSON(gate, alias, types.PathApplicationAuthEmailRedeem, applicationAuthEmailRedeemRequest{Token: fresh}); rec.Code != http.StatusOK {
		t.Fatalf("redeem of a link from this hold = %d; want 200", rec.Code)
	}
}

func TestLoginRedirectDropsAPathTooLongToPostBack(t *testing.T) {
	t.Parallel()

	gate := newEmailTestGate(t, emailTestConfig("127.0.0.1:25", "alice@example.com"), http.NotFoundHandler())
	for path, want := range map[string]string{
		"/" + strings.Repeat("a", applicationAuthNextLimit-1): "/" + strings.Repeat("a", applicationAuthNextLimit-1),
		"/" + strings.Repeat("a", applicationAuthNextLimit):   "/",
	} {
		rec := httptest.NewRecorder()
		gate.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://"+emailTestHost+path, nil))
		location, err := url.Parse(rec.Header().Get("Location"))
		if rec.Code != http.StatusSeeOther || err != nil {
			t.Fatalf("redirect = %d, %v", rec.Code, err)
		}
		if got := location.Query().Get("next"); got != want {
			t.Fatalf("a path of %d bytes returns to %d bytes; want %d", len(path), len(got), len(want))
		}
	}
}

func newAliasedSessionGate(t *testing.T) (*atomic.Value, *applicationAuth, []*http.Cookie) {
	t.Helper()
	const alias = "alias.example"
	var public atomic.Value
	public.Store([]PublicHost{{URL: "https://" + emailTestHost}, {URL: "https://" + alias}})
	cfg := emailTestConfig("127.0.0.1:25", "alice@example.com")
	cfg.PublicHosts = func() []PublicHost { return public.Load().([]PublicHost) }
	handler, err := New(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), applicationAuthTestIdentity(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	gate := handler.(*applicationAuth)
	token := gate.email.issue("alice@example.com", true, alias, "/", time.Now().UTC())
	<-gate.email.sendSlots
	redeem := postEmailJSON(gate, alias, types.PathApplicationAuthEmailRedeem, applicationAuthEmailRedeemRequest{Token: token})
	if redeem.Code != http.StatusOK || len(redeem.Result().Cookies()) != 1 {
		t.Fatalf("redeem = %d, cookies = %v", redeem.Code, redeem.Result().Cookies())
	}
	return &public, gate, redeem.Result().Cookies()
}
func checkAliasedSessionOpen(t *testing.T, gate *applicationAuth, cookies []*http.Cookie) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "https://alias.example/private", nil)
	req.AddCookie(cookies[0])
	rec := httptest.NewRecorder()
	gate.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("session on a public alias = %d; want 204", rec.Code)
	}
}
func checkAliasedSessionLost(t *testing.T, gate *applicationAuth, cookies []*http.Cookie) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "https://alias.example/private", nil)
	req.AddCookie(cookies[0])
	rec := httptest.NewRecorder()
	gate.ServeHTTP(rec, req)
	if rec.Code != http.StatusMisdirectedRequest {
		t.Fatalf("session on a lost alias = %d; want 421", rec.Code)
	}
}
func checkAliasedSessionBack(t *testing.T, gate *applicationAuth, cookies []*http.Cookie) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "https://alias.example/private", nil)
	req.AddCookie(cookies[0])
	rec := httptest.NewRecorder()
	gate.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("session after the alias came back = %d; want the login redirect", rec.Code)
	}
}
func TestEmailSessionEndsWithItsPublicHost(t *testing.T) {
	t.Parallel()
	const alias = "alias.example"
	public, gate, cookies := newAliasedSessionGate(t)
	checkAliasedSessionOpen(t, gate, cookies)
	public.Store([]PublicHost{{URL: "https://" + emailTestHost}})
	checkAliasedSessionLost(t, gate, cookies)
	public.Store([]PublicHost{{URL: "https://" + emailTestHost}, {URL: "https://" + alias, Since: time.Now().Add(time.Minute)}})
	checkAliasedSessionBack(t, gate, cookies)
}
func checkSessionAgainstAllowlist(t *testing.T, session string, allowed []string, want int) {
	t.Helper()
	gate := newEmailTestGate(t, emailTestConfig("127.0.0.1:25", allowed...), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodGet, "https://"+emailTestHost+"/", nil)
	req.AddCookie(&http.Cookie{Name: applicationAuthCookieName, Value: session})
	rec := httptest.NewRecorder()
	gate.ServeHTTP(rec, req)
	if rec.Code != want {
		t.Fatalf("allowlist %q: status = %d; want %d", allowed, rec.Code, want)
	}
}
func checkSessionAfterConfigChange(t *testing.T, session string, name string, change func(*Config)) {
	t.Helper()
	cfg := emailTestConfig("127.0.0.1:25", "alice@example.com")
	change(&cfg)
	gate := newEmailTestGate(t, cfg, http.NotFoundHandler())
	req := httptest.NewRequest(http.MethodGet, "https://"+emailTestHost+"/", nil)
	req.AddCookie(&http.Cookie{Name: applicationAuthCookieName, Value: session})
	rec := httptest.NewRecorder()
	gate.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("new %s: status = %d; want the session refused", name, rec.Code)
	}
}
func TestEmailSessionFollowsTheAllowlist(t *testing.T) {
	t.Parallel()
	issued := newEmailTestGate(t, emailTestConfig("127.0.0.1:25", "alice@example.com"), http.NotFoundHandler())
	session, err := issued.issueSession(Principal{Provider: ProviderEmail, Subject: "alice@example.com"}, emailTestHost, time.Now(), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		allowed []string
		want    int
	}{
		{[]string{"alice@example.com"}, http.StatusNoContent},
		{[]string{"@example.com"}, http.StatusNoContent},
		{[]string{"bob@example.com"}, http.StatusSeeOther},
	} {
		checkSessionAgainstAllowlist(t, session, tc.allowed, tc.want)
	}
	for name, change := range map[string]func(*Config){
		"server":   func(c *Config) { c.SMTPAddr = "127.0.0.1:587" },
		"username": func(c *Config) { c.SMTPUsername = "other" },
		"sender":   func(c *Config) { c.SMTPFrom = "other@portal.example" },
	} {
		checkSessionAfterConfigChange(t, session, name, change)
	}
}
func TestEmailPrincipalIsTheAddress(t *testing.T) {
	t.Parallel()

	gate := newEmailTestGate(t, emailTestConfig("127.0.0.1:25", "alice@example.com"), http.NotFoundHandler())
	token := gate.email.issue("alice@example.com", true, emailTestHost, "/", time.Now().UTC())
	<-gate.email.sendSlots
	rec := postEmailJSON(gate, emailTestHost, types.PathApplicationAuthEmailRedeem, applicationAuthEmailRedeemRequest{Token: token})
	if rec.Code != http.StatusOK {
		t.Fatalf("redeem status = %d, body = %s", rec.Code, rec.Body.String())
	}
	req := httptest.NewRequest(http.MethodGet, "https://"+emailTestHost+"/", nil)
	req.AddCookie(rec.Result().Cookies()[0])
	want := Principal{ProviderEmail, "alice@example.com", "alice@example.com"}
	if got, ok := gate.authenticateSession(req); !ok || got != want {
		t.Fatalf("principal = (%+v, %v); want %+v", got, ok, want)
	}
}
