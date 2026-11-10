package appauth

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestApplicationSessionRefusesOtherOrigins(t *testing.T) {
	t.Parallel()

	tunnelIdentity := applicationAuthTestIdentity()
	upstreamRequests := 0
	handler, err := New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamRequests++
		w.WriteHeader(http.StatusNoContent)
	}), tunnelIdentity, Config{Provider: ProviderCredential})
	if err != nil {
		t.Fatal(err)
	}
	credential := issueOriginCredential(t, tunnelIdentity)
	session := redeemOriginCookie(t, handler, credential)

	checkOriginPolicyTable(t, handler, session, &upstreamRequests)
}

func issueOriginCredential(t *testing.T, tunnelIdentity types.Identity) string {
	t.Helper()
	credential, err := IssueCredential(tunnelIdentity, "app.example", "alice", time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return credential
}

func redeemOriginCookie(t *testing.T, handler http.Handler, credential string) *http.Cookie {
	t.Helper()
	body, _ := json.Marshal(applicationAuthRedeemRequest{Credential: credential})
	redeem := httptest.NewRequest(http.MethodPost, "https://app.example"+types.PathApplicationAuthRedeem, bytes.NewReader(body))
	redeem.Header.Set("Origin", "https://app.example")
	redeemRec := httptest.NewRecorder()
	handler.ServeHTTP(redeemRec, redeem)
	if redeemRec.Code != http.StatusOK || len(redeemRec.Result().Cookies()) != 1 {
		t.Fatalf("redeem status = %d, cookies = %#v", redeemRec.Code, redeemRec.Result().Cookies())
	}
	return redeemRec.Result().Cookies()[0]
}

func upgradeOriginHeaders(origin string) http.Header {
	return http.Header{"Connection": {"Upgrade"}, "Upgrade": {"websocket"}, "Origin": {origin}}
}

func buildOriginHeader(origin string) http.Header {
	return http.Header{"Origin": {origin}}
}

func fetchSiteOriginHeaders(origin, site string) http.Header {
	return http.Header{"Origin": {origin}, "Sec-Fetch-Site": {site}}
}

func checkOriginPolicyTable(t *testing.T, handler http.Handler, session *http.Cookie, upstream *int) {
	t.Helper()
	const self, other = "https://app.example", "https://other.example"
	for _, tt := range []struct {
		name       string
		method     string
		headers    http.Header
		wantStatus int
	}{
		{"upgrade from own origin", http.MethodGet, upgradeOriginHeaders(self), http.StatusNoContent},
		{"upgrade from another origin", http.MethodGet, upgradeOriginHeaders(other), http.StatusForbidden},
		{"upgrade with another port", http.MethodGet, upgradeOriginHeaders(self + ":8443"), http.StatusForbidden},
		{"upgrade from plain http", http.MethodGet, upgradeOriginHeaders("http://app.example"), http.StatusForbidden},
		{"upgrade from opaque origin", http.MethodGet, upgradeOriginHeaders("null"), http.StatusForbidden},
		{"upgrade without origin", http.MethodGet, http.Header{"Connection": {"Upgrade"}, "Upgrade": {"websocket"}}, http.StatusNoContent},
		{"post from own origin", http.MethodPost, buildOriginHeader(self), http.StatusNoContent},
		{"post from another origin", http.MethodPost, buildOriginHeader(other), http.StatusForbidden},
		{"post from opaque origin", http.MethodPost, buildOriginHeader("null"), http.StatusForbidden},
		{"post without origin", http.MethodPost, http.Header{}, http.StatusNoContent},
		{"form post from a no-referrer page of the own origin", http.MethodPost, fetchSiteOriginHeaders("null", "same-origin"), http.StatusNoContent},
		{"form post from a no-referrer page elsewhere", http.MethodPost, fetchSiteOriginHeaders("null", "cross-site"), http.StatusForbidden},
		{"same-origin mark on a real origin", http.MethodPost, fetchSiteOriginHeaders(other, "same-origin"), http.StatusForbidden},
		{"same-origin mark on an upgrade", http.MethodGet, http.Header{"Upgrade": {"websocket"}, "Origin": {"null"}, "Sec-Fetch-Site": {"same-origin"}}, http.StatusForbidden},
		{"post from a sibling host", http.MethodPost, fetchSiteOriginHeaders(other, "same-site"), http.StatusForbidden},
		{"post from a sandboxed frame", http.MethodPost, fetchSiteOriginHeaders("null", "same-site"), http.StatusForbidden},
		{"put from another origin", http.MethodPut, buildOriginHeader(other), http.StatusForbidden},
		{"patch from another origin", http.MethodPatch, buildOriginHeader(other), http.StatusForbidden},
		{"delete from another origin", http.MethodDelete, buildOriginHeader(other), http.StatusForbidden},
		{"get from another origin", http.MethodGet, buildOriginHeader(other), http.StatusNoContent},
		{"head from another origin", http.MethodHead, buildOriginHeader(other), http.StatusNoContent},
		{"options from another origin", http.MethodOptions, buildOriginHeader(other), http.StatusNoContent},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "https://app.example/private", nil)
			req.Header = tt.headers.Clone()
			req.AddCookie(session)
			before := *upstream
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d; want %d", rec.Code, tt.wantStatus)
			}
			if reached := *upstream > before; reached != (tt.wantStatus == http.StatusNoContent) {
				t.Fatalf("upstream reached = %v with status %d", reached, rec.Code)
			}
		})
	}
}

func TestGateAnswersOnlyForHostsItHolds(t *testing.T) {
	t.Parallel()

	const canonical, alias = "app.example", "alias.example"
	now := time.Now().UTC()
	hostsWithAlias := []PublicHost{{URL: "https://" + canonical}, {URL: "https://" + alias, Since: now.Add(-time.Hour)}}
	var hosts atomic.Value
	hosts.Store(hostsWithAlias)
	tunnelIdentity := applicationAuthTestIdentity()
	handler, err := New(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), tunnelIdentity, Config{Provider: ProviderCredential, PublicHosts: func() []PublicHost { return hosts.Load().([]PublicHost) }})
	if err != nil {
		t.Fatal(err)
	}
	gate := handler.(*applicationAuth)
	checkHeldGateSessions(t, gate, now, hostsWithAlias)
	checkLostAliasRefused(t, gate, &hosts, hostsWithAlias, now)
}

func issueGateSessionSend(t *testing.T, gate *applicationAuth, host string, issuedAt, expires time.Time) func(*http.Request) {
	t.Helper()
	value, err := gate.issueSession(Principal{Provider: ProviderCredential, Subject: "alice"}, host, issuedAt, expires)
	if err != nil {
		t.Fatal(err)
	}
	return func(r *http.Request) { r.AddCookie(&http.Cookie{Name: applicationAuthCookieName, Value: value}) }
}

func serveGateRequest(gate *applicationAuth, host, path string, send func(*http.Request)) int {
	req := httptest.NewRequest(http.MethodGet, "https://"+host+path, nil)
	send(req)
	rec := httptest.NewRecorder()
	gate.ServeHTTP(rec, req)
	return rec.Code
}

func issueAliasCredential(t *testing.T, tunnelIdentity types.Identity, alias string, now time.Time) string {
	t.Helper()
	credential, err := IssueCredential(tunnelIdentity, alias, "alice", now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return credential
}

func presentGateCredential(credential string) func(*http.Request) {
	return func(r *http.Request) { r.Header.Set(types.HeaderAccessCredential, credential) }
}

func checkHeldGateSessions(t *testing.T, gate *applicationAuth, now time.Time, hostsWithAlias []PublicHost) {
	t.Helper()
	const canonical, alias = "app.example", "alias.example"
	credential := issueAliasCredential(t, applicationAuthTestIdentity(), alias, now)
	presentCredential := presentGateCredential(credential)
	longAgo := now.Add(-23 * time.Hour)
	held := hostsWithAlias[1].Since
	for _, tt := range []struct {
		name string
		host string
		send func(*http.Request)
		want int
	}{
		{"a session from this hold of the alias", alias, issueGateSessionSend(t, gate, alias, now, now.Add(time.Hour)), http.StatusNoContent},
		{"a session from the start of this hold", alias, issueGateSessionSend(t, gate, alias, held, now.Add(time.Hour)), http.StatusNoContent},
		{"a session from just before this hold", alias, issueGateSessionSend(t, gate, alias, held.Add(-time.Millisecond), now.Add(time.Hour)), http.StatusSeeOther},
		{"a session from an earlier hold of the alias", alias, issueGateSessionSend(t, gate, alias, longAgo, now.Add(time.Hour)), http.StatusSeeOther},
		{"a session too old to carry its date", alias, issueGateSessionSend(t, gate, alias, time.Unix(0, 0), now.Add(time.Hour)), http.StatusSeeOther},
		{"an old session on a host that cannot change hands", canonical, issueGateSessionSend(t, gate, canonical, longAgo, now.Add(time.Hour)), http.StatusNoContent},
		{"a credential for the alias", alias, presentCredential, http.StatusNoContent},
		{"a host the application never held", "attacker.example", issueGateSessionSend(t, gate, "attacker.example", now, now.Add(time.Hour)), http.StatusMisdirectedRequest},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := serveGateRequest(gate, tt.host, "/private", tt.send); got != tt.want {
				t.Fatalf("status = %d; want %d", got, tt.want)
			}
		})
	}
}

func checkLostAliasRefused(t *testing.T, gate *applicationAuth, hosts *atomic.Value, hostsWithAlias []PublicHost, now time.Time) {
	t.Helper()
	const canonical, alias = "app.example", "alias.example"
	hosts.Store(hostsWithAlias[:1])
	credential := issueAliasCredential(t, applicationAuthTestIdentity(), alias, now)
	for name, send := range map[string]func(*http.Request){
		"session":    issueGateSessionSend(t, gate, alias, now, now.Add(time.Hour)),
		"credential": presentGateCredential(credential),
	} {
		if got := serveGateRequest(gate, alias, "/private", send); got != http.StatusMisdirectedRequest {
			t.Fatalf("%s on a lost alias = %d; want 421", name, got)
		}
	}
	if got := serveGateRequest(gate, alias, types.PathApplicationAuthLogin, func(*http.Request) {}); got != http.StatusMisdirectedRequest {
		t.Fatalf("login page on a lost alias = %d; want 421", got)
	}
	if got := serveGateRequest(gate, canonical, "/private", issueGateSessionSend(t, gate, canonical, now, now.Add(time.Hour))); got != http.StatusNoContent {
		t.Fatalf("losing the alias touched the canonical host: %d", got)
	}
}
