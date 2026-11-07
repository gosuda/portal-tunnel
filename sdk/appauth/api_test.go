package appauth_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/gosuda/portal-tunnel/v2/sdk/appauth"
	"github.com/gosuda/portal-tunnel/v2/types"
)

const sessionCookie = "__Host-portal_access"

func testIdentity(secret string) types.Identity {
	return types.Identity{Name: "embedder", Address: "0x0000000000000000000000000000000000000001", TokenSecret: strings.Repeat(secret, 32)}
}

// gatedServer serves next behind a gate on a TLS listener, the way a browser
// reaches it: over HTTPS, under the host the session is bound to.
type gatedServer struct {
	*httptest.Server
	host   string
	client *http.Client
}

func startGate(t *testing.T, cfg appauth.Config, next http.Handler) *gatedServer {
	t.Helper()
	handler, err := appauth.New(next, testIdentity("k"), cfg)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	client := server.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &gatedServer{Server: server, host: server.Listener.Addr().String(), client: client}
}

// signIn redeems a credential and returns the session cookie.
func (s *gatedServer) signIn(t *testing.T, subject string) *http.Cookie {
	t.Helper()
	credential, err := appauth.IssueCredential(testIdentity("k"), s.host, subject, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{"credential": credential})
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, s.URL+appauth.ReservedPathPrefix+"redeem", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Origin", "https://"+s.host)
	resp, err := s.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	for _, cookie := range resp.Cookies() {
		if cookie.Name == sessionCookie {
			return cookie
		}
	}
	t.Fatalf("redeem answered %d with no session", resp.StatusCode)
	return nil
}

func (s *gatedServer) status(t *testing.T, method, path string, cookie *http.Cookie) int {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, s.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode
}

func (s *gatedServer) dial(t *testing.T, origin string, cookie *http.Cookie) (*websocket.Conn, *http.Response, error) {
	t.Helper()
	header := http.Header{"Origin": {origin}}
	if cookie != nil {
		header.Set("Cookie", cookie.Name+"="+cookie.Value)
	}
	return websocket.Dial(t.Context(), "wss://"+s.host+"/ws", &websocket.DialOptions{HTTPClient: s.client, HTTPHeader: header})
}

func failOnReach(t *testing.T) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("the application was reached")
	})
}

func TestRequestWithoutSessionNeverReachesTheApplication(t *testing.T) {
	t.Parallel()

	server := startGate(t, appauth.Config{Provider: appauth.ProviderCredential}, failOnReach(t))
	if got := server.status(t, http.MethodGet, "/private", nil); got != http.StatusSeeOther {
		t.Errorf("GET status = %d; want %d", got, http.StatusSeeOther)
	}
	if got := server.status(t, http.MethodPost, "/private", nil); got != http.StatusUnauthorized {
		t.Errorf("POST status = %d; want %d", got, http.StatusUnauthorized)
	}
	conn, resp, err := server.dial(t, "https://"+server.host, nil)
	if err == nil {
		_ = conn.CloseNow()
		t.Fatal("a WebSocket without a session was accepted")
	}
	if resp == nil || resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("WebSocket answer = %+v, error %v; want %d", resp, err, http.StatusSeeOther)
	}
}

// An embedder's handler takes over the connection for a WebSocket, so the gate
// must hand it the original ResponseWriter, not a wrapper without Hijack.
func TestWebSocketWithSessionReachesTheApplication(t *testing.T) {
	t.Parallel()

	server := startGate(t, appauth.Config{Provider: appauth.ProviderCredential}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, _ := appauth.PrincipalFromContext(r.Context())
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			t.Errorf("accept: %v", err)
			return
		}
		defer func() { _ = conn.CloseNow() }()
		_ = conn.Write(r.Context(), websocket.MessageText, []byte(principal.Subject))
		_, _, _ = conn.Read(r.Context())
	}))
	conn, _, err := server.dial(t, "https://"+server.host, server.signIn(t, "alice"))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.CloseNow() }()
	_, message, err := conn.Read(t.Context())
	if err != nil || string(message) != "alice" {
		t.Fatalf("message = %q, error %v; want alice", message, err)
	}
}

func TestWebSocketFromAnotherOriginNeverReachesTheApplication(t *testing.T) {
	t.Parallel()

	server := startGate(t, appauth.Config{Provider: appauth.ProviderCredential}, failOnReach(t))
	conn, resp, err := server.dial(t, "https://other.example", server.signIn(t, "alice"))
	if err == nil {
		_ = conn.CloseNow()
		t.Fatal("a WebSocket from another origin was accepted")
	}
	if resp == nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("answer = %+v, error %v; want %d", resp, err, http.StatusForbidden)
	}
}

func TestPrincipalReachesTheApplicationWithoutIdentityHeaders(t *testing.T) {
	t.Parallel()

	got := make(chan appauth.Principal, 1)
	var user string
	server := startGate(t, appauth.Config{Provider: appauth.ProviderCredential}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, ok := appauth.PrincipalFromContext(r.Context())
		if !ok {
			t.Error("no principal behind the gate")
		}
		user = r.Header.Get(types.HeaderPortalUser)
		got <- principal
		w.WriteHeader(http.StatusNoContent)
	}))
	if code := server.status(t, http.MethodGet, "/private", server.signIn(t, "alice")); code != http.StatusNoContent {
		t.Fatalf("status = %d", code)
	}
	want := appauth.Principal{Provider: appauth.ProviderCredential, Subject: "alice"}
	if principal := <-got; principal != want {
		t.Fatalf("principal = %+v; want %+v", principal, want)
	}
	if user != "" {
		t.Fatalf("%s = %q without IdentityHeaders", types.HeaderPortalUser, user)
	}
}

func TestNoPrincipalWithoutAGate(t *testing.T) {
	t.Parallel()

	if principal, ok := appauth.PrincipalFromContext(context.Background()); ok {
		t.Fatalf("principal = %+v without a gate", principal)
	}
}

// An embedder swaps its application during a redeploy. A gate built again from
// the same identity and settings must accept the sessions of the last one, and
// must still apply its own allowlist to them.
func TestRebuiltGateKeepsItsSessionsAndChecksItsAllowlist(t *testing.T) {
	t.Parallel()

	first := startGate(t, appauth.Config{Provider: appauth.ProviderCredential}, failOnReach(t))
	session := first.signIn(t, "alice")
	rebuilt := func(id types.Identity, allow ...string) int {
		handler, err := appauth.New(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}), id, appauth.Config{Provider: appauth.ProviderCredential, Allow: allow})
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodGet, "https://"+first.host+"/private", nil)
		req.AddCookie(session)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Code
	}
	if got := rebuilt(testIdentity("k")); got != http.StatusNoContent {
		t.Errorf("same identity: status = %d; want %d", got, http.StatusNoContent)
	}
	if got := rebuilt(testIdentity("k"), "alice"); got != http.StatusNoContent {
		t.Errorf("subject still listed: status = %d; want %d", got, http.StatusNoContent)
	}
	if got := rebuilt(testIdentity("k"), "bob"); got != http.StatusSeeOther {
		t.Errorf("subject no longer listed: status = %d; want %d", got, http.StatusSeeOther)
	}
	if got := rebuilt(testIdentity("x")); got != http.StatusSeeOther {
		t.Errorf("another token secret: status = %d; want %d", got, http.StatusSeeOther)
	}
}

// json.Marshal drops the token secret of an identity. A random secret would end
// every session at each start without a word, so a gate refuses to run without.
func TestGateRefusesAnIdentityWithoutItsTokenSecret(t *testing.T) {
	t.Parallel()

	id := testIdentity("k")
	id.TokenSecret = ""
	if _, err := appauth.New(http.NotFoundHandler(), id, appauth.Config{Provider: appauth.ProviderCredential}); err == nil {
		t.Fatal("New accepted an identity without a token secret")
	}
}

// oidcWithIssuer is a complete OIDC config, so a test of the issuer fails for the
// issuer alone.
func oidcWithIssuer(issuer string) appauth.Config {
	return appauth.Config{
		Provider:   appauth.ProviderOIDC,
		EmailList:  []string{"alice@example.com"},
		OIDCConfig: appauth.OIDCConfig{OIDCIssuerURL: issuer, OIDCClientID: "client"},
	}
}

func TestNewReportsAMistakeInTheConfig(t *testing.T) {
	t.Parallel()

	noList := oidcWithIssuer("https://idp.example")
	noList.EmailList = nil
	for name, cfg := range map[string]appauth.Config{
		"unknown provider":  {Provider: "kerberos"},
		"no provider":       {},
		"empty allowlist":   noList,
		"malformed issuer":  oidcWithIssuer("https://idp.example/?q=1"),
		"cleartext issuer":  oidcWithIssuer("http://idp.example"),
		"list of the wrong": {Provider: appauth.ProviderSIWE, EmailList: []string{"alice@example.com"}},
	} {
		if _, err := appauth.New(http.NotFoundHandler(), testIdentity("k"), cfg); err == nil {
			t.Errorf("%s: New accepted the config", name)
		}
		if err := appauth.Validate(cfg); err == nil {
			t.Errorf("%s: Validate accepted the config", name)
		}
	}
}

// New must not read the network: a rebuild during a provider outage would fail
// although every session it has to serve needs no provider. Check reports the
// outage instead.
func TestProviderOutageFailsCheckButNotNew(t *testing.T) {
	t.Parallel()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	issuer := "http://" + listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	cfg := oidcWithIssuer(issuer)
	if _, err := appauth.New(http.NotFoundHandler(), testIdentity("k"), cfg); err != nil {
		t.Fatalf("New during an outage: %v", err)
	}
	if err := appauth.Check(t.Context(), cfg); err == nil {
		t.Fatal("Check passed although the provider cannot be reached")
	}
}

// A secret enters a gate as a value, so it must not leave one in a status or an
// error an embedder is likely to show.
func TestSecretsStayOutOfStatusAndErrors(t *testing.T) {
	t.Parallel()

	const proof, clientSecret, smtpPassword = "identity-proof-secret-value", "oidc-client-secret-value", "smtp-password-secret-value"
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gone := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	oidc := oidcWithIssuer("http://" + gone)
	oidc.OIDCClientSecret, oidc.IdentityHeaders, oidc.IdentityProof = clientSecret, true, proof
	email := appauth.Config{
		Provider:    appauth.ProviderEmail,
		EmailList:   []string{"alice@example.com"},
		EmailConfig: appauth.EmailConfig{SMTPAddr: gone, SMTPUsername: "portal", SMTPPassword: smtpPassword, SMTPFrom: "login@example.com"},
	}
	badProof := oidc
	badProof.IdentityHeaders = false

	var seen strings.Builder
	for _, cfg := range []appauth.Config{oidc, email} {
		status, err := json.Marshal(cfg.Public())
		if err != nil {
			t.Fatal(err)
		}
		seen.Write(status)
		seen.WriteString(errorText(appauth.Check(t.Context(), cfg)))
	}
	seen.WriteString(errorText(appauth.Validate(badProof)))
	_, err = appauth.New(http.NotFoundHandler(), testIdentity("k"), badProof)
	seen.WriteString(errorText(err))
	for _, secret := range []string{proof, clientSecret, smtpPassword} {
		if strings.Contains(seen.String(), secret) {
			t.Fatalf("a secret left the gate: %s", seen.String())
		}
	}
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func TestReservedPathsNeverReachTheApplication(t *testing.T) {
	t.Parallel()

	server := startGate(t, appauth.Config{Provider: appauth.ProviderCredential}, failOnReach(t))
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+appauth.ReservedPathPrefix+"login", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := server.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil && !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "Sign in to continue") {
		t.Fatalf("status = %d, body %.80q; want the sign-in page", resp.StatusCode, body)
	}
}
