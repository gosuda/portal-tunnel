package e2e_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/tunnel"
	"github.com/gosuda/portal-tunnel/v2/portal"
	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/sdk"
	"github.com/gosuda/portal-tunnel/v2/sdk/appauth"
	"github.com/gosuda/portal-tunnel/v2/types"
)

type stubOIDCProvider struct {
	*httptest.Server
	key *rsa.PrivateKey

	mu        sync.Mutex
	nonce     string
	challenge string
}

func startStubOIDCProvider(t *testing.T) *stubOIDCProvider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &stubOIDCProvider{key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 p.URL,
			"authorization_endpoint": p.URL + "/authorize",
			"token_endpoint":         p.URL + "/token",
			"jwks_uri":               p.URL + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "stub", Algorithm: "RS256", Use: "sig"}}})
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		p.mu.Lock()
		p.nonce, p.challenge = query.Get("nonce"), query.Get("code_challenge")
		p.mu.Unlock()
		back, err := url.Parse(query.Get("redirect_uri"))
		if err != nil {
			http.Error(w, "bad redirect_uri", http.StatusBadRequest)
			return
		}
		back.RawQuery = url.Values{"code": {"stub-code"}, "state": {query.Get("state")}}.Encode()
		http.Redirect(w, r, back.String(), http.StatusFound)
	})
	mux.HandleFunc("/token", p.serveToken(t))
	p.Server = httptest.NewServer(mux)
	t.Cleanup(p.Close)
	return p
}

func (p *stubOIDCProvider) serveToken(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		p.mu.Lock()
		nonce, challenge := p.nonce, p.challenge
		p.mu.Unlock()
		verifier := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		if base64.RawURLEncoding.EncodeToString(verifier[:]) != challenge {
			http.Error(w, "pkce mismatch", http.StatusBadRequest)
			return
		}
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: p.key, KeyID: "stub"}}, nil)
		if err != nil {
			t.Error(err)
			return
		}
		now := time.Now()
		token, err := jwt.Signed(signer).Claims(jwt.Claims{
			Issuer:   p.URL,
			Subject:  "user-123",
			Audience: jwt.Audience{"embedder"},
			IssuedAt: jwt.NewNumericDate(now),
			Expiry:   jwt.NewNumericDate(now.Add(time.Hour)),
		}).Claims(map[string]any{"nonce": nonce, "email": "alice@example.com", "email_verified": true}).Serialize()
		if err != nil {
			t.Error(err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "stub", "token_type": "Bearer", "id_token": token})
	}
}

type swappableHandler struct{ current atomic.Value }

func (h *swappableHandler) set(handler http.Handler) { h.current.Store(&handler) }

func (h *swappableHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	(*h.current.Load().(*http.Handler)).ServeHTTP(w, r)
}

func TestEmbeddedApplicationAuth(t *testing.T) {
	provider := startStubOIDCProvider(t)
	reachedWithoutSession := make(chan string, 8)

	app := http.NewServeMux()
	app.HandleFunc("/whoami", func(w http.ResponseWriter, r *http.Request) {
		principal, ok := appauth.PrincipalFromContext(r.Context())
		if !ok {
			reachedWithoutSession <- r.URL.Path
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"provider": principal.Provider,
			"subject":  principal.Subject,
			"email":    principal.Email,
			"header":   r.Header.Get(types.HeaderPortalUser),
			"proof":    r.Header.Get(types.HeaderPortalProof),
		})
	})
	app.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		principal, ok := appauth.PrincipalFromContext(r.Context())
		if !ok {
			reachedWithoutSession <- r.URL.Path
		}
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			t.Errorf("accept: %v", err)
			return
		}
		defer func() { _ = conn.CloseNow() }()
		_ = conn.Write(r.Context(), websocket.MessageText, []byte(principal.Email))
		_, _, _ = conn.Read(r.Context())
	})

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	port := harnessPort(t, "localhost")
	sniAddr := net.JoinHostPort("localhost", strconv.Itoa(port))
	relay, err := portal.NewServer(portal.ServerConfig{
		PortalURL:     "https://" + sniAddr,
		StateDir:      t.TempDir(),
		SNIListenAddr: sniAddr,
		SNIPort:       port,
	})
	if err != nil {
		t.Fatalf("create relay: %v", err)
	}
	if err := relay.Start(ctx, relayHandler(relay, nil)); err != nil {
		t.Fatalf("start relay: %v", err)
	}
	t.Cleanup(func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		_ = relay.Shutdown(shutdownCtx)
		_ = relay.Wait()
	})

	id, err := identity.Generate("embed")
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	cfg := appauth.Config{
		Provider:   appauth.ProviderOIDC,
		EmailList:  []string{"sub:user-123"},
		OIDCConfig: appauth.OIDCConfig{OIDCIssuerURL: provider.URL, OIDCClientID: "embedder"},
	}
	if err := appauth.Check(ctx, cfg); err != nil {
		t.Fatalf("check provider: %v", err)
	}
	gate, err := appauth.New(app, id, cfg)
	if err != nil {
		t.Fatalf("build gate: %v", err)
	}
	front := &swappableHandler{}
	front.set(gate)

	exposure, err := sdk.Expose(ctx, id, []string{"https://" + sniAddr})
	if err != nil {
		t.Fatalf("expose: %v", err)
	}
	runDone := make(chan error, 1)
	go func() { runDone <- sdk.RunHTTP(ctx, exposure, front, "") }()
	t.Cleanup(func() {
		_ = exposure.Close()
		cancel()
		select {
		case err := <-runDone:
			if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, net.ErrClosed) {
				t.Errorf("run: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Error("RunHTTP did not stop")
		}
	})
	waitCtx, waitCancel := context.WithTimeout(ctx, 60*time.Second)
	defer waitCancel()
	ready, err := exposure.WaitReady(waitCtx)
	if err != nil {
		t.Fatalf("wait for lease: %v", err)
	}
	if len(ready) != 1 || ready[0].PublicURL == "" {
		t.Fatalf("relay status = %+v, want one public URL", ready)
	}
	publicURL := strings.TrimSuffix(ready[0].PublicURL, "/")
	public, err := url.Parse(publicURL)
	if err != nil {
		t.Fatal(err)
	}

	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr == strings.TrimPrefix(provider.URL, "http://") {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		}
		return (&net.Dialer{}).DialContext(ctx, network, sniAddr)
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: 20 * time.Second, Jar: jar, Transport: &http.Transport{
		DisableKeepAlives: true,
		DialContext:       dial,
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true, ServerName: public.Hostname(), MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}},
	}}
	noRedirect := *client
	noRedirect.Jar = nil
	noRedirect.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	get := func(c *http.Client, path string, header http.Header) (int, string) {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, publicURL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		for name, values := range header {
			req.Header[name] = values
		}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		defer func() { _ = resp.Body.Close() }()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode, string(body)
	}
	dialSocket := func(cookie string) (*websocket.Conn, *http.Response, error) {
		t.Helper()
		header := http.Header{"Origin": {"https://" + public.Host}}
		if cookie != "" {
			header.Set("Cookie", cookie)
		}
		return websocket.Dial(ctx, "wss://"+public.Host+"/ws", &websocket.DialOptions{HTTPClient: &noRedirect, HTTPHeader: header})
	}

	spoofed := http.Header{
		types.HeaderPortalUser: {"mallory"},
		types.HeaderPortalAuth: {"oidc"},
		"X_Portal_User":        {"mallory"},
		"X_portal_auth":        {"oidc"},
	}
	if code, _ := get(&noRedirect, "/whoami", spoofed); code != http.StatusSeeOther {
		t.Fatalf("no session: status = %d, want %d", code, http.StatusSeeOther)
	}
	if conn, resp, err := dialSocket(""); err == nil {
		_ = conn.CloseNow()
		t.Fatal("a WebSocket without a session was accepted")
	} else if resp == nil || resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("no session: WebSocket answer %+v, error %v", resp, err)
	}

	code, body := get(client, "/whoami", spoofed)
	if code != http.StatusOK {
		t.Fatalf("after sign-in: status = %d, body %s", code, body)
	}
	var seen map[string]string
	if err := json.Unmarshal([]byte(body), &seen); err != nil {
		t.Fatalf("whoami body %q: %v", body, err)
	}
	if seen["provider"] != appauth.ProviderOIDC || seen["subject"] != "sub:user-123" || seen["email"] != "alice@example.com" {
		t.Fatalf("principal = %v", seen)
	}
	if seen["header"] != "" {
		t.Fatalf("a spoofed %s reached the program: %v", types.HeaderPortalUser, seen)
	}

	sessionURL := &url.URL{Scheme: "https", Host: public.Host, Path: "/"}
	var cookie string
	for _, c := range jar.Cookies(sessionURL) {
		if strings.HasPrefix(c.Name, "__Host-portal_access") {
			cookie = c.Name + "=" + c.Value
		}
	}
	if cookie == "" {
		t.Fatal("the browser holds no session")
	}
	conn, _, err := dialSocket(cookie)
	if err != nil {
		t.Fatalf("WebSocket with a session: %v", err)
	}
	if _, message, err := conn.Read(ctx); err != nil || string(message) != "alice@example.com" {
		t.Fatalf("WebSocket message = %q, error %v", message, err)
	}
	_ = conn.CloseNow()

	rebuilt, err := appauth.New(app, id, cfg)
	if err != nil {
		t.Fatalf("rebuild gate: %v", err)
	}
	front.set(rebuilt)
	if code, _ := get(&noRedirect, "/whoami", http.Header{"Cookie": {cookie}}); code != http.StatusOK {
		t.Fatalf("after a rebuild: status = %d, want %d", code, http.StatusOK)
	}

	select {
	case path := <-reachedWithoutSession:
		t.Fatalf("%s was reached without a principal", path)
	default:
	}
}
func TestSessionsFollowTheHostsATunnelHolds(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	port := harnessPort(t, "localhost")
	sniAddr := net.JoinHostPort("localhost", strconv.Itoa(port))
	relay, err := portal.NewServer(portal.ServerConfig{PortalURL: "https://" + sniAddr, StateDir: t.TempDir(), SNIListenAddr: sniAddr, SNIPort: port})
	if err != nil {
		t.Fatalf("create relay: %v", err)
	}
	if err := relay.Start(ctx, relayHandler(relay, nil)); err != nil {
		t.Fatalf("start relay: %v", err)
	}
	t.Cleanup(func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		_ = relay.Shutdown(shutdownCtx)
		_ = relay.Wait()
	})

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	t.Cleanup(upstream.Close)
	identityPath := filepath.Join(t.TempDir(), "identity.json")
	var id types.Identity
	start := func() (status sdk.RelayStatus, stop func()) {
		t.Helper()
		runtime, err := tunnel.Start(ctx, tunnel.Spec{
			Identity:  tunnel.IdentitySpec{Name: "held", Path: identityPath},
			Relays:    tunnel.RelaySpec{URLs: []string{"https://" + sniAddr}},
			Transport: tunnel.TransportSpec{Target: strings.TrimPrefix(upstream.URL, "http://")},
			HTTP:      &tunnel.HTTPConfig{Auth: &appauth.Config{Provider: appauth.ProviderCredential}},
		})
		if err != nil {
			t.Fatal(err)
		}
		id = runtime.Identity
		runDone := make(chan error, 1)
		go func() { runDone <- runtime.Run(ctx) }()
		waitCtx, waitCancel := context.WithTimeout(ctx, 60*time.Second)
		defer waitCancel()
		ready, err := runtime.Exposure.WaitReady(waitCtx)
		if err != nil {
			t.Fatal(err)
		}
		if len(ready) != 1 || ready[0].PublicURL == "" || ready[0].AliasURL == "" {
			t.Fatalf("relay status = %+v, want a public URL and an alias", ready)
		}
		return ready[0], func() {
			t.Helper()
			_ = runtime.Close()
			select {
			case err := <-runDone:
				if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, net.ErrClosed) {
					t.Errorf("run: %v", err)
				}
			case <-time.After(10 * time.Second):
				t.Error("the tunnel did not stop")
			}
		}
	}

	client := &http.Client{
		Timeout:       20 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{
			DisableKeepAlives: true,
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, sniAddr)
			},
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}},
		},
	}
	send := func(req *http.Request) *http.Response {
		t.Helper()
		response, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		return response
	}
	signIn := func(publicURL string) *http.Cookie {
		t.Helper()
		parsed, err := url.Parse(publicURL)
		if err != nil {
			t.Fatal(err)
		}
		credential, err := appauth.IssueCredential(id, parsed.Host, "alice", time.Now().Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		body, err := json.Marshal(map[string]string{"credential": credential})
		if err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, publicURL+types.PathApplicationAuthRedeem, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Origin", "https://"+parsed.Host)
		response := send(req)
		if response.StatusCode != http.StatusOK || len(response.Cookies()) != 1 {
			t.Fatalf("sign-in at %s = %d, cookies %v", publicURL, response.StatusCode, response.Cookies())
		}
		return response.Cookies()[0]
	}
	open := func(publicURL string, session *http.Cookie, host string) int {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, publicURL+"/private", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = host
		req.AddCookie(session)
		return send(req).StatusCode
	}

	status, stop := start()
	canonicalSession, aliasSession := signIn(status.PublicURL), signIn(status.AliasURL)
	if code := open(status.PublicURL, canonicalSession, ""); code != http.StatusNoContent {
		t.Fatalf("canonical session = %d; want 204", code)
	}
	if code := open(status.AliasURL, aliasSession, ""); code != http.StatusNoContent {
		t.Fatalf("alias session = %d; want 204", code)
	}
	if code := open(status.PublicURL, canonicalSession, "elsewhere.localhost:"+strconv.Itoa(port)); code != http.StatusMisdirectedRequest {
		t.Fatalf("a host the tunnel does not hold = %d; want 421", code)
	}

	stop()
	restarted, stop := start()
	t.Cleanup(stop)
	if code := open(restarted.PublicURL, canonicalSession, ""); code != http.StatusNoContent {
		t.Fatalf("canonical session after a restart = %d; want 204", code)
	}
	if code := open(restarted.AliasURL, aliasSession, ""); code != http.StatusSeeOther {
		t.Fatalf("alias session after a restart = %d; want the login redirect", code)
	}
	if code := open(restarted.AliasURL, signIn(restarted.AliasURL), ""); code != http.StatusNoContent {
		t.Fatalf("new alias session = %d; want 204", code)
	}
}
