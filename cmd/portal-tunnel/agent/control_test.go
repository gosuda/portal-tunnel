package agent

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/sdk/appauth"
	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestControlHandlerRejectsUntrustedHostAndOrigin(t *testing.T) {
	handler := &controlHandler{
		authority:          "127.0.0.1:4018",
		localhostAuthority: "localhost:4018",
	}
	tests := []struct {
		name    string
		host    string
		origins []string
		want    int
	}{
		{name: "bound host without origin", host: "127.0.0.1:4018", want: http.StatusOK},
		{name: "bound host and origin", host: "127.0.0.1:4018", origins: []string{"http://127.0.0.1:4018"}, want: http.StatusOK},
		{name: "localhost alias", host: "localhost:4018", origins: []string{"http://localhost:4018"}, want: http.StatusOK},
		{name: "attacker host", host: "attack.example:4018", want: http.StatusForbidden},
		{name: "attacker host and origin", host: "attack.example:4018", origins: []string{"http://attack.example:4018"}, want: http.StatusForbidden},
		{name: "other loopback port", host: "127.0.0.1:4019", want: http.StatusForbidden},
		{name: "other loopback address", host: "127.0.0.2:4018", want: http.StatusForbidden},
		{name: "other origin", host: "127.0.0.1:4018", origins: []string{"http://attack.example"}, want: http.StatusForbidden},
		{name: "other scheme", host: "127.0.0.1:4018", origins: []string{"https://127.0.0.1:4018"}, want: http.StatusForbidden},
		{name: "null origin", host: "127.0.0.1:4018", origins: []string{"null"}, want: http.StatusForbidden},
		{name: "multiple origins", host: "127.0.0.1:4018", origins: []string{"http://127.0.0.1:4018", "http://attack.example"}, want: http.StatusForbidden},
		{name: "empty origin", host: "127.0.0.1:4018", origins: []string{""}, want: http.StatusForbidden},
		{name: "empty host", host: "", want: http.StatusForbidden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, types.PathAgentAuthStatus, nil)
			req.Host = tt.host
			for _, origin := range tt.origins {
				req.Header.Add("Origin", origin)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d; body = %s", rec.Code, tt.want, rec.Body.String())
			}
		})
	}
}

func TestControlHandlerRejectsUntrustedHostBeforeAuthorization(t *testing.T) {
	handler := &controlHandler{
		token:              "secret",
		authority:          "127.0.0.1:4018",
		localhostAuthority: "localhost:4018",
	}
	for _, endpoint := range []struct {
		path   string
		method string
	}{
		{types.PathAgentAuthChallenge, http.MethodPost},
		{types.PathAgentAuthLogin, http.MethodPost},
		{types.PathAgentAuthLogout, http.MethodPost},
		{types.PathAgentAuthStatus, http.MethodGet},
		{types.PathAgentShutdown, http.MethodPost},
	} {
		t.Run(endpoint.path, func(t *testing.T) {
			req := httptest.NewRequest(endpoint.method, endpoint.path, nil)
			req.Host = "attack.example:4018"
			req.Header.Set("Authorization", "Bearer secret")
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want forbidden", rec.Code)
			}
		})
	}
}

// A wallet session is read-only, and any wallet may sign in while the dashboard
// has no wallet allowlist, so it must not learn who may sign in to a tunnel or
// which mail account sends its links. The control token still sees them.
func TestWalletSessionDoesNotSeeTunnelAllowlists(t *testing.T) {
	tunnelCfg := testTunnel("web")
	tunnelCfg.Provider = "credential"
	tunnelCfg.AllowedWallets = []string{"alice", "bob"}
	mailCfg := testTunnel("mail")
	mailCfg.Provider = appauth.ApplicationAuthProviderEmail
	mailCfg.EmailList = []string{"carol@example.com"}
	mailCfg.EmailConfig = appauth.EmailConfig{SMTPAddr: "smtp.example.com:587", SMTPUsername: "me@example.com", SMTPPassword: "not-a-real-secret-0123", SMTPFrom: "login@example.com"}
	m, _ := testManager(t, tunnelCfg, mailCfg)

	auth, err := newWalletAuthenticator(walletAuthConfig{AllowAnyAddress: true})
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := identity.ResolveSecp256k1Identity(strings.Repeat("0", 63) + "3")
	if err != nil {
		t.Fatal(err)
	}
	wallet := identity.NewLocalAuthority(resolved)
	const domain = "127.0.0.1:4018"
	now := time.Now().UTC()
	challenge, err := auth.issueChallenge(
		types.WalletAuthChallengeRequest{Address: wallet.Identity().Address},
		domain, "http://"+domain+types.PathAgentAuthLogin, now,
	)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := wallet.SignEthereumPersonalMessage(challenge.SIWEMessage)
	if err != nil {
		t.Fatal(err)
	}
	session, _, err := auth.login(types.WalletAuthLoginRequest{
		ChallengeID:   challenge.ChallengeID,
		SIWEMessage:   challenge.SIWEMessage,
		SIWESignature: signature,
	}, domain, now)
	if err != nil {
		t.Fatal(err)
	}

	handler := &controlHandler{manager: m, token: "control-token", auth: auth, authority: domain, localhostAuthority: "localhost:4018"}
	statusAs := func(authorize func(*http.Request)) map[string]AgentTunnelStatus {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, types.PathAgentStatus, nil)
		req.Host = domain
		authorize(req)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
		}
		var body struct {
			Data AgentStatusResponse `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		tunnels := make(map[string]AgentTunnelStatus, len(body.Data.Tunnels))
		for _, tunnel := range body.Data.Tunnels {
			tunnels[tunnel.ID] = tunnel
		}
		return tunnels
	}

	token := statusAs(func(r *http.Request) { r.Header.Set("Authorization", "Bearer control-token") })
	if got := token["web"].AllowedWallets; !slices.Equal(got, []string{"alice", "bob"}) {
		t.Fatalf("control token sees allowlist %v, want [alice bob]", got)
	}
	if got := token["mail"]; !slices.Equal(got.EmailList, []string{"carol@example.com"}) || got.SMTPUsername != "me@example.com" || got.SMTPPassword != "" || !got.AuthSMTPPasswordSet {
		t.Fatalf("control token sees %+v, want the list and the account, not the password", got.ApplicationAuthConfig)
	}
	signedIn := statusAs(func(r *http.Request) { r.AddCookie(&http.Cookie{Name: agentCookieName, Value: session}) })
	if got := signedIn["web"].AllowedWallets; len(got) != 0 {
		t.Fatalf("wallet session sees allowlist %v, want none", got)
	}
	if got := signedIn["mail"]; len(got.EmailList) != 0 || got.EmailConfig != (appauth.EmailConfig{}) || got.AuthSMTPPasswordSet {
		t.Fatalf("wallet session sees %+v, want no list and no mail account", got.ApplicationAuthConfig)
	}
}
