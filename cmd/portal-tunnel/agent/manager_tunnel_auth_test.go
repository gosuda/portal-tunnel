package agent

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func TestUpdateTunnelAuthChangesOnlyWhatIsSent(t *testing.T) {
	const oldSecret, newSecret = "old-client-secret", "new-client-secret"
	m, path := testManager(t, oidcTunnel("app", unreachableIssuer, oldSecret))
	startManager(t, m)

	for _, step := range tunnelAuthUpdateSteps(oldSecret, newSecret) {
		t.Run(step.name, func(t *testing.T) {
			checkTunnelAuthUpdateStep(t, m, path, newSecret, step)
		})
	}
}

type tunnelAuthUpdateStep struct {
	name  string
	body  string
	check func(t *testing.T, saved TunnelConfig, status AgentTunnelStatus)
}

func tunnelAuthUpdateSteps(oldSecret, newSecret string) []tunnelAuthUpdateStep {
	return []tunnelAuthUpdateStep{
		{
			name: "metadata leaves sign-in alone",
			body: `{"metadata":{"description":"hello"}}`,
			check: func(t *testing.T, saved TunnelConfig, status AgentTunnelStatus) {
				checkAuthUpdateLeavesSignInAlone(t, saved, oldSecret)
			},
		},
		{
			name: "allowlist replaces only the allowlist",
			body: `{"auth_allowed_wallets":["Bob@Example.com","sub:42"]}`,
			check: func(t *testing.T, saved TunnelConfig, status AgentTunnelStatus) {
				checkAuthUpdateReplacesAllowlist(t, saved, status, oldSecret)
			},
		},
		{
			name: "null leaves a field as it is",
			body: `{"metadata":{"description":"again"},"auth_allowed_wallets":null,"auth_oidc_issuer":null}`,
			check: func(t *testing.T, saved TunnelConfig, status AgentTunnelStatus) {
				checkAuthUpdateNullKeepsField(t, saved)
			},
		},
		{
			name: "secret is replaced and never echoed",
			body: `{"auth_oidc_client_secret":"` + newSecret + `"}`,
			check: func(t *testing.T, saved TunnelConfig, status AgentTunnelStatus) {
				checkAuthUpdateReplacesSecret(t, saved, status, newSecret)
			},
		},
		{
			name: "empty secret clears it",
			body: `{"auth_oidc_client_secret":""}`,
			check: func(t *testing.T, saved TunnelConfig, status AgentTunnelStatus) {
				checkAuthUpdateClearsSecret(t, saved, status)
			},
		},
	}
}

func checkAuthUpdateLeavesSignInAlone(t *testing.T, saved TunnelConfig, oldSecret string) {
	t.Helper()
	if saved.Description != "hello" || saved.Provider != "oidc" || saved.OIDCClientSecret != oldSecret ||
		!slices.Equal(saved.Allow, []string{"alice@example.com"}) {
		t.Fatalf("saved = %+v", saved)
	}
}

func checkAuthUpdateReplacesAllowlist(t *testing.T, saved TunnelConfig, status AgentTunnelStatus, oldSecret string) {
	t.Helper()
	if !slices.Equal(saved.Allow, []string{"bob@example.com", "sub:42"}) ||
		!slices.Equal(status.Allow, saved.Allow) ||
		saved.OIDCIssuerURL != unreachableIssuer || saved.OIDCClientID != "client-123" || saved.OIDCClientSecret != oldSecret {
		t.Fatalf("saved = %+v, status allowlist = %v", saved, status.Allow)
	}
}

func checkAuthUpdateNullKeepsField(t *testing.T, saved TunnelConfig) {
	t.Helper()
	if !slices.Equal(saved.Allow, []string{"bob@example.com", "sub:42"}) || saved.OIDCIssuerURL != unreachableIssuer {
		t.Fatalf("saved = %+v", saved)
	}
}

func checkAuthUpdateReplacesSecret(t *testing.T, saved TunnelConfig, status AgentTunnelStatus, newSecret string) {
	t.Helper()
	if saved.OIDCClientSecret != newSecret || !status.AuthOIDCClientSecretSet {
		t.Fatalf("saved secret = %q, secret set = %v", saved.OIDCClientSecret, status.AuthOIDCClientSecretSet)
	}
	if data, _ := json.Marshal(status); strings.Contains(string(data), newSecret) {
		t.Fatalf("status exposes the client secret: %s", data)
	}
}

func checkAuthUpdateClearsSecret(t *testing.T, saved TunnelConfig, status AgentTunnelStatus) {
	t.Helper()
	if saved.OIDCClientSecret != "" || status.AuthOIDCClientSecretSet || saved.Provider != "oidc" {
		t.Fatalf("saved = %+v, secret set = %v", saved, status.AuthOIDCClientSecretSet)
	}
}

func checkTunnelAuthUpdateStep(t *testing.T, m *manager, path, newSecret string, step tunnelAuthUpdateStep) {
	t.Helper()
	code, body := callControl(t, m, http.MethodPatch, types.PathAgentTunnelsPrefix+"app", step.body)
	if code != http.StatusAccepted {
		t.Fatalf("status = %d, body = %s", code, body)
	}
	if strings.Contains(body, newSecret) {
		t.Fatalf("response echoes the client secret: %s", body)
	}
	step.check(t, savedTunnel(t, path, "app"), tunnelStatus(t, m, "app"))
}

func TestUpdateTunnelEmptyAuthTurnsSignInOff(t *testing.T) {
	cfg := oidcTunnel("app", unreachableIssuer, "client-secret")
	cfg.IdentityHeaders = true
	m, path := testManager(t, cfg)
	startManager(t, m)

	if code, body := callControl(t, m, http.MethodPatch, types.PathAgentTunnelsPrefix+"app", `{"auth":""}`); code != http.StatusAccepted {
		t.Fatalf("status = %d, body = %s", code, body)
	}
	saved := savedTunnel(t, path, "app")
	status := tunnelStatus(t, m, "app")
	if auth := saved.AuthConfig; !auth.IsZero() {
		t.Fatalf("saved auth = %+v", auth)
	}
	if data, _ := json.Marshal(status); strings.Contains(string(data), `"auth`) {
		t.Fatalf("status still reports sign-in: %s", data)
	}
}

func TestUpdateTunnelAuthRejectionChangesNothing(t *testing.T) {
	const secret = "rejected-client-secret"
	wallet := "0x0000000000000000000000000000000000000001"
	signedIn := testTunnel("signedin")
	signedIn.Provider = "siwe"
	signedIn.Allow = []string{wallet}
	tcp := testTunnel("tcp")
	tcp.TCPEnabled = true
	udp := testTunnel("udp")
	udp.UDPEnabled = true
	m, path := testManager(t, testTunnel("plain"), signedIn, tcp, udp)

	for _, tc := range []updateRejectionCase{
		{name: "oidc without allowlist", id: "plain", want: "oidc requires at least one",
			body: `{"auth":"oidc","auth_oidc_issuer":"https://accounts.example.com","auth_oidc_client_id":"client-123","auth_oidc_client_secret":"` + secret + `"}`},
		{name: "oidc without issuer", id: "plain", want: "issuer",
			body: `{"auth":"oidc","auth_allowed_wallets":["alice@example.com"],"auth_oidc_client_id":"client-123","auth_oidc_client_secret":"` + secret + `"}`},
		{name: "oidc settings under siwe", id: "signedin", want: "oidc settings require",
			body: `{"auth_oidc_issuer":"https://accounts.example.com","auth_oidc_client_secret":"` + secret + `"}`},
		{name: "invalid wallet", id: "signedin", want: "address must start with 0x", body: `{"auth_allowed_wallets":["alice"]}`},
		{name: "unknown provider", id: "plain", want: "unsupported application auth provider", body: `{"auth":"magic"}`},
		{name: "allowlist without provider", id: "plain", want: "unsupported application auth provider", body: `{"auth_allowed_wallets":["` + wallet + `"]}`},
		{name: "settings together with sign-in turned off", id: "signedin", want: "leave out the other auth fields",
			body: `{"auth":"","auth_oidc_issuer":"https://accounts.example.com"}`},
		{name: "unknown auth field", id: "signedin", want: "unknown field", body: `{"auth_oidc_isuer":"https://accounts.example.com"}`},
		{name: "tcp", id: "tcp", want: "cannot be combined with TCP or UDP", body: `{"auth":"siwe"}`},
		{name: "udp", id: "udp", want: "cannot be combined with TCP or UDP", body: `{"auth":"credential"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checkUpdateRejectionUnchanged(t, m, path, secret, tc)
		})
	}
}

type updateRejectionCase struct {
	name, id, body, want string
}

func checkUpdateRejectionUnchanged(t *testing.T, m *manager, path, secret string, tc updateRejectionCase) {
	t.Helper()
	fileBefore, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	statusBefore := tunnelStatus(t, m, tc.id)

	code, body := callControl(t, m, http.MethodPatch, types.PathAgentTunnelsPrefix+tc.id, tc.body)
	if code != http.StatusBadRequest || !strings.Contains(body, tc.want) {
		t.Fatalf("status = %d, body = %s; want 400 mentioning %q", code, body, tc.want)
	}
	if strings.Contains(body, secret) {
		t.Fatalf("error echoes the client secret: %s", body)
	}
	fileAfter, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(fileBefore, fileAfter) {
		t.Fatalf("rejected update changed the config file:\n%s", fileAfter)
	}
	if statusAfter := tunnelStatus(t, m, tc.id); !reflect.DeepEqual(statusBefore, statusAfter) {
		t.Fatalf("rejected update changed the tunnel: %+v -> %+v", statusBefore, statusAfter)
	}
}

func TestUpdateTunnelAuthRestartsOnlyThatTunnel(t *testing.T) {
	addedRelay, err := utils.NormalizeRelayURL("https://127.0.0.1:2")
	if err != nil {
		t.Fatal(err)
	}
	edited := testTunnel("a")
	edited.Provider = "credential"
	m, _ := testManager(t, edited, testTunnel("b"))
	startManager(t, m)
	eventually(t, "both tunnels to run", func() bool {
		return tunnelStatus(t, m, "a").State == "running" && tunnelStatus(t, m, "b").State == "running"
	})
	connectTunnelRelay(t, m, "b", addedRelay)
	if b := tunnelStatus(t, m, "b"); !statusHasRelay(b, addedRelay) {
		t.Fatalf("relay was not connected to b: %+v", b.Relays)
	}

	body := `{"auth":"oidc","auth_allowed_wallets":["alice@example.com"],"auth_oidc_issuer":"` + unreachableIssuer + `","auth_oidc_client_id":"client-123"}`
	if code, resp := callControl(t, m, http.MethodPatch, types.PathAgentTunnelsPrefix+"a", body); code != http.StatusAccepted {
		t.Fatalf("status = %d, body = %s", code, resp)
	}
	if b := tunnelStatus(t, m, "b"); b.State != "running" || !statusHasRelay(b, addedRelay) {
		t.Fatalf("sign-in change on a restarted b: %+v", b)
	}
	eventually(t, "a to run with the oidc gate", func() bool {
		return tunnelStatus(t, m, "a").AuthProviderError != ""
	})

	connectTunnelRelay(t, m, "a", addedRelay)
	body = `{"metadata":{"description":"in place"},"auth":"oidc","auth_oidc_issuer":"` + unreachableIssuer + `"}`
	if code, resp := callControl(t, m, http.MethodPatch, types.PathAgentTunnelsPrefix+"a", body); code != http.StatusAccepted {
		t.Fatalf("status = %d, body = %s", code, resp)
	}
	if status := tunnelStatus(t, m, "a"); status.State != "running" || !statusHasRelay(status, addedRelay) || status.Metadata.Description != "in place" {
		t.Fatalf("tunnel was rebuilt for a metadata change: %+v", status)
	}
}

func connectTunnelRelay(t *testing.T, m *manager, tunnelID, relayURL string) {
	t.Helper()
	if code, body := callControl(t, m, http.MethodPost, types.PathAgentTunnelsPrefix+tunnelID+"/relays", `{"relay_url":"`+relayURL+`"}`); code != http.StatusAccepted {
		t.Fatalf("connect relay: status = %d, body = %s", code, body)
	}
}

func statusHasRelay(status AgentTunnelStatus, relayURL string) bool {
	return slices.ContainsFunc(status.Relays, func(relay AgentRelayStatus) bool { return relay.RelayURL == relayURL })
}
