package agent

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/tunnel"
	"github.com/gosuda/portal-tunnel/v2/sdk"
	"github.com/gosuda/portal-tunnel/v2/sdk/appauth"
)

func TestAgentTunnelUpdateRequestJSON(t *testing.T) {
	var req AgentTunnelUpdateRequest
	body := `{"max_active_relays":2,"Auth":"oidc","auth_allowed_wallets":null,"auth_oidc_issuer":"https://idp.example","unknown":1}`
	if err := json.Unmarshal([]byte(body), &req); err != nil {
		t.Fatal(err)
	}
	wantAuth := map[string]json.RawMessage{"auth": json.RawMessage(`"oidc"`), "auth_oidc_issuer": json.RawMessage(`"https://idp.example"`)}
	if req.MaxActiveRelays == nil || *req.MaxActiveRelays != 2 || !reflect.DeepEqual(req.Auth, wantAuth) {
		t.Fatalf("decoded = %+v, auth = %s", req, req.Auth)
	}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	var again AgentTunnelUpdateRequest
	if err := json.Unmarshal(data, &again); err != nil || !reflect.DeepEqual(again, req) {
		t.Fatalf("round trip of %s = %+v (err %v)", data, again, err)
	}
	if err := json.Unmarshal([]byte(`{"auth":"oidc","AUTH":null}`), &again); err == nil || !strings.Contains(err.Error(), "more than once") {
		t.Fatalf("auth in two spellings: err = %v", err)
	}
}

func TestAuthChangesApplyToTheDesiredSettings(t *testing.T) {
	stored := appauth.Config{
		Provider:        appauth.ProviderOIDC,
		Allow:           []string{"alice@example.com"},
		IdentityHeaders: true,
		OIDCConfig:      appauth.OIDCConfig{OIDCIssuerURL: "https://idp.example", OIDCClientID: "client", OIDCClientSecret: "secret"},
	}
	desired := appauth.Config{
		Provider:   appauth.ProviderSAML,
		Allow:      []string{"alice@example.com"},
		SAMLConfig: appauth.SAMLConfig{SAMLMetadataURL: "https://idp.example/metadata"},
	}
	changes := AuthChanges(stored, desired)
	want := map[string]json.RawMessage{
		"auth":                   json.RawMessage(`"saml"`),
		"auth_identity_headers":  json.RawMessage(`false`),
		"auth_oidc_issuer":       json.RawMessage(`""`),
		"auth_oidc_client_id":    json.RawMessage(`""`),
		"auth_saml_metadata_url": json.RawMessage(`"https://idp.example/metadata"`),
	}
	if !reflect.DeepEqual(changes, want) {
		t.Fatalf("changes = %s", changes)
	}
	applied := stored
	if err := (AgentTunnelUpdateRequest{Auth: changes}).applyAuth(&applied); err != nil {
		t.Fatal(err)
	}
	wantApplied := desired
	wantApplied.OIDCClientSecret = "secret"
	if !reflect.DeepEqual(applied, wantApplied) {
		t.Fatalf("applied = %+v, want %+v", applied, wantApplied)
	}
	if AuthChanges(applied, applied) != nil {
		t.Fatal("equal settings have changes")
	}
}

func TestApplyAuthLeavesTheStoredListsAlone(t *testing.T) {
	t.Parallel()

	stored := appauth.Config{Provider: "oidc", Allow: []string{"a@example.com"}, EmailList: []string{"b@example.com"}}
	applied := stored
	request := AgentTunnelUpdateRequest{Auth: map[string]json.RawMessage{
		"auth_allowed_wallets": json.RawMessage(`["c@example.com"]`),
		"auth_email_list":      json.RawMessage(`["d@example.com"]`),
	}}
	if err := request.applyAuth(&applied); err != nil {
		t.Fatal(err)
	}
	if stored.Allow[0] != "a@example.com" || stored.EmailList[0] != "b@example.com" {
		t.Fatalf("stored lists changed: %v, %v", stored.Allow, stored.EmailList)
	}
}

func TestAgentTunnelStatusLabel(t *testing.T) {
	if got := (AgentTunnelStatus{ID: "web-1", Name: "web"}).Label(); got != "web" {
		t.Fatalf("label = %q, want the public name", got)
	}
	if got := (AgentTunnelStatus{ID: "web-1", Name: "  "}).Label(); got != "web-1" {
		t.Fatalf("label = %q, want the id when the name is blank", got)
	}
}

func TestAgentTunnelStatusTargetSummary(t *testing.T) {
	routes := func(amounts ...string) []tunnel.HTTPRoute {
		out := make([]tunnel.HTTPRoute, 0, len(amounts))
		for _, amount := range amounts {
			out = append(out, tunnel.HTTPRoute{Prefix: "/", Upstream: "3000", Amount: amount})
		}
		return out
	}
	tests := []struct {
		name   string
		tunnel AgentTunnelStatus
		want   string
	}{
		{name: "target address", tunnel: AgentTunnelStatus{TargetAddr: " 127.0.0.1:3000 "}, want: "127.0.0.1:3000"},
		{name: "static site wins over the target", tunnel: AgentTunnelStatus{Serve: "./site", TargetAddr: "127.0.0.1:3000"}, want: "./site"},
		{name: "free routes", tunnel: AgentTunnelStatus{HTTPRoutes: routes("", "")}, want: "2 routes"},
		{name: "paid routes", tunnel: AgentTunnelStatus{HTTPRoutes: routes("", "0.01", "0.02")}, want: "3 routes, 2 paid"},
		{name: "nothing to show", tunnel: AgentTunnelStatus{}, want: "-"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.tunnel.TargetSummary(); got != tt.want {
				t.Fatalf("target = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestAgentRelayStatusMode(t *testing.T) {
	for _, tc := range []struct {
		name  string
		relay AgentRelayStatus
		want  string
	}{
		{name: "unknown", want: "-"},
		{name: "ready", relay: AgentRelayStatus{State: sdk.RelayReady, PublicURL: "https://app.example"}, want: "direct"},
		{name: "connecting", relay: AgentRelayStatus{State: sdk.RelayConnecting}, want: "connecting..."},
		{name: "waiting", relay: AgentRelayStatus{State: sdk.RelayConnecting, Approval: sdk.RelayApprovalPending}, want: "waiting"},
		{name: "refused", relay: AgentRelayStatus{State: sdk.RelayConnecting, Approval: sdk.RelayApprovalRefused}, want: "refused"},
		{name: "failed with retained URL", relay: AgentRelayStatus{State: sdk.RelayFailed, PublicURL: "https://app.example"}, want: "failed"},
		{name: "ready over legacy TLS", relay: AgentRelayStatus{State: sdk.RelayReady, CertificateError: "unknown authority"}, want: "legacy TLS"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.relay.Mode(); got != tc.want {
				t.Fatalf("mode = %q, want %q", got, tc.want)
			}
		})
	}
}

// URL is what the dashboards hand to a browser, so it carries only http and
// https addresses, and never the credentials, query or fragment of one.
func TestAgentRelayStatusURL(t *testing.T) {
	tests := []struct {
		name  string
		relay AgentRelayStatus
		want  string
	}{
		{name: "public URL without credentials, query and fragment", relay: AgentRelayStatus{PublicURL: "https://user:secret@web.relay.example.com/app?token=1#frag"}, want: "https://web.relay.example.com/app"},
		{name: "alias before the identity-bound URL", relay: AgentRelayStatus{PublicURL: "https://web-0x1234.relay.example.com/", AliasURL: "https://web.relay.example.com/"}, want: "https://web.relay.example.com/"},
		{name: "port is kept", relay: AgentRelayStatus{PublicURL: "https://web.localhost:8443/"}, want: "https://web.localhost:8443/"},
		{name: "IPv6 host", relay: AgentRelayStatus{PublicURL: "http://[::1]/"}, want: "http://[::1]/"},
		{name: "scheme is lowercased", relay: AgentRelayStatus{PublicURL: "HTTPS://web.relay.example.com"}, want: "https://web.relay.example.com"},
		{name: "other schemes are not URLs to open", relay: AgentRelayStatus{PublicURL: "file:///etc/passwd"}, want: ""},
		{name: "javascript is not a URL to open", relay: AgentRelayStatus{PublicURL: "javascript:alert(1)"}, want: ""},
		{name: "a host is required", relay: AgentRelayStatus{PublicURL: "https:///path"}, want: ""},
		{name: "a TCP address is not a URL", relay: AgentRelayStatus{TCPAddr: "relay.example.com:40001"}, want: ""},
		{name: "nothing known", relay: AgentRelayStatus{}, want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.relay.URL(); got != tt.want {
				t.Fatalf("url = %q, want %q", got, tt.want)
			}
		})
	}
}
