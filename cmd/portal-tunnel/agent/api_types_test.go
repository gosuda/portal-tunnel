package agent

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/gateway"
)

// The auth fields of an update sit next to its other fields on the wire, as
// they did when each had a field of its own; a null one is left out. Field names
// match without regard to case, so one field sent in two spellings is refused.
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

// authChanges names what an update must send to turn the stored settings into
// the desired ones, and applying it gives the desired settings. The write-only
// client secret is never among the changes, so the stored one stays.
func TestAuthChangesApplyToTheDesiredSettings(t *testing.T) {
	stored := gateway.ApplicationAuthConfig{
		Provider:        gateway.ApplicationAuthProviderOIDC,
		AllowedWallets:  []string{"alice@example.com"},
		IdentityHeaders: true,
		OIDCConfig:      gateway.OIDCConfig{OIDCIssuerURL: "https://idp.example", OIDCClientID: "client", OIDCClientSecret: "secret"},
	}
	desired := gateway.ApplicationAuthConfig{
		Provider:       gateway.ApplicationAuthProviderSAML,
		AllowedWallets: []string{"alice@example.com"},
		SAMLConfig:     gateway.SAMLConfig{SAMLMetadataURL: "https://idp.example/metadata"},
	}
	changes := authChanges(stored, desired)
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
	desired.OIDCClientSecret = "secret"
	if !reflect.DeepEqual(applied, desired) {
		t.Fatalf("applied = %+v, want %+v", applied, desired)
	}
	if authChanges(applied, applied) != nil {
		t.Fatal("equal settings have changes")
	}
}

// An update decodes over the stored settings, and decoding reuses the array of a
// slice, so a refused update must not have written into the stored lists.
func TestApplyAuthLeavesTheStoredListsAlone(t *testing.T) {
	t.Parallel()

	stored := gateway.ApplicationAuthConfig{Provider: "oidc", AllowedWallets: []string{"a@example.com"}, EmailList: []string{"b@example.com"}}
	applied := stored
	request := AgentTunnelUpdateRequest{Auth: map[string]json.RawMessage{
		"auth_allowed_wallets": json.RawMessage(`["c@example.com"]`),
		"auth_email_list":      json.RawMessage(`["d@example.com"]`),
	}}
	if err := request.applyAuth(&applied); err != nil {
		t.Fatal(err)
	}
	if stored.AllowedWallets[0] != "a@example.com" || stored.EmailList[0] != "b@example.com" {
		t.Fatalf("stored lists changed: %v, %v", stored.AllowedWallets, stored.EmailList)
	}
}
