package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/gateway"
	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/tunnel"
	"github.com/gosuda/portal-tunnel/v2/sdk/appauth"
	"github.com/gosuda/portal-tunnel/v2/types"
)

// Agent control-plane DTOs. These live in the agent package because both
// their producers (the manager and control API in this package) and their
// consumers (the agent CLI and dashboard) are application surfaces; shared
// types stay agent-blind.

type AgentStatusResponse struct {
	ConfigPath    string              `json:"config_path,omitempty"`
	ControlAddr   string              `json:"control_addr"`
	WalletAddress string              `json:"wallet_address,omitempty"`
	Tunnels       []AgentTunnelStatus `json:"tunnels,omitempty"`
}

// AgentTunnelStatus reports a tunnel: its settings as the agent resolved them,
// without secrets, and its runtime state.
type AgentTunnelStatus struct {
	ID              string              `json:"id"`
	Name            string              `json:"name,omitempty"`
	Address         string              `json:"address,omitempty"`
	State           string              `json:"state"`
	TargetAddr      string              `json:"target_addr,omitempty"`
	Serve           string              `json:"serve,omitempty"`
	LastError       string              `json:"last_error,omitempty"`
	Discovery       bool                `json:"discovery"`
	Overlay         bool                `json:"overlay"`
	MaxActiveRelays int                 `json:"max_active_relays,omitempty"`
	Metadata        types.LeaseMetadata `json:"metadata"`
	// The auth settings come without their secrets (see
	// appauth.Config.Public). The OIDC client secret and the
	// SMTP password are write-only: AuthOIDCClientSecretSet and
	// AuthSMTPPasswordSet say whether one is configured.
	tunnel.AuthConfig
	AuthOIDCClientSecretSet bool `json:"auth_oidc_client_secret_set,omitempty"`
	AuthSMTPPasswordSet     bool `json:"auth_smtp_password_set,omitempty"`
	// The provider fields report the startup check of the OIDC or SAML
	// identity provider, or of the SMTP server of email, of a running tunnel:
	// both are empty until the check finishes, and the error stays empty while
	// the provider is usable.
	AuthProviderChecked bool   `json:"auth_provider_checked,omitempty"`
	AuthProviderError   string `json:"auth_provider_error,omitempty"`
	gateway.X402Config
	HTTPRoutes []tunnel.HTTPRoute `json:"http_routes,omitempty"`
	Relays     []AgentRelayStatus `json:"relays,omitempty"`
}

type AgentRelayStatus struct {
	RelayURL   string `json:"relay_url"`
	PublicURL  string `json:"public_url,omitempty"`
	AliasURL   string `json:"alias_url,omitempty"`
	TCPAddr    string `json:"tcp_addr,omitempty"`
	Version    string `json:"version,omitempty"`
	Explicit   bool   `json:"explicit,omitempty"`
	Connecting bool   `json:"connecting"`
	// Approval is pending or refused while the relay refuses this tunnel's
	// lease. Empty never means approved.
	Approval    string `json:"approval,omitempty"`
	Bootstrap   bool   `json:"bootstrap"`
	Banned      bool   `json:"banned"`
	SupportsUDP bool   `json:"supports_udp"`
	SupportsTCP bool   `json:"supports_tcp"`
}

// AgentTunnelRequest adds a tunnel. The auth and payment components are the
// ones the agent config stores, under the same keys.
type AgentTunnelRequest struct {
	ID                  string             `json:"id"`
	Name                string             `json:"name,omitempty"`
	TargetAddr          string             `json:"target_addr,omitempty"`
	Serve               string             `json:"serve,omitempty"`
	HTTPRoutes          []tunnel.HTTPRoute `json:"http_routes,omitempty"`
	StripRequestHeaders []string           `json:"strip_request_headers,omitempty"`
	RelayURLs           []string           `json:"relays,omitempty"`
	Discovery           *bool              `json:"discovery,omitempty"`
	Overlay             bool               `json:"overlay,omitempty"`
	MaxActiveRelays     int                `json:"max_active_relays,omitempty"`
	tunnel.AuthConfig
	gateway.X402Config
}

type AgentRelayRequest struct {
	RelayURL string `json:"relay_url"`
}

// AgentTunnelUpdateRequest changes the fields it names; an omitted field, or one
// sent as null, stays as it is. Auth holds the auth and auth_* fields as sent,
// and they are decoded over the stored auth settings, so a setting added to
// appauth.Config can be updated without a field of its own here.
// An empty auth turns application sign-in off and clears the other auth
// settings. The OIDC client secret and the SMTP password are write-only: an
// empty value clears one.
type AgentTunnelUpdateRequest struct {
	MaxActiveRelays *int                       `json:"max_active_relays,omitempty"`
	Metadata        *AgentMetadataRequest      `json:"metadata,omitempty"`
	Auth            map[string]json.RawMessage `json:"-"`
}

// agentTunnelUpdateFields encodes and decodes the named fields of an
// AgentTunnelUpdateRequest without its JSON methods.
type agentTunnelUpdateFields AgentTunnelUpdateRequest

func (r *AgentTunnelUpdateRequest) UnmarshalJSON(data []byte) error {
	var named agentTunnelUpdateFields
	if err := json.Unmarshal(data, &named); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	auth := make(map[string]json.RawMessage)
	for key, value := range fields {
		key = strings.ToLower(key)
		if key != "auth" && !strings.HasPrefix(key, "auth_") {
			continue
		}
		// Field names match without regard to case, so two spellings of one
		// field would leave the outcome to the order of the map.
		if _, ok := auth[key]; ok {
			return fmt.Errorf("auth field %q is sent more than once", key)
		}
		auth[key] = value
	}
	maps.DeleteFunc(auth, func(_ string, value json.RawMessage) bool { return bytes.Equal(value, []byte("null")) })
	if len(auth) > 0 {
		named.Auth = auth
	}
	*r = AgentTunnelUpdateRequest(named)
	return nil
}

func (r AgentTunnelUpdateRequest) MarshalJSON() ([]byte, error) {
	data, err := json.Marshal(agentTunnelUpdateFields(r))
	if err != nil || len(r.Auth) == 0 {
		return data, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return nil, err
	}
	maps.Copy(fields, r.Auth)
	return json.Marshal(fields)
}

func (r AgentTunnelUpdateRequest) Empty() bool {
	return r.MaxActiveRelays == nil && (r.Metadata == nil || r.Metadata.Empty()) && len(r.Auth) == 0
}

// applyAuth decodes the auth fields of the request over auth, the stored
// settings, and refuses a field the settings do not have. An empty auth clears
// the settings and refuses any other auth field next to it.
func (r AgentTunnelUpdateRequest) applyAuth(auth *appauth.Config) error {
	if len(r.Auth) == 0 {
		return nil
	}
	if raw, ok := r.Auth["auth"]; ok {
		var provider string
		if err := json.Unmarshal(raw, &provider); err == nil && strings.TrimSpace(provider) == "" {
			if len(r.Auth) > 1 {
				return errAuthEmptyWhichTurnsSignOff
			}
			*auth = appauth.Config{}
			return nil
		}
	}
	data, err := json.Marshal(r.Auth)
	if err != nil {
		return err
	}
	// Decoding reuses the backing array of a slice, which the stored settings
	// may share.
	next := *auth
	next.Allow, next.EmailList = slices.Clone(next.Allow), slices.Clone(next.EmailList)
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&next); err != nil {
		return err
	}
	*auth = next
	return nil
}

// authChanges is the auth part of an update that turns the stored settings into
// desired: each field that differs, and each emptied one with its empty value.
// Both are compared as a status shows them, so a write-only secret is never
// among the changes; a client that changes one names it itself. An update
// decodes over the stored settings, so it can empty a string, a number, a
// boolean or a list, and a setting must be one of these.
func authChanges(stored, desired appauth.Config) map[string]json.RawMessage {
	fields := func(auth appauth.Config) map[string]json.RawMessage {
		data, _ := json.Marshal(auth.Public())
		var out map[string]json.RawMessage
		_ = json.Unmarshal(data, &out)
		return out
	}
	from, to := fields(stored), fields(desired)
	changes := make(map[string]json.RawMessage)
	for key, value := range to {
		if !bytes.Equal(from[key], value) {
			changes[key] = value
		}
	}
	for key, value := range from {
		if _, ok := to[key]; ok {
			continue
		}
		// Every field is omitted when empty, so a field only stored is emptied,
		// with the empty value of the type it is stored as.
		var storedValue any
		_ = json.Unmarshal(value, &storedValue)
		switch storedValue.(type) {
		case string:
			changes[key] = json.RawMessage(`""`)
		case float64:
			changes[key] = json.RawMessage(`0`)
		case bool:
			changes[key] = json.RawMessage(`false`)
		case []any:
			changes[key] = json.RawMessage(`[]`)
		}
	}
	if len(changes) == 0 {
		return nil
	}
	return changes
}

type AgentMetadataRequest struct {
	Description *string   `json:"description,omitempty"`
	Owner       *string   `json:"owner,omitempty"`
	Thumbnail   *string   `json:"thumbnail,omitempty"`
	Tags        *[]string `json:"tags,omitempty"`
	Hide        *bool     `json:"hide,omitempty"`
}

func (r AgentMetadataRequest) Empty() bool {
	return r.Description == nil &&
		r.Owner == nil &&
		r.Thumbnail == nil &&
		r.Tags == nil &&
		r.Hide == nil
}
