package main

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/cmd/relay-server/policy"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

type persistedPolicyPayload struct {
	persistedPolicyState
	LegacyBannedIPs json.RawMessage `json:"banned_ips"`
}

func applyPersistedPayload(initial *policy.State, payload persistedPolicyPayload) error {
	if strings.TrimSpace(payload.ApprovalMode) != "" {
		mode, err := policy.ParseMode(payload.ApprovalMode)
		if err != nil {
			return err
		}
		initial.SetMode(mode)
	}
	approved, err := parseIdentityKeyList("approved_identity_keys", payload.ApprovedIdentityKeys)
	if err != nil {
		return err
	}
	denied, err := parseIdentityKeyList("denied_identity_keys", payload.DeniedIdentityKeys)
	if err != nil {
		return err
	}
	banned, err := parseIdentityKeyList("banned_identity_keys", payload.BannedIdentityKeys)
	if err != nil {
		return err
	}
	limits, err := parseIdentityBPSLimits(payload.IdentityBPS)
	if err != nil {
		return err
	}
	for key, limit := range limits {
		if limit < 0 {
			limits[key] = 0
		}
	}
	initial.SetDecisions(approved, denied)
	initial.SetBannedKeys(banned)
	initial.IdentityBPS = limits
	initial.UDP = applyOptionalPolicy(payload.UDPEnabled, payload.UDPMaxLeases, initial.UDP)
	initial.TCPPort = applyOptionalPolicy(payload.TCPPortEnabled, payload.TCPPortMaxLeases, initial.TCPPort)
	return nil
}

func (api *RelayAPI) loadPolicyState(initial policy.State) error {
	var payload persistedPolicyPayload
	loaded, err := utils.ReadJSONFileIfExists(api.policyStatePath, &payload)
	if err != nil {
		return err
	}
	if loaded {
		if err := applyPersistedPayload(&initial, payload); err != nil {
			return err
		}
	}
	if err := api.commitPolicy(initial); err != nil {
		return err
	}
	if len(payload.LegacyBannedIPs) > 0 {
		if err := utils.WriteJSONFile(api.policyStatePath, policyState(initial), 0o600); err != nil {
			return fmt.Errorf("remove legacy IP bans: %w", err)
		}
		log.Info().Msg("removed legacy IP bans; durable blocking now uses identity keys")
	}
	return nil
}
func (api *RelayAPI) policyLeases(access policy.State) []types.PolicyLease {
	leases := api.server.PolicyLeases()
	for i := range leases {
		key, err := types.ParseServiceIdentityKey(leases[i].IdentityKey)
		if err != nil {
			continue
		}
		leases[i].IsApproved = access.EffectiveApproval(key)
		leases[i].IsBanned = access.IsBanned(key)
		leases[i].IsDenied = access.IsDenied(key)
	}
	return leases
}

func (api *RelayAPI) commitPolicy(next policy.State) error {
	if err := api.server.SetTransportPolicy(next.UDP.Enabled, next.UDP.MaxLeases, next.TCPPort.Enabled, next.TCPPort.MaxLeases); err != nil {
		return err
	}
	api.server.BPSManager().SetServiceIdentityBPSLimits(next.IdentityBPS)
	previous := api.policies.Snapshot()
	committed := api.policies.Commit(next)
	keys := make(map[types.ServiceIdentityKey]struct{})
	for _, state := range []policy.State{previous, committed} {
		for _, key := range state.ApprovedKeys() {
			keys[key] = struct{}{}
		}
		for _, key := range state.DeniedKeys() {
			keys[key] = struct{}{}
		}
		for _, key := range state.BannedKeys() {
			keys[key] = struct{}{}
		}
	}
	for _, key := range api.server.AccessProjectionKeys() {
		keys[key] = struct{}{}
	}
	for key := range keys {
		api.server.SetServiceIdentityAccess(key, committed.Access(key), committed.Revision())
	}
	return nil
}

func policySettings(state policy.State) types.PolicySettings {
	return types.PolicySettings{ApprovalMode: string(state.Mode()), UDP: state.UDP, TCPPort: state.TCPPort}
}
func policyState(access policy.State) persistedPolicyState {
	udpEnabled, udpMaxLeases := access.UDP.Enabled, access.UDP.MaxLeases
	tcpPortEnabled, tcpPortMaxLeases := access.TCPPort.Enabled, access.TCPPort.MaxLeases
	approved := access.ApprovedKeys()
	approvedStrings := make([]string, len(approved))
	for i, key := range approved {
		approvedStrings[i] = key.String()
	}
	denied := access.DeniedKeys()
	deniedStrings := make([]string, len(denied))
	for i, key := range denied {
		deniedStrings[i] = key.String()
	}
	banned := access.BannedKeys()
	bannedStrings := make([]string, len(banned))
	for i, key := range banned {
		bannedStrings[i] = key.String()
	}
	limits := make(map[string]int64, len(access.IdentityBPS))
	for key, limit := range access.IdentityBPS {
		limits[key.String()] = limit
	}
	return persistedPolicyState{
		ApprovalMode:         string(access.Mode()),
		ApprovedIdentityKeys: approvedStrings,
		DeniedIdentityKeys:   deniedStrings,
		BannedIdentityKeys:   bannedStrings,
		IdentityBPS:          limits,
		UDPEnabled:           &udpEnabled,
		UDPMaxLeases:         &udpMaxLeases,
		TCPPortEnabled:       &tcpPortEnabled,
		TCPPortMaxLeases:     &tcpPortMaxLeases,
	}
}

type persistedPolicyState struct {
	ApprovalMode         string           `json:"approval_mode"`
	ApprovedIdentityKeys []string         `json:"approved_identity_keys,omitempty"`
	DeniedIdentityKeys   []string         `json:"denied_identity_keys,omitempty"`
	BannedIdentityKeys   []string         `json:"banned_identity_keys,omitempty"`
	IdentityBPS          map[string]int64 `json:"identity_bps,omitempty"`
	UDPEnabled           *bool            `json:"udp_enabled,omitempty"`
	UDPMaxLeases         *int             `json:"udp_max_leases,omitempty"`
	TCPPortEnabled       *bool            `json:"tcp_port_enabled,omitempty"`
	TCPPortMaxLeases     *int             `json:"tcp_port_max_leases,omitempty"`
}

func applyOptionalPolicy(enabled *bool, maxLeases *int, current types.PolicyPortSettings) types.PolicyPortSettings {
	if enabled == nil && maxLeases == nil {
		return current
	}
	if enabled != nil {
		current.Enabled = *enabled
	}
	if maxLeases != nil {
		current.MaxLeases = *maxLeases
	}
	return current
}

func parseIdentityKeyList(section string, keys []string) ([]types.ServiceIdentityKey, error) {
	parsed := make([]types.ServiceIdentityKey, len(keys))
	for i, raw := range keys {
		key, err := types.ParseServiceIdentityKey(raw)
		if err != nil {
			return nil, fmt.Errorf("policy.json %s[%d]: %w", section, i, err)
		}
		parsed[i] = key
	}
	return parsed, nil
}

func parseIdentityBPSLimits(limits map[string]int64) (map[types.ServiceIdentityKey]int64, error) {
	if limits == nil {
		return nil, nil
	}
	parsed := make(map[types.ServiceIdentityKey]int64, len(limits))
	for raw, limit := range limits {
		key, err := types.ParseServiceIdentityKey(raw)
		if err != nil {
			return nil, fmt.Errorf("policy.json identity_bps[%q]: %w", raw, err)
		}
		if existing, ok := parsed[key]; ok && existing != limit {
			return nil, fmt.Errorf("policy.json identity_bps[%q]: canonical key %q already set to %d", raw, key.String(), existing)
		}
		parsed[key] = limit
	}
	return parsed, nil
}
