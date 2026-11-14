package main

import (
	"cmp"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/cmd/relay-server/policy"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func (api *RelayAPI) serveAdmin(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimSuffix(strings.TrimSpace(r.URL.Path), "/")
	path = cmp.Or(path, types.PathRoot)

	switch path {
	case types.PathAdmin:
		http.NotFound(w, r)
		return
	case types.PathAdminAuthLogin:
		if !utils.RequireMethod(w, r, http.MethodPost) {
			return
		}
		api.handleAdminLogin(w, r)
		return
	case types.PathAdminLogout:
		if !utils.RequireMethod(w, r, http.MethodPost) {
			return
		}
		utils.WriteAPIData(w, http.StatusOK, map[string]any{})
		return
	case types.PathAdminAuthStatus:
		if !utils.RequireMethod(w, r, http.MethodGet) {
			return
		}
		utils.WriteAPIData(w, http.StatusOK, types.AdminAuthStatusResponse{
			Authenticated: api.authenticatedAdmin(r),
		})
		return
	}

	if !api.authenticatedAdmin(r) {
		utils.WriteAPIError(w, http.StatusUnauthorized, types.APIErrorCodeUnauthorized, "unauthorized")
		return
	}

	switch path {
	case types.PathAdmin + "/metrics":
		api.metrics.handler.ServeHTTP(w, r)
		return
	default:
		http.NotFound(w, r)
	}
}
func decodePolicySettingsBody(w http.ResponseWriter, r *http.Request, invalidBody utils.APIErrorResponse) (types.PolicySettings, bool) {
	var settings types.PolicySettings
	if r.Method == http.MethodGet {
		return settings, false
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodGet+", "+http.MethodPost)
		utils.MethodNotAllowedError().Write(w)
		return settings, false
	}
	req, ok := utils.DecodeJSONRequestAs[types.PolicySettings](w, r, controlBodyLimit, invalidBody)
	if !ok {
		return settings, false
	}
	return req, true
}

func leasePolicyUpdateError(update types.LeasePolicyUpdate) string {
	if update.IsBanned == nil && update.IsApproved == nil && update.IsDenied == nil && update.BPS == nil && !update.ResetBPS {
		return "lease policy update is empty"
	}
	if update.ResetBPS && update.BPS != nil {
		return "bps and reset_bps are mutually exclusive"
	}
	if update.IsApproved != nil && update.IsDenied != nil && *update.IsApproved && *update.IsDenied {
		return "lease cannot be approved and denied"
	}
	return ""
}

func (api *RelayAPI) routePolicyRequest(w http.ResponseWriter, r *http.Request, requestPath string) (types.PolicySettings, types.LeasePolicyUpdate, bool) {
	var settings types.PolicySettings
	var update types.LeasePolicyUpdate
	invalidBody := utils.InvalidRequestError(errors.New("invalid request body"))
	switch requestPath {
	case types.PathPolicy:
		if r.Method == http.MethodGet {
			utils.WriteAPIData(w, http.StatusOK, policySettings(api.policies.Snapshot()))
			return settings, update, false
		}
		req, ok := decodePolicySettingsBody(w, r, invalidBody)
		if !ok {
			return settings, update, false
		}
		return req, update, true
	case types.PathPolicyState:
		if !utils.RequireMethod(w, r, http.MethodGet) {
			return settings, update, false
		}
		state := api.policies.Snapshot()
		utils.WriteAPIData(w, http.StatusOK, types.PolicyStateResponse{
			Policy: policySettings(state), Leases: api.policyLeases(state),
		})
		return settings, update, false
	case types.PathPolicyLeases:
		if !utils.RequireMethod(w, r, http.MethodPost) {
			return settings, update, false
		}
		req, ok := utils.DecodeJSONRequestAs[types.LeasePolicyUpdate](w, r, controlBodyLimit, invalidBody)
		if !ok {
			return settings, update, false
		}
		return settings, req, true
	default:
		http.NotFound(w, r)
		return settings, update, false
	}
}

func (api *RelayAPI) applyPolicySettingsLocked(w http.ResponseWriter, next *policy.State, settings types.PolicySettings) bool {
	mode, err := policy.ParseMode(settings.ApprovalMode)
	if err != nil {
		utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidMode, "approval_mode must be 'auto' or 'manual'")
		return false
	}
	if err := api.server.ValidateTransportPolicy(settings.UDP.Enabled, settings.UDP.MaxLeases, settings.TCPPort.Enabled, settings.TCPPort.MaxLeases); err != nil {
		utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidRequest, err.Error())
		return false
	}
	next.SetMode(mode)
	next.UDP, next.TCPPort = settings.UDP, settings.TCPPort
	return true
}

func (api *RelayAPI) applyLeasePolicyUpdateLocked(w http.ResponseWriter, next *policy.State, update types.LeasePolicyUpdate) bool {
	key, err := types.ParseServiceIdentityKey(update.IdentityKey)
	if err != nil {
		utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidRequest, "invalid identity")
		return false
	}
	if msg := leasePolicyUpdateError(update); msg != "" {
		utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidRequest, msg)
		return false
	}
	if update.ResetBPS {
		delete(next.IdentityBPS, key)
	}
	if !api.applyLeaseBPSLocked(w, next, key, update) {
		return false
	}
	applyLeaseDecisionLocked(next, key, update)
	return true
}
func applyLeaseDecisionLocked(next *policy.State, key types.ServiceIdentityKey, update types.LeasePolicyUpdate) {
	if update.IsBanned != nil {
		if *update.IsBanned {
			next.Ban(key)
		} else {
			next.Unban(key)
		}
	}
	if update.IsDenied != nil {
		if *update.IsDenied {
			next.Deny(key)
		} else {
			next.Undeny(key)
		}
	}
	if update.IsApproved != nil {
		if *update.IsApproved {
			next.Approve(key)
		} else {
			next.Revoke(key)
		}
	}
}

func (api *RelayAPI) applyLeaseBPSLocked(w http.ResponseWriter, next *policy.State, key types.ServiceIdentityKey, update types.LeasePolicyUpdate) bool {
	if update.BPS == nil {
		return true
	}
	if *update.BPS < 0 {
		utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidRequest, "bps must be non-negative")
		return false
	}
	if next.IdentityBPS == nil {
		next.IdentityBPS = make(map[types.ServiceIdentityKey]int64)
	}
	next.IdentityBPS[key] = *update.BPS
	return true
}

func (api *RelayAPI) persistPolicyLocked(w http.ResponseWriter, next policy.State) bool {
	if err := utils.WriteJSONFile(api.policyStatePath, policyState(next), 0o600); err != nil {
		log.Error().Err(err).Str("path", api.policyStatePath).Msg("persist relay policy state")
		utils.WriteAPIError(w, http.StatusInternalServerError, types.APIErrorCodeInternal, "policy could not be persisted")
		return false
	}
	if err := api.commitPolicy(next); err != nil {
		log.Error().Err(err).Msg("apply saved relay policy")
		utils.WriteAPIError(w, http.StatusInternalServerError, types.APIErrorCodeInternal, "saved policy could not be applied")
		return false
	}
	return true
}

func (api *RelayAPI) servePolicy(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimSuffix(strings.TrimSpace(r.URL.Path), "/")
	if !api.authenticatedAdmin(r) {
		utils.WriteAPIError(w, http.StatusUnauthorized, types.APIErrorCodeUnauthorized, "unauthorized")
		return
	}
	settings, update, proceed := api.routePolicyRequest(w, r, path)
	if !proceed {
		return
	}
	api.policyWriteMu.Lock()
	defer api.policyWriteMu.Unlock()
	next := api.policies.Snapshot()
	var applied bool
	if path == types.PathPolicy {
		applied = api.applyPolicySettingsLocked(w, &next, settings)
	} else {
		applied = api.applyLeasePolicyUpdateLocked(w, &next, update)
	}
	if !applied {
		return
	}
	if !api.persistPolicyLocked(w, next) {
		return
	}
	if path == types.PathPolicy {
		utils.WriteAPIData(w, http.StatusOK, policySettings(next))
	} else {
		utils.WriteAPIData(w, http.StatusOK, map[string]any{})
	}
}

func (api *RelayAPI) handleAdminLogin(w http.ResponseWriter, r *http.Request) {
	req, ok := utils.DecodeJSONRequestAs[types.AdminAuthLoginRequest](w, r, controlBodyLimit, utils.InvalidRequestError(errors.New("invalid request body")))
	if !ok {
		return
	}
	if !api.tokenAllowed(req.Token) {
		utils.WriteAPIError(w, http.StatusUnauthorized, types.APIErrorCodeUnauthorized, "invalid admin token")
		return
	}
	utils.WriteAPIData(w, http.StatusOK, types.AdminAuthLoginResponse{
		AccessToken: api.adminToken,
	})
}

func (api *RelayAPI) authenticatedAdmin(r *http.Request) bool {
	return api.tokenAllowed(adminAccessToken(r))
}

func adminAccessToken(r *http.Request) string {
	parts := strings.Fields(r.Header.Get("Authorization"))
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

func (api *RelayAPI) tokenAllowed(raw string) bool {
	token := strings.TrimSpace(raw)
	expected := strings.TrimSpace(api.adminToken)
	if token == "" || expected == "" || len(token) != len(expected) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(token), []byte(expected)) == 1
}

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
