package main

import (
	"cmp"
	"crypto/subtle"
	"errors"
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
