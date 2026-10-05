package main

import (
	"cmp"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog/log"

	portaltunnel "github.com/gosuda/portal-tunnel/v2"
	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/installer"
	"github.com/gosuda/portal-tunnel/v2/cmd/relay-server/policy"
	"github.com/gosuda/portal-tunnel/v2/portal"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

//go:embed dist/*
var embeddedDistFS embed.FS

const (
	controlBodyLimit = 1 << 16

	// Relay-local wire paths. Deliberately not in types/paths.go: no Go
	// package outside cmd/relay-server needs them.
	pathReputationVote    = types.PathAPIPrefix + "/reputation/vote"
	reputationFilename    = "reputation.json"
	reputationVoterCookie = "portal_voter"
)

type RelayAPI struct {
	server               *portal.Server
	access               *policy.Access
	ingress              *policy.Ingress
	adminToken           string
	policyStatePath      string
	frontendFS           fs.FS
	frontendCache        sync.Map
	frontendCacheEnabled bool
	// reputation is the relay-local vote ledger owned by the policy
	// package and persisted in reputation.json.
	reputation *policy.ReputationStore
	// policyWriteMu serializes mutations including the state-file write;
	// policyMu guards in-memory state only, so readers never block on disk I/O.
	policyWriteMu      sync.Mutex
	policyMu           sync.RWMutex
	udpPolicy          types.PolicyPortSettings
	tcpPortPolicy      types.PolicyPortSettings
	landingPageEnabled bool
}

func NewRelayAPI(server *portal.Server, access *policy.Access, ingress *policy.Ingress, policyStatePath, adminToken, frontendDir string, initialSettings types.PolicySettings) (*RelayAPI, error) {
	if server == nil {
		return nil, errors.New("relay api requires portal server")
	}
	if access == nil {
		return nil, errors.New("relay api requires access state")
	}
	policyStatePath = strings.TrimSpace(policyStatePath)
	if policyStatePath == "" {
		return nil, errors.New("relay api requires policy state path")
	}
	frontendFS, err := resolveFrontendFS(frontendDir)
	if err != nil {
		return nil, err
	}
	reputationStore, err := policy.NewReputationStore(filepath.Join(filepath.Dir(policyStatePath), reputationFilename))
	if err != nil {
		return nil, err
	}

	api := &RelayAPI{
		server:               server,
		access:               access,
		ingress:              ingress,
		adminToken:           strings.TrimSpace(adminToken),
		policyStatePath:      policyStatePath,
		frontendFS:           frontendFS,
		frontendCacheEnabled: strings.TrimSpace(frontendDir) == "",
		reputation:           reputationStore,
		udpPolicy:            initialSettings.UDP,
		tcpPortPolicy:        initialSettings.TCPPort,
		landingPageEnabled:   initialSettings.LandingPageEnabled,
	}
	if mode := strings.TrimSpace(initialSettings.ApprovalMode); mode != "" {
		initialAccess := api.access.Snapshot()
		if err := initialAccess.SetMode(policy.Mode(mode)); err != nil {
			return nil, err
		}
		api.commitAccess(initialAccess)
	}
	if err := api.server.SetTransportPolicy(api.udpPolicy.Enabled, api.udpPolicy.MaxLeases, api.tcpPortPolicy.Enabled, api.tcpPortPolicy.MaxLeases); err != nil {
		return nil, err
	}
	if err := api.loadPolicyState(); err != nil {
		return nil, err
	}
	return api, nil
}

func (api *RelayAPI) Handler() *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc(types.PathLLMs, func(w http.ResponseWriter, r *http.Request) {
		serveLLMs(w, r, api.server.PortalURL())
	})
	mux.HandleFunc(types.PathAdmin, api.serveAdmin)
	mux.HandleFunc(types.PathAdminPrefix, api.serveAdmin)
	mux.HandleFunc(types.PathPolicy, api.servePolicy)
	mux.HandleFunc(types.PathPolicyPrefix, api.servePolicy)
	mux.HandleFunc(types.PathState, api.servePublicState)
	mux.HandleFunc(pathReputationVote, api.serveReputationVote)
	mux.HandleFunc(types.PathInstallShell, func(w http.ResponseWriter, r *http.Request) {
		serveInstallScript(w, r, api.server.PortalURL(), false)
	})
	mux.HandleFunc(types.PathInstallPowerShell, func(w http.ResponseWriter, r *http.Request) {
		serveInstallScript(w, r, api.server.PortalURL(), true)
	})
	mux.HandleFunc(types.PathInstallBinPrefix, serveInstallBinary)
	mux.HandleFunc("/", api.serveFrontend)

	return mux
}

func (api *RelayAPI) servePublicState(w http.ResponseWriter, r *http.Request) {
	if !utils.RequireMethod(w, r, http.MethodGet) {
		return
	}

	leases := api.server.PublicLeases()
	api.policyMu.RLock()
	landingPageEnabled := api.landingPageEnabled
	api.policyMu.RUnlock()
	voterCookieID := ""
	if cookie, err := r.Cookie(reputationVoterCookie); err == nil {
		voterCookieID = cookie.Value
	}
	utils.WriteAPIData(w, http.StatusOK, publicStateResponse{
		PublicStateResponse: types.PublicStateResponse{Leases: leases, LandingPageEnabled: landingPageEnabled},
		Reputation:          api.reputation.Summaries(api.reputation.ViewerHashFor(voterCookieID), publicIdentityLeases(leases, api.server)),
	})
}

type publicStateResponse struct {
	types.PublicStateResponse
	Reputation []policy.ReputationSummary `json:"reputation,omitempty"`
}

func (api *RelayAPI) loadPolicyState() error {
	var payload struct {
		persistedPolicyState
		LegacyBannedIPs json.RawMessage `json:"banned_ips"`
	}
	loaded, err := utils.ReadJSONFileIfExists(api.policyStatePath, &payload)
	if err != nil {
		return err
	}
	if !loaded {
		return nil
	}
	if err := payload.apply(api); err != nil {
		return err
	}
	if len(payload.LegacyBannedIPs) > 0 {
		if err := api.savePolicyState(api.policyState(api.access.Snapshot())); err != nil {
			return fmt.Errorf("remove legacy IP bans: %w", err)
		}
		log.Info().Msg("removed legacy IP bans; durable blocking now uses identity keys")
	}
	return nil
}

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
		promhttp.Handler().ServeHTTP(w, r)
		return
	default:
		http.NotFound(w, r)
	}
}

func (api *RelayAPI) servePolicy(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimSuffix(strings.TrimSpace(r.URL.Path), "/")
	path = cmp.Or(path, types.PathRoot)

	if !api.authenticatedAdmin(r) {
		utils.WriteAPIError(w, http.StatusUnauthorized, types.APIErrorCodeUnauthorized, "unauthorized")
		return
	}

	invalidRequestBody := utils.InvalidRequestError(errors.New("invalid request body"))

	switch path {
	case types.PathPolicy:
		switch r.Method {
		case http.MethodGet:
			api.policyMu.RLock()
			settings := api.policySettings()
			api.policyMu.RUnlock()
			utils.WriteAPIData(w, http.StatusOK, settings)
		case http.MethodPost:
			req, ok := utils.DecodeJSONRequestAs[types.PolicySettings](w, r, controlBodyLimit, invalidRequestBody)
			if !ok {
				return
			}
			api.policyWriteMu.Lock()
			defer api.policyWriteMu.Unlock()
			api.policyMu.Lock()
			proposedAccess := api.access.Snapshot()
			previous := api.policyState(proposedAccess)
			if !api.applyPolicySettings(w, req, &proposedAccess) {
				api.policyMu.Unlock()
				return
			}
			payload := api.policyState(proposedAccess)
			api.policyMu.Unlock()
			if !api.persistPolicyState(w, previous, payload) {
				return
			}
			api.commitAccess(proposedAccess)
			api.policyMu.RLock()
			settings := api.policySettings()
			api.policyMu.RUnlock()
			utils.WriteAPIData(w, http.StatusOK, settings)
		default:
			w.Header().Set("Allow", http.MethodGet+", "+http.MethodPost)
			utils.MethodNotAllowedError().Write(w)
		}
	case types.PathPolicyState:
		if !utils.RequireMethod(w, r, http.MethodGet) {
			return
		}
		api.policyMu.RLock()
		settings := api.policySettings()
		api.policyMu.RUnlock()
		leases := api.policyLeases()
		utils.WriteAPIData(w, http.StatusOK, types.PolicyStateResponse{
			Policy: settings,
			Leases: leases,
		})
	case types.PathPolicyLeases:
		if !utils.RequireMethod(w, r, http.MethodPost) {
			return
		}
		req, ok := utils.DecodeJSONRequestAs[types.LeasePolicyUpdate](w, r, controlBodyLimit, invalidRequestBody)
		if !ok {
			return
		}
		identityKey, ok := normalizePolicyIdentityKey(w, req.IdentityKey)
		if !ok {
			return
		}
		api.policyWriteMu.Lock()
		defer api.policyWriteMu.Unlock()
		api.policyMu.Lock()
		proposedAccess := api.access.Snapshot()
		previous := api.policyState(proposedAccess)
		if !api.applyLeasePolicyUpdate(w, identityKey, req, &proposedAccess) {
			api.policyMu.Unlock()
			return
		}
		payload := api.policyState(proposedAccess)
		api.policyMu.Unlock()
		if !api.persistPolicyState(w, previous, payload) {
			return
		}
		api.commitAccess(proposedAccess)
		utils.WriteAPIData(w, http.StatusOK, map[string]any{})
	default:
		http.NotFound(w, r)
	}
}

// policyLeases decorates the portal's lease listing with the relay's access
// decisions for the admin surface.
func (api *RelayAPI) policyLeases() []types.PolicyLease {
	leases := api.server.PolicyLeases()
	access := api.access.Snapshot()
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

// commitAccess publishes a saved transaction before acknowledging the admin
// request. policyWriteMu serializes writers; registration may publish the same
// snapshot concurrently, and Portal rejects any older revision on arrival.
func (api *RelayAPI) commitAccess(next policy.AccessState) {
	previous := api.access.Snapshot()
	committed := api.access.Commit(next)
	keys := make(map[types.ServiceIdentityKey]struct{})
	for _, state := range []policy.AccessState{previous, committed} {
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
		api.server.SetServiceIdentityRoutable(key, committed.Routable(key), committed.Revision())
	}
}

func (api *RelayAPI) policySettings() types.PolicySettings {
	return types.PolicySettings{
		ApprovalMode:       string(api.access.Snapshot().Mode()),
		LandingPageEnabled: api.landingPageEnabled,
		UDP:                api.udpPolicy,
		TCPPort:            api.tcpPortPolicy,
	}
}

func (api *RelayAPI) applyPolicySettings(w http.ResponseWriter, req types.PolicySettings, access *policy.AccessState) bool {
	if req.UDP.MaxLeases < 0 || req.TCPPort.MaxLeases < 0 {
		utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidRequest, "max_leases must be non-negative")
		return false
	}
	mode := policy.Mode(strings.TrimSpace(req.ApprovalMode))
	if mode != policy.ModeAuto && mode != policy.ModeManual {
		utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidMode, "approval_mode must be 'auto' or 'manual'")
		return false
	}
	if err := api.server.SetTransportPolicy(req.UDP.Enabled, req.UDP.MaxLeases, req.TCPPort.Enabled, req.TCPPort.MaxLeases); err != nil {
		utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidRequest, err.Error())
		return false
	}
	_ = access.SetMode(mode)
	api.udpPolicy = req.UDP
	api.tcpPortPolicy = req.TCPPort
	api.landingPageEnabled = req.LandingPageEnabled
	return true
}

// normalizePolicyIdentityKey canonicalizes an untrusted admin-supplied
// identity key into the typed runtime form. It reuses the same normalization
// as the policy.json loader, so malformed keys are rejected with an HTTP 400
// instead of being trusted as-is.
func normalizePolicyIdentityKey(w http.ResponseWriter, raw string) (types.ServiceIdentityKey, bool) {
	key, err := types.ParseServiceIdentityKey(raw)
	if err != nil {
		utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidRequest, "invalid identity")
		return types.ServiceIdentityKey{}, false
	}
	return key, true
}
func (api *RelayAPI) applyLeasePolicyUpdate(w http.ResponseWriter, identityKey types.ServiceIdentityKey, req types.LeasePolicyUpdate, access *policy.AccessState) bool {
	if req.IsBanned == nil && req.IsApproved == nil && req.IsDenied == nil && req.BPS == nil {
		utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidRequest, "lease policy update is empty")
		return false
	}
	if req.IsApproved != nil && req.IsDenied != nil && *req.IsApproved && *req.IsDenied {
		utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidRequest, "lease cannot be approved and denied")
		return false
	}
	if req.BPS != nil {
		if *req.BPS < 0 {
			utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidRequest, "bps must be non-negative")
			return false
		}
		if *req.BPS == 0 {
			api.server.BPSManager().DeleteIdentityBPS(identityKey)
		} else {
			api.server.BPSManager().SetIdentityBPS(identityKey, *req.BPS)
		}
	}
	if req.IsBanned != nil {
		if *req.IsBanned {
			access.Ban(identityKey)
		} else {
			access.Unban(identityKey)
		}
	}
	if req.IsDenied != nil {
		if *req.IsDenied {
			access.Deny(identityKey)
		} else {
			access.Undeny(identityKey)
		}
	}
	if req.IsApproved != nil {
		if *req.IsApproved {
			access.Approve(identityKey)
		} else {
			access.Revoke(identityKey)
		}
	}
	return true
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

func (api *RelayAPI) persistPolicyState(w http.ResponseWriter, previous, payload persistedPolicyState) bool {
	if err := api.savePolicyState(payload); err != nil {
		log.Error().Err(err).Str("path", api.policyStatePath).Msg("persist relay policy state")
		api.policyMu.Lock()
		rollbackErr := previous.apply(api)
		api.policyMu.Unlock()
		if rollbackErr != nil {
			log.Error().Err(rollbackErr).Msg("roll back relay policy state")
		}
		utils.WriteAPIError(w, http.StatusInternalServerError, types.APIErrorCodeInternal, "policy could not be persisted")
		return false
	}
	return true
}

func (api *RelayAPI) savePolicyState(payload persistedPolicyState) error {
	return utils.WriteJSONFile(api.policyStatePath, payload, 0o600)
}

func (api *RelayAPI) policyState(access policy.AccessState) persistedPolicyState {
	udpEnabled, udpMaxLeases := api.udpPolicy.Enabled, api.udpPolicy.MaxLeases
	tcpPortEnabled, tcpPortMaxLeases := api.tcpPortPolicy.Enabled, api.tcpPortPolicy.MaxLeases
	landingPageEnabled := api.landingPageEnabled
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
	return persistedPolicyState{
		ApprovalMode:         string(access.Mode()),
		ApprovedIdentityKeys: approvedStrings,
		DeniedIdentityKeys:   deniedStrings,
		BannedIdentityKeys:   bannedStrings,
		IdentityBPS:          api.server.BPSManager().IdentityBPSLimits(),
		UDPEnabled:           &udpEnabled,
		UDPMaxLeases:         &udpMaxLeases,
		TCPPortEnabled:       &tcpPortEnabled,
		TCPPortMaxLeases:     &tcpPortMaxLeases,
		LandingPageEnabled:   &landingPageEnabled,
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
	LandingPageEnabled   *bool            `json:"landing_page_enabled,omitempty"`
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

func (s persistedPolicyState) apply(api *RelayAPI) error {
	access := api.access.Snapshot()
	mode := access.Mode()
	if rawMode := strings.TrimSpace(s.ApprovalMode); rawMode != "" {
		parsed := policy.Mode(rawMode)
		if parsed != policy.ModeAuto && parsed != policy.ModeManual {
			return fmt.Errorf("invalid approval mode: %q", rawMode)
		}
		mode = parsed
	}
	approvedKeys, err := parseIdentityKeyList("approved_identity_keys", s.ApprovedIdentityKeys)
	if err != nil {
		return err
	}
	deniedKeys, err := parseIdentityKeyList("denied_identity_keys", s.DeniedIdentityKeys)
	if err != nil {
		return err
	}
	bannedKeys, err := parseIdentityKeyList("banned_identity_keys", s.BannedIdentityKeys)
	if err != nil {
		return err
	}
	identityBPS, err := parseIdentityBPSLimits(s.IdentityBPS)
	if err != nil {
		return err
	}
	udpPolicy := applyOptionalPolicy(s.UDPEnabled, s.UDPMaxLeases, api.udpPolicy)
	tcpPortPolicy := applyOptionalPolicy(s.TCPPortEnabled, s.TCPPortMaxLeases, api.tcpPortPolicy)
	if err := api.server.SetTransportPolicy(udpPolicy.Enabled, udpPolicy.MaxLeases, tcpPortPolicy.Enabled, tcpPortPolicy.MaxLeases); err != nil {
		return err
	}
	_ = access.SetMode(mode)
	access.SetDecisions(approvedKeys, deniedKeys)
	access.SetBannedKeys(bannedKeys)
	api.server.BPSManager().SetServiceIdentityBPSLimits(identityBPS)
	api.udpPolicy = udpPolicy
	api.tcpPortPolicy = tcpPortPolicy
	if s.LandingPageEnabled != nil {
		api.landingPageEnabled = *s.LandingPageEnabled
	}
	api.commitAccess(access)
	return nil
}

// parseIdentityKeyList converts persisted identity strings at the policy
// boundary so AccessState only receives typed runtime keys.
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

// parseIdentityBPSLimits converts persisted identity_bps keys at the policy
// boundary. Two
// spellings sharing a canonical key must agree on the limit: conflicting
// values abort load instead of letting map iteration order pick a winner,
// while identical duplicates collapse silently.
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

func serveInstallBinary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", http.MethodGet+", "+http.MethodHead)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	slug := strings.Trim(strings.TrimPrefix(r.URL.Path, types.PathInstallBinPrefix), "/")
	checksumRequest := strings.HasSuffix(slug, ".sha256")
	if checksumRequest {
		slug = strings.TrimSuffix(slug, ".sha256")
	}

	filename, ok := installer.AssetFilename(slug)
	if !ok {
		http.NotFound(w, r)
		return
	}
	requestedVersion := strings.TrimSpace(r.URL.Query().Get("version"))
	if requestedVersion != "" && requestedVersion != types.ReleaseVersion {
		http.Error(w, "artifact version does not match this relay", http.StatusConflict)
		return
	}
	data, err := embeddedDistFS.ReadFile("dist/tunnel/" + filename)
	if err != nil {
		releasePath := "/latest/download/"
		if requestedVersion != "" {
			releasePath = "/download/" + url.PathEscape(types.ReleaseVersion) + "/"
		}
		redirectURL := types.OfficialReleaseBaseURL + releasePath + filename
		if checksumRequest {
			redirectURL += ".sha256"
		}
		http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
		return
	}
	sum := sha256.Sum256(data)
	checksumHex := hex.EncodeToString(sum[:])

	if checksumRequest {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if r.Method == http.MethodGet {
			_, _ = fmt.Fprintf(w, "%s  %s\n", checksumHex, filename)
		}
		return
	}

	contentType := "application/octet-stream"
	if strings.HasSuffix(filename, ".wasm") {
		contentType = "application/wasm"
	} else if strings.HasSuffix(filename, ".js") {
		contentType = "text/javascript; charset=utf-8"
	}
	w.Header().Set("Content-Type", contentType)
	if contentType == "application/octet-stream" {
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	}
	if requestedVersion == types.ReleaseVersion {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		w.Header().Set("Cache-Control", "no-cache")
	}
	w.Header().Set("ETag", `"`+checksumHex+`"`)
	w.Header().Set("X-Checksum-Sha256", checksumHex)
	if r.Method == http.MethodGet {
		_, _ = w.Write(data)
	}
}

func serveInstallScript(w http.ResponseWriter, r *http.Request, portalURL string, isWindows bool) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", http.MethodGet+", "+http.MethodHead)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	script, filename, contentType, err := installer.RelayScript(portalURL, isWindows)
	if err != nil {
		http.Error(w, "failed to render install script", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("inline; filename=%q", filename))
	if r.Method == http.MethodGet {
		_, _ = w.Write([]byte(script))
	}
}

func serveLLMs(w http.ResponseWriter, r *http.Request, portalURL string) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", http.MethodGet+", "+http.MethodHead)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if r.Method == http.MethodHead {
		return
	}

	body := strings.ReplaceAll(string(portaltunnel.LLMsTXT), "%s", portalURL)
	_, _ = w.Write([]byte(body))
}

type reputationVoteRequest struct {
	Hostname string `json:"hostname"`
	Vote     string `json:"vote"`
}

// serveReputationVote is admission -> decode -> store op. Admission runs
// before decoding, matching the pre-auth routes: rate-limited sources pay
// no parse cost, and the body bound applies inside decode.
func (api *RelayAPI) serveReputationVote(w http.ResponseWriter, r *http.Request) {
	if !utils.RequireMethod(w, r, http.MethodPost) {
		return
	}
	sourceAddr := api.ingress.SourceAddr(r)
	if retry := api.reputation.AllowVote(sourceAddr); retry > 0 {
		policy.WriteRetryAfter(w, retry, "vote request budget exhausted")
		return
	}
	req, ok := utils.DecodeJSONRequestAs[reputationVoteRequest](w, r, 1<<12, utils.InvalidRequestError(errors.New("invalid request body")))
	if !ok {
		return
	}
	hostname := utils.NormalizeHostname(req.Hostname)
	if hostname == "" {
		utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidRequest, "hostname is required")
		return
	}
	vote := strings.TrimSpace(req.Vote)
	if vote != policy.VoteUp && vote != policy.VoteDown {
		utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidRequest, "vote must be 'up' or 'down'")
		return
	}
	identity := ""
	for _, lease := range publicIdentityLeases(api.server.PublicLeases(), api.server) {
		if utils.NormalizeHostname(lease.Hostname) == hostname || utils.NormalizeHostname(lease.CanonicalHostname) == hostname {
			identity = lease.IdentityKey
			break
		}
	}
	voterCookieID := ""
	if cookie, err := r.Cookie(reputationVoterCookie); err == nil {
		voterCookieID = cookie.Value
	}
	summary, minted, err := api.reputation.CastVote(hostname, identity, vote, voterCookieID, sourceAddr)
	if err != nil {
		switch {
		case errors.Is(err, policy.ErrReputationCapacity):
			utils.WriteAPIError(w, http.StatusTooManyRequests, types.APIErrorCodeRateLimited, "vote capacity reached")
		case errors.Is(err, policy.ErrReputationUnknownHostname):
			utils.WriteAPIError(w, http.StatusNotFound, types.APIErrorCodeInvalidRequest, "hostname is not in the public directory")
		default:
			log.Error().Err(err).Msg("persist reputation vote")
			utils.WriteAPIError(w, http.StatusInternalServerError, types.APIErrorCodeInternal, "vote failed")
		}
		return
	}
	if minted != "" {
		http.SetCookie(w, &http.Cookie{
			Name:     reputationVoterCookie,
			Value:    minted,
			Path:     types.PathAPIPrefix,
			MaxAge:   int((10 * 365 * 24 * time.Hour).Seconds()),
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			Secure:   r.TLS != nil,
		})
	}
	utils.WriteAPIData(w, http.StatusOK, summary)
}

func publicIdentityLeases(public []types.Lease, server *portal.Server) []types.PolicyLease {
	known := make(map[string]bool)
	for _, lease := range public {
		known[utils.NormalizeHostname(lease.CanonicalHostname)] = true
	}
	leases := make([]types.PolicyLease, 0)
	for _, lease := range server.PolicyLeases() {
		if known[utils.NormalizeHostname(lease.CanonicalHostname)] && lease.IdentityKey != "" {
			leases = append(leases, lease)
		}
	}
	return leases
}
