package main

import (
	"cmp"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"mime"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	portaltunnel "github.com/gosuda/portal-tunnel/v2"
	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/installer"
	"github.com/gosuda/portal-tunnel/v2/cmd/relay-server/policy"
	"github.com/gosuda/portal-tunnel/v2/portal"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

var (
	errRelayAPIRequiresPortalServer    = errors.New("relay api requires portal server")
	errRelayAPIRequiresPolicyStore     = errors.New("relay api requires policy store")
	errRelayAPIRequiresPolicyStatePath = errors.New("relay api requires policy state path")
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
	commentAuthorCookie   = "portal_comment_author"
)

type RelayAPI struct {
	server               *portal.Server
	metrics              *relayMetrics
	policies             *policy.Store
	ingress              *policy.Ingress
	adminToken           string
	policyStatePath      string
	frontendFS           fs.FS
	frontendCache        sync.Map
	frontendCacheEnabled bool
	// reputation owns app votes, comments, and comment votes in reputation.json.
	reputation *policy.ReputationStore
	// policyWriteMu serializes candidate editing, persistence, and publication.
	policyWriteMu sync.Mutex
}

func NewRelayAPI(server *portal.Server, policies *policy.Store, ingress *policy.Ingress, policyStatePath, adminToken, frontendDir string, initialSettings types.PolicySettings) (*RelayAPI, error) {
	if server == nil {
		return nil, errRelayAPIRequiresPortalServer
	}
	if policies == nil {
		return nil, errRelayAPIRequiresPolicyStore
	}
	policyStatePath = strings.TrimSpace(policyStatePath)
	if policyStatePath == "" {
		return nil, errRelayAPIRequiresPolicyStatePath
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
		metrics:              newRelayMetrics(server),
		policies:             policies,
		ingress:              ingress,
		adminToken:           strings.TrimSpace(adminToken),
		policyStatePath:      policyStatePath,
		frontendFS:           frontendFS,
		frontendCacheEnabled: strings.TrimSpace(frontendDir) == "",
		reputation:           reputationStore,
	}
	initial := api.policies.Snapshot()
	initial.UDP, initial.TCPPort = initialSettings.UDP, initialSettings.TCPPort
	if strings.TrimSpace(initialSettings.ApprovalMode) != "" {
		mode, err := policy.ParseMode(initialSettings.ApprovalMode)
		if err != nil {
			return nil, err
		}
		initial.SetMode(mode)
	}
	if err := api.loadPolicyState(initial); err != nil {
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
	mux.HandleFunc(pathReputationVote, api.serveVote)
	mux.HandleFunc(types.PathComments, api.serveComments)
	mux.HandleFunc(types.PathCommentsVote, api.serveVote)
	mux.HandleFunc(types.PathCommentsDelete, api.deleteComment)
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
	voterCookieID := ""
	if cookie, err := r.Cookie(reputationVoterCookie); err == nil {
		voterCookieID = cookie.Value
	}
	utils.WriteAPIData(w, http.StatusOK, publicStateResponse{
		PublicStateResponse: types.PublicStateResponse{Leases: leases},
		Reputation:          api.reputation.Summaries(api.reputation.ViewerHashFor(voterCookieID), publicIdentityLeases(leases, api.server)),
	})
}

type publicStateResponse struct {
	types.PublicStateResponse
	Reputation []policy.ReputationSummary `json:"reputation,omitempty"`
}

func (api *RelayAPI) loadPolicyState(initial policy.State) error {
	var payload struct {
		persistedPolicyState
		LegacyBannedIPs json.RawMessage `json:"banned_ips"`
	}
	loaded, err := utils.ReadJSONFileIfExists(api.policyStatePath, &payload)
	if err != nil {
		return err
	}
	if loaded {
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
		// Nonpositive limits in older files mean explicit unlimited, distinct
		// from an absent entry inheriting the configured relay default.
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

func (api *RelayAPI) servePolicy(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimSuffix(strings.TrimSpace(r.URL.Path), "/")
	if !api.authenticatedAdmin(r) {
		utils.WriteAPIError(w, http.StatusUnauthorized, types.APIErrorCodeUnauthorized, "unauthorized")
		return
	}
	var settings types.PolicySettings
	var update types.LeasePolicyUpdate
	invalidBody := utils.InvalidRequestError(errors.New("invalid request body"))
	switch path {
	case types.PathPolicy:
		if r.Method == http.MethodGet {
			utils.WriteAPIData(w, http.StatusOK, policySettings(api.policies.Snapshot()))
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodGet+", "+http.MethodPost)
			utils.MethodNotAllowedError().Write(w)
			return
		}
		req, ok := utils.DecodeJSONRequestAs[types.PolicySettings](w, r, controlBodyLimit, invalidBody)
		if !ok {
			return
		}
		settings = req
	case types.PathPolicyState:
		if !utils.RequireMethod(w, r, http.MethodGet) {
			return
		}
		state := api.policies.Snapshot()
		utils.WriteAPIData(w, http.StatusOK, types.PolicyStateResponse{
			Policy: policySettings(state), Leases: api.policyLeases(state),
		})
		return
	case types.PathPolicyLeases:
		if !utils.RequireMethod(w, r, http.MethodPost) {
			return
		}
		req, ok := utils.DecodeJSONRequestAs[types.LeasePolicyUpdate](w, r, controlBodyLimit, invalidBody)
		if !ok {
			return
		}
		update = req
	default:
		http.NotFound(w, r)
		return
	}
	api.policyWriteMu.Lock()
	defer api.policyWriteMu.Unlock()
	next := api.policies.Snapshot()
	if path == types.PathPolicy {
		mode, err := policy.ParseMode(settings.ApprovalMode)
		if err != nil {
			utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidMode, "approval_mode must be 'auto' or 'manual'")
			return
		}
		if err := api.server.ValidateTransportPolicy(settings.UDP.Enabled, settings.UDP.MaxLeases, settings.TCPPort.Enabled, settings.TCPPort.MaxLeases); err != nil {
			utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidRequest, err.Error())
			return
		}
		next.SetMode(mode)
		next.UDP, next.TCPPort = settings.UDP, settings.TCPPort
	} else {
		key, err := types.ParseServiceIdentityKey(update.IdentityKey)
		if err != nil {
			utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidRequest, "invalid identity")
			return
		}
		if update.IsBanned == nil && update.IsApproved == nil && update.IsDenied == nil && update.BPS == nil && !update.ResetBPS {
			utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidRequest, "lease policy update is empty")
			return
		}
		if update.ResetBPS && update.BPS != nil {
			utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidRequest, "bps and reset_bps are mutually exclusive")
			return
		}
		if update.IsApproved != nil && update.IsDenied != nil && *update.IsApproved && *update.IsDenied {
			utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidRequest, "lease cannot be approved and denied")
			return
		}
		if update.ResetBPS {
			delete(next.IdentityBPS, key)
		}
		if update.BPS != nil {
			if *update.BPS < 0 {
				utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidRequest, "bps must be non-negative")
				return
			}
			if next.IdentityBPS == nil {
				next.IdentityBPS = make(map[types.ServiceIdentityKey]int64)
			}
			next.IdentityBPS[key] = *update.BPS
		}
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
	if err := utils.WriteJSONFile(api.policyStatePath, policyState(next), 0o600); err != nil {
		log.Error().Err(err).Str("path", api.policyStatePath).Msg("persist relay policy state")
		utils.WriteAPIError(w, http.StatusInternalServerError, types.APIErrorCodeInternal, "policy could not be persisted")
		return
	}
	if err := api.commitPolicy(next); err != nil {
		log.Error().Err(err).Msg("apply saved relay policy")
		utils.WriteAPIError(w, http.StatusInternalServerError, types.APIErrorCodeInternal, "saved policy could not be applied")
		return
	}
	if path == types.PathPolicy {
		utils.WriteAPIData(w, http.StatusOK, policySettings(next))
	} else {
		utils.WriteAPIData(w, http.StatusOK, map[string]any{})
	}
}

// policyLeases decorates the portal's lease listing with the relay's access
// decisions for the admin surface.
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

// commitPolicy applies saved operator policy and publishes access decisions
// before acknowledging the admin request. policyWriteMu serializes writers;
// registration may publish the same snapshot concurrently, and Portal rejects
// any older revision on arrival.
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

// parseIdentityKeyList converts persisted identity strings at the policy
// boundary so policy.State only receives typed runtime keys.
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

// serveVote keeps both public vote URLs on one admission, mutation, and cookie
// path. The route determines the target; a missing comment ID cannot vote on an app.
func (api *RelayAPI) serveVote(w http.ResponseWriter, r *http.Request) {
	if !utils.RequireMethod(w, r, http.MethodPost) {
		return
	}
	if !requireJSONContentType(w, r) {
		return
	}
	commentVote := r.URL.Path == types.PathCommentsVote
	sourceAddr := api.ingress.SourceAddr(r)
	if retry := api.reputation.AllowVote(sourceAddr, commentVote); retry > 0 {
		policy.WriteRetryAfter(w, retry, "vote request budget exhausted")
		return
	}
	req, ok := utils.DecodeJSONRequestAs[types.VoteRequest](w, r, 1<<12, utils.InvalidRequestError(errors.New("invalid request body")))
	if !ok {
		return
	}
	if commentVote {
		req.ID = strings.TrimSpace(req.ID)
		if req.ID == "" {
			utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidRequest, "comment id is required")
			return
		}
	} else {
		req.ID = ""
	}
	hostname := utils.NormalizeHostname(req.Hostname)
	if !commentVote && hostname == "" {
		utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidRequest, "hostname is required")
		return
	}
	identity := api.publicIdentityFor(hostname)
	if commentVote && identity == "" {
		utils.WriteAPIError(w, http.StatusNotFound, types.APIErrorCodeInvalidRequest, "This app is no longer in the public directory.")
		return
	}
	voterCookieID := ""
	if cookie, err := r.Cookie(reputationVoterCookie); err == nil {
		voterCookieID = cookie.Value
	}
	summary, minted, err := api.reputation.Vote(identity, req.ID, req.Vote, voterCookieID, sourceAddr)
	if err != nil {
		switch {
		case errors.Is(err, policy.ErrVoteChoice):
			utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidRequest, err.Error())
		case errors.Is(err, policy.ErrReputationCapacity):
			utils.WriteAPIError(w, http.StatusTooManyRequests, types.APIErrorCodeRateLimited, "vote capacity reached")
		case errors.Is(err, policy.ErrReputationUnknownHostname):
			utils.WriteAPIError(w, http.StatusNotFound, types.APIErrorCodeInvalidRequest, "hostname is not in the public directory")
		case errors.Is(err, policy.ErrCommentNotFound):
			utils.WriteAPIError(w, http.StatusNotFound, types.APIErrorCodeInvalidRequest, "comment not found")
		case errors.Is(err, policy.ErrCommentCapacity):
			utils.WriteAPIError(w, http.StatusConflict, types.APIErrorCodeInvalidRequest, "comment vote storage limit reached")
		default:
			log.Error().Err(err).Msg("persist vote")
			utils.WriteAPIError(w, http.StatusInternalServerError, types.APIErrorCodeInternal, "could not save vote")
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
	if commentVote {
		viewerHash := api.reputation.ViewerHashFor(cmp.Or(minted, voterCookieID))
		utils.WriteAPIData(w, http.StatusOK, types.CommentListResponse{
			Comments: api.reputation.ListComments(identity, viewerHash, commentAuthorHash(r)),
		})
	} else {
		utils.WriteAPIData(w, http.StatusOK, policy.ReputationSummary{
			Hostname:    hostname,
			Comments:    api.reputation.CommentsCount(identity),
			VoteSummary: summary,
		})
	}
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

func commentAuthorHash(r *http.Request) string {
	cookie, err := r.Cookie(commentAuthorCookie)
	if err != nil {
		return ""
	}
	token, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil || len(token) != 32 {
		return ""
	}
	hash := sha256.Sum256(token)
	return hex.EncodeToString(hash[:])
}

func requireJSONContentType(w http.ResponseWriter, r *http.Request) bool {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		utils.WriteAPIError(w, http.StatusUnsupportedMediaType, types.APIErrorCodeInvalidRequest, "application/json is required")
		return false
	}
	return true
}

func (api *RelayAPI) serveComments(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var hostname, text string
	switch r.Method {
	case http.MethodGet:
		hostname = utils.NormalizeHostname(r.URL.Query().Get("hostname"))
	case http.MethodPost:
		if retry := api.reputation.AllowCommentPost(api.ingress.SourceAddr(r)); retry > 0 {
			policy.WriteRetryAfter(w, retry, "Please wait before posting another comment.")
			return
		}
		if !requireJSONContentType(w, r) {
			return
		}
		req, ok := utils.DecodeJSONRequestAs[types.CreateCommentRequest](w, r, 1<<15, utils.InvalidRequestError(errors.New("invalid comment request")))
		if !ok {
			return
		}
		hostname, text = utils.NormalizeHostname(req.Hostname), req.Text
	default:
		w.Header().Set("Allow", http.MethodGet+", "+http.MethodPost)
		utils.MethodNotAllowedError().Write(w)
		return
	}
	identity := api.publicIdentityFor(hostname)
	if identity == "" {
		utils.WriteAPIError(w, http.StatusNotFound, types.APIErrorCodeInvalidRequest, "This app is no longer in the public directory.")
		return
	}
	voterCookieID := ""
	if cookie, err := r.Cookie(reputationVoterCookie); err == nil {
		voterCookieID = cookie.Value
	}
	viewerHash := api.reputation.ViewerHashFor(voterCookieID)
	authorHash := commentAuthorHash(r)

	if r.Method == http.MethodGet {
		utils.WriteAPIData(w, http.StatusOK, types.CommentListResponse{Comments: api.reputation.ListComments(identity, viewerHash, authorHash)})
		return
	}
	minted := ""
	if authorHash == "" {
		token := make([]byte, 32)
		if _, err := rand.Read(token); err != nil {
			utils.WriteAPIError(w, http.StatusInternalServerError, types.APIErrorCodeInternal, "Could not create comment identity.")
			return
		}
		minted = base64.RawURLEncoding.EncodeToString(token)
		hash := sha256.Sum256(token)
		authorHash = hex.EncodeToString(hash[:])
	}
	comments, err := api.reputation.AddComment(identity, text, viewerHash, authorHash)
	if err != nil {
		switch {
		case errors.Is(err, policy.ErrCommentInvalid):
			utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidRequest, err.Error())
		case errors.Is(err, policy.ErrCommentCapacity):
			utils.WriteAPIError(w, http.StatusConflict, types.APIErrorCodeInvalidRequest, "Comment storage is full. Contact the relay administrator.")
		default:
			log.Error().Err(err).Msg("persist comment")
			utils.WriteAPIError(w, http.StatusInternalServerError, types.APIErrorCodeInternal, "Could not save your comment.")
		}
		return
	}
	if minted != "" {
		http.SetCookie(w, &http.Cookie{Name: commentAuthorCookie, Value: minted, Path: types.PathComments, MaxAge: int((10 * 365 * 24 * time.Hour).Seconds()), HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: r.TLS != nil})
	}
	utils.WriteAPIData(w, http.StatusCreated, types.CommentListResponse{Comments: comments})
}

func (api *RelayAPI) deleteComment(w http.ResponseWriter, r *http.Request) {
	if !utils.RequireMethod(w, r, http.MethodPost) {
		return
	}
	if !requireJSONContentType(w, r) {
		return
	}
	req, ok := utils.DecodeJSONRequestAs[types.DeleteCommentRequest](w, r, 1<<12, utils.InvalidRequestError(errors.New("invalid comment deletion request")))
	if !ok {
		return
	}
	identity := api.publicIdentityFor(utils.NormalizeHostname(req.Hostname))
	if identity == "" {
		utils.WriteAPIError(w, http.StatusNotFound, types.APIErrorCodeInvalidRequest, "This app is no longer in the public directory.")
		return
	}
	viewerHash := ""
	if cookie, err := r.Cookie(reputationVoterCookie); err == nil {
		viewerHash = api.reputation.ViewerHashFor(cookie.Value)
	}
	comments, err := api.reputation.DeleteComment(identity, strings.TrimSpace(req.ID), viewerHash, commentAuthorHash(r))
	if err != nil {
		if errors.Is(err, policy.ErrCommentNotFound) {
			utils.WriteAPIError(w, http.StatusNotFound, types.APIErrorCodeInvalidRequest, "Comment not found.")
		} else {
			log.Error().Err(err).Msg("delete comment")
			utils.WriteAPIError(w, http.StatusInternalServerError, types.APIErrorCodeInternal, "Could not delete this comment.")
		}
		return
	}
	utils.WriteAPIData(w, http.StatusOK, types.CommentListResponse{Comments: comments})
}

func (api *RelayAPI) publicIdentityFor(hostname string) string {
	if hostname == "" {
		return ""
	}
	for _, lease := range publicIdentityLeases(api.server.PublicLeases(), api.server) {
		if utils.NormalizeHostname(lease.Hostname) == hostname || utils.NormalizeHostname(lease.CanonicalHostname) == hostname {
			return lease.IdentityKey
		}
	}
	return ""
}
