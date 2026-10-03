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
	// reputation owns relay-local service reputation state and its
	// reputation.json file; see reputation.go.
	reputation *ReputationStore
	// policyWriteMu serializes mutations including the state-file write;
	// policyMu guards in-memory state only, so readers never block on disk I/O.
	// udpPolicy/tcpPortPolicy are the canonical operator-configured transport
	// policy; the portal registry only receives pushed enforcement values.
	policyWriteMu      sync.Mutex
	policyMu           sync.RWMutex
	udpPolicy          types.PolicyPortSettings
	tcpPortPolicy      types.PolicyPortSettings
	landingPageEnabled bool
}

func NewRelayAPI(server *portal.Server, access *policy.Access, ingress *policy.Ingress, policyStatePath, adminToken, frontendDir string, initial types.PolicySettings) (*RelayAPI, error) {
	if server == nil {
		return nil, errors.New("relay api requires portal server")
	}
	if access == nil {
		return nil, errors.New("relay api requires access state")
	}
	if ingress == nil {
		return nil, errors.New("relay api requires ingress")
	}
	policyStatePath = strings.TrimSpace(policyStatePath)
	if policyStatePath == "" {
		return nil, errors.New("relay api requires policy state path")
	}
	frontendFS, err := resolveFrontendFS(frontendDir)
	if err != nil {
		return nil, err
	}
	reputationStore, err := newReputationStore(filepath.Join(filepath.Dir(policyStatePath), reputationFilename))
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
		udpPolicy:            initial.UDP,
		tcpPortPolicy:        initial.TCPPort,
		landingPageEnabled:   initial.LandingPageEnabled,
	}
	if mode := policy.Mode(strings.TrimSpace(initial.ApprovalMode)); mode != "" {
		if err := access.SetMode(mode); err != nil {
			return nil, err
		}
	}
	if err := server.SetTransportPolicy(api.udpPolicy, api.tcpPortPolicy); err != nil {
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
	utils.WriteAPIData(w, http.StatusOK, publicStateResponse{
		PublicStateResponse: types.PublicStateResponse{Leases: leases, LandingPageEnabled: landingPageEnabled},
		Reputation:          api.reputation.summaries(api.reputation.viewerHashFor(voterCookieID(r)), publicIdentityLeases(leases, api.server)),
	})
}

type publicStateResponse struct {
	types.PublicStateResponse
	Reputation []reputationSummary `json:"reputation,omitempty"`
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
		if err := api.savePolicyState(api.policyState()); err != nil {
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
			previous := api.policyState()
			if !api.applyPolicySettings(w, req) {
				api.policyMu.Unlock()
				return
			}
			payload := api.policyState()
			settings := api.policySettings()
			api.policyMu.Unlock()
			if !api.persistPolicyState(w, previous, payload) {
				return
			}
			api.pushAccess()
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
		utils.WriteAPIData(w, http.StatusOK, types.PolicyStateResponse{
			Policy: settings,
			Leases: api.policyLeases(),
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
		previous := api.policyState()
		if !api.applyLeasePolicyUpdate(w, identityKey, req) {
			api.policyMu.Unlock()
			return
		}
		payload := api.policyState()
		api.policyMu.Unlock()
		if !api.persistPolicyState(w, previous, payload) {
			return
		}
		api.pushAccess(identityKey)
		utils.WriteAPIData(w, http.StatusOK, map[string]any{})
	default:
		http.NotFound(w, r)
	}
}

// policyLeases decorates the portal's lease listing with the relay's access
// decisions for the admin surface.
func (api *RelayAPI) policyLeases() []types.PolicyLease {
	leases := api.server.PolicyLeases()
	for i := range leases {
		key := leases[i].IdentityKey
		leases[i].IsApproved = api.access.EffectiveApproval(key)
		leases[i].IsBanned = api.access.IsBanned(key)
		leases[i].IsDenied = api.access.IsDenied(key)
	}
	return leases
}

// pushAccess mirrors the relay's current access decisions into the portal
// data path for the named identities, or for every identity the relay knows
// when none are named: its decision lists plus live leases. The portal
// consumes only the resulting routability values.
func (api *RelayAPI) pushAccess(keys ...string) {
	if len(keys) > 0 {
		for _, key := range keys {
			api.access.Publish(key, api.server.SetIdentityRoutable)
		}
		return
	}
	for _, key := range api.access.BannedKeys() {
		api.access.Publish(key, api.server.SetIdentityRoutable)
	}
	for _, key := range api.access.DeniedKeys() {
		api.access.Publish(key, api.server.SetIdentityRoutable)
	}
	for _, key := range api.access.ApprovedKeys() {
		api.access.Publish(key, api.server.SetIdentityRoutable)
	}
	for _, lease := range api.server.PolicyLeases() {
		api.access.Publish(lease.IdentityKey, api.server.SetIdentityRoutable)
	}
}

func (api *RelayAPI) policySettings() types.PolicySettings {
	return types.PolicySettings{
		ApprovalMode:       string(api.access.Mode()),
		LandingPageEnabled: api.landingPageEnabled,
		UDP:                api.udpPolicy,
		TCPPort:            api.tcpPortPolicy,
	}
}

func (api *RelayAPI) applyPolicySettings(w http.ResponseWriter, req types.PolicySettings) bool {
	if req.UDP.MaxLeases < 0 || req.TCPPort.MaxLeases < 0 {
		utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidRequest, "max_leases must be non-negative")
		return false
	}
	mode := policy.Mode(strings.TrimSpace(req.ApprovalMode))
	previousMode := api.access.Mode()
	if err := api.access.SetMode(mode); err != nil {
		utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidMode, "approval_mode must be 'auto' or 'manual'")
		return false
	}
	if err := api.server.SetTransportPolicy(req.UDP, req.TCPPort); err != nil {
		// A rejected request must leave nothing applied: the mode change is
		// rolled back so a 400 never partially mutates the policy.
		_ = api.access.SetMode(previousMode)
		utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidRequest, err.Error())
		return false
	}
	api.udpPolicy = req.UDP
	api.tcpPortPolicy = req.TCPPort
	api.landingPageEnabled = req.LandingPageEnabled
	return true
}

// normalizePolicyIdentityKey canonicalizes an untrusted admin-supplied
// identity key into the runtime key form (lowercase name:address, as built
// by types.Identity.Key). It reuses the same types.ParseIdentityKey rule the
// policy.json loader applies, so malformed keys are rejected with an HTTP 400
// instead of being trusted as-is.
func normalizePolicyIdentityKey(w http.ResponseWriter, raw string) (string, bool) {
	key, err := types.ParseIdentityKey(raw)
	if err != nil {
		utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidRequest, "invalid identity")
		return "", false
	}
	return key, true
}
func (api *RelayAPI) applyLeasePolicyUpdate(w http.ResponseWriter, identityKey string, req types.LeasePolicyUpdate) bool {
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
			api.access.Ban(identityKey)
		} else {
			api.access.Unban(identityKey)
		}
	}
	if req.IsDenied != nil {
		if *req.IsDenied {
			api.access.Deny(identityKey)
		} else {
			api.access.Undeny(identityKey)
		}
	}
	if req.IsApproved != nil {
		if *req.IsApproved {
			api.access.Approve(identityKey)
		} else {
			api.access.Revoke(identityKey)
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

func (api *RelayAPI) policyState() persistedPolicyState {
	udpEnabled := api.udpPolicy.Enabled
	udpMaxLeases := api.udpPolicy.MaxLeases
	tcpPortEnabled := api.tcpPortPolicy.Enabled
	tcpPortMaxLeases := api.tcpPortPolicy.MaxLeases
	landingPageEnabled := api.landingPageEnabled
	return persistedPolicyState{
		ApprovalMode:         string(api.access.Mode()),
		ApprovedIdentityKeys: api.access.ApprovedKeys(),
		DeniedIdentityKeys:   api.access.DeniedKeys(),
		BannedIdentityKeys:   api.access.BannedKeys(),
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

func (s persistedPolicyState) apply(api *RelayAPI) error {
	if mode := policy.Mode(strings.TrimSpace(s.ApprovalMode)); mode != "" {
		if err := api.access.SetMode(mode); err != nil {
			return err
		}
	}
	if err := canonicalizeIdentityKeyList("approved_identity_keys", s.ApprovedIdentityKeys); err != nil {
		return err
	}
	if err := canonicalizeIdentityKeyList("denied_identity_keys", s.DeniedIdentityKeys); err != nil {
		return err
	}
	if err := canonicalizeIdentityKeyList("banned_identity_keys", s.BannedIdentityKeys); err != nil {
		return err
	}
	identityBPS, err := canonicalIdentityBPSKeys(s.IdentityBPS)
	if err != nil {
		return err
	}
	api.access.SetDecisions(s.ApprovedIdentityKeys, s.DeniedIdentityKeys)
	api.access.SetBannedKeys(s.BannedIdentityKeys)
	api.server.BPSManager().SetIdentityBPSLimits(identityBPS)

	udp := api.udpPolicy
	if s.UDPEnabled != nil {
		udp.Enabled = *s.UDPEnabled
	}
	if s.UDPMaxLeases != nil {
		udp.MaxLeases = *s.UDPMaxLeases
	}
	tcp := api.tcpPortPolicy
	if s.TCPPortEnabled != nil {
		tcp.Enabled = *s.TCPPortEnabled
	}
	if s.TCPPortMaxLeases != nil {
		tcp.MaxLeases = *s.TCPPortMaxLeases
	}
	if err := api.server.SetTransportPolicy(udp, tcp); err != nil {
		return err
	}
	api.udpPolicy = udp
	api.tcpPortPolicy = tcp
	if s.LandingPageEnabled != nil {
		api.landingPageEnabled = *s.LandingPageEnabled
	}
	api.pushAccess()
	return nil
}

// canonicalizeIdentityKeyList validates every persisted identity key through
// types.ParseIdentityKey, normalizing entries in place so the runtime only
// ever receives canonical lowercase name:address keys. A malformed entry
// aborts with the offending section, index, and value so a corrupt
// policy.json fails startup with a clear message.
func canonicalizeIdentityKeyList(section string, keys []string) error {
	for i, raw := range keys {
		key, err := types.ParseIdentityKey(raw)
		if err != nil {
			return fmt.Errorf("policy.json %s[%d]: %w", section, i, err)
		}
		keys[i] = key
	}
	return nil
}

// canonicalIdentityBPSKeys rebuilds the identity_bps map with canonical keys
// so per-identity limits set under unnormalized spellings still apply. Two
// spellings sharing a canonical key must agree on the limit: conflicting
// values abort load instead of letting map iteration order pick a winner,
// while identical duplicates collapse silently.
func canonicalIdentityBPSKeys(limits map[string]int64) (map[string]int64, error) {
	if limits == nil {
		return nil, nil
	}
	canonical := make(map[string]int64, len(limits))
	for raw, limit := range limits {
		key, err := types.ParseIdentityKey(raw)
		if err != nil {
			return nil, fmt.Errorf("policy.json identity_bps[%q]: %w", raw, err)
		}
		if existing, ok := canonical[key]; ok && existing != limit {
			return nil, fmt.Errorf("policy.json identity_bps[%q]: canonical key %q already set to %d", raw, key, existing)
		}
		canonical[key] = limit
	}
	return canonical, nil
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
