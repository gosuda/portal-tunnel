package main

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/installer"
	"github.com/gosuda/portal-tunnel/v2/portal"
	"github.com/gosuda/portal-tunnel/v2/portal/auth"
	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/portal/policy"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

//go:embed dist/*
var embeddedDistFS embed.FS

const (
	controlBodyLimit = 1 << 16
)

type RelayAPI struct {
	server          *portal.Server
	auth            *auth.WalletAuthenticator
	policyStatePath string
}

func NewRelayAPI(server *portal.Server, identityPath string, adminWallets []string) (*RelayAPI, error) {
	if server == nil {
		return nil, errors.New("relay api requires portal server")
	}
	runtime := server.PolicyRuntime()
	if runtime == nil {
		return nil, errors.New("relay api requires policy runtime")
	}
	policyStatePath := identity.ResolveRelayPolicyPath(identityPath)
	if policyStatePath == "" {
		return nil, errors.New("relay api requires identity path")
	}
	if err := loadPolicyState(policyStatePath, server); err != nil {
		return nil, err
	}
	relayIdentity := server.RelayIdentity()
	allowedWallets := append([]string{relayIdentity.Address}, adminWallets...)
	authenticator, err := auth.NewWalletAuthenticator(auth.WalletAuthConfig{
		AllowedAddresses: allowedWallets,
		Statement:        "Sign in to Portal relay admin",
	})
	if err != nil {
		return nil, err
	}

	api := &RelayAPI{
		server:          server,
		auth:            authenticator,
		policyStatePath: strings.TrimSpace(policyStatePath),
	}
	return api, nil
}

func (api *RelayAPI) Handler() *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("/{$}", func(w http.ResponseWriter, r *http.Request) {
		if !utils.RequireMethod(w, r, http.MethodGet) {
			return
		}
		utils.WriteAPIData(w, http.StatusOK, map[string]any{
			"service": "portal-relay",
			"root":    api.server.RelayIdentity().Name,
		})
	})
	mux.HandleFunc(types.PathAdmin, api.serveAdmin)
	mux.HandleFunc(types.PathAdminPrefix, api.serveAdmin)
	mux.HandleFunc(types.PathPolicy, api.servePolicy)
	mux.HandleFunc(types.PathPolicyPrefix, api.servePolicy)
	mux.HandleFunc(types.PathState, api.servePublicState)
	mux.HandleFunc(types.PathInstallShell, func(w http.ResponseWriter, r *http.Request) {
		serveInstallScript(w, r, api.server.PortalURL(), false)
	})
	mux.HandleFunc(types.PathInstallPowerShell, func(w http.ResponseWriter, r *http.Request) {
		serveInstallScript(w, r, api.server.PortalURL(), true)
	})
	mux.HandleFunc(types.PathInstallBinPrefix, serveInstallBinary)

	return mux
}

func (api *RelayAPI) servePublicState(w http.ResponseWriter, r *http.Request) {
	if !utils.RequireMethod(w, r, http.MethodGet) {
		return
	}

	leases := api.server.PublicLeases()
	utils.WriteAPIData(w, http.StatusOK, types.PublicStateResponse{
		Leases: leases,
	})
}

func loadPolicyState(path string, server *portal.Server) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}

	var payload persistedPolicyState
	loaded, err := utils.ReadJSONFileIfExists(path, &payload)
	if err != nil {
		return err
	}
	if !loaded {
		return nil
	}
	return payload.apply(server)
}

func (api *RelayAPI) serveAdmin(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimSuffix(strings.TrimSpace(r.URL.Path), "/")
	if path == "" {
		path = types.PathRoot
	}

	switch path {
	case types.PathAdmin:
		http.NotFound(w, r)
		return
	case types.PathAdminAuthChallenge:
		if !utils.RequireMethod(w, r, http.MethodPost) {
			return
		}
		api.handleWalletChallenge(w, r)
		return
	case types.PathAdminAuthLogin:
		if !utils.RequireMethod(w, r, http.MethodPost) {
			return
		}
		api.handleWalletLogin(w, r)
		return
	case types.PathAdminLogout:
		if !utils.RequireMethod(w, r, http.MethodPost) {
			return
		}
		api.auth.DeleteSession(adminAccessToken(r))
		utils.WriteAPIData(w, http.StatusOK, map[string]any{})
		return
	case types.PathAdminAuthStatus:
		if !utils.RequireMethod(w, r, http.MethodGet) {
			return
		}
		walletAddress, authenticated := api.authenticatedWallet(r)
		utils.WriteAPIData(w, http.StatusOK, types.WalletAuthStatusResponse{
			Authenticated: authenticated,
			WalletAddress: walletAddress,
		})
		return
	}

	if _, ok := api.authenticatedWallet(r); !ok {
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
	if path == "" {
		path = types.PathRoot
	}

	if _, ok := api.authenticatedWallet(r); !ok {
		utils.WriteAPIError(w, http.StatusUnauthorized, types.APIErrorCodeUnauthorized, "unauthorized")
		return
	}

	runtime := api.server.PolicyRuntime()
	invalidRequestBody := utils.InvalidRequestError(errors.New("invalid request body"))

	switch path {
	case types.PathPolicy:
		switch r.Method {
		case http.MethodGet:
			utils.WriteAPIData(w, http.StatusOK, api.policySettings(runtime))
		case http.MethodPost:
			req, ok := utils.DecodeJSONRequestAs[types.PolicySettings](w, r, controlBodyLimit, invalidRequestBody)
			if !ok {
				return
			}
			if !api.applyPolicySettings(w, runtime, req) {
				return
			}
			utils.WriteAPIData(w, http.StatusOK, api.policySettings(runtime))
		default:
			w.Header().Set("Allow", http.MethodGet+", "+http.MethodPost)
			utils.MethodNotAllowedError().Write(w)
		}
	case types.PathPolicyState:
		if !utils.RequireMethod(w, r, http.MethodGet) {
			return
		}
		leases := api.server.PolicyLeases()
		utils.WriteAPIData(w, http.StatusOK, types.PolicyStateResponse{
			Policy: api.policySettings(runtime),
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
		if !applyLeasePolicyUpdate(w, runtime, identityKey, req) {
			return
		}
		savePolicyState(api.policyStatePath, runtime)
		utils.WriteAPIData(w, http.StatusOK, map[string]any{})
	case types.PathPolicyIPs:
		if !utils.RequireMethod(w, r, http.MethodPost) {
			return
		}
		req, ok := utils.DecodeJSONRequestAs[types.IPPolicyUpdate](w, r, controlBodyLimit, invalidRequestBody)
		if !ok {
			return
		}
		ip := strings.TrimSpace(req.IP)
		if net.ParseIP(ip) == nil {
			utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidIP, "invalid IP address")
			return
		}
		if req.IsBanned {
			runtime.IPFilter().BanIP(ip)
		} else {
			runtime.IPFilter().UnbanIP(ip)
		}
		savePolicyState(api.policyStatePath, runtime)
		utils.WriteAPIData(w, http.StatusOK, map[string]any{})
	default:
		http.NotFound(w, r)
	}
}

func (api *RelayAPI) policySettings(runtime *policy.Runtime) types.PolicySettings {
	return types.PolicySettings{
		ApprovalMode: string(runtime.Approver().Mode()),
		UDP: types.PolicyPortSettings{
			Enabled:   runtime.IsUDPEnabled(),
			MaxLeases: runtime.UDPMaxLeases(),
		},
		TCPPort: types.PolicyPortSettings{
			Enabled:   runtime.IsTCPPortEnabled(),
			MaxLeases: runtime.TCPPortMaxLeases(),
		},
	}
}

func (api *RelayAPI) applyPolicySettings(w http.ResponseWriter, runtime *policy.Runtime, req types.PolicySettings) bool {
	if req.UDP.MaxLeases < 0 || req.TCPPort.MaxLeases < 0 {
		utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidRequest, "max_leases must be non-negative")
		return false
	}
	if err := runtime.Approver().SetMode(policy.Mode(strings.TrimSpace(req.ApprovalMode))); err != nil {
		utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidMode, "approval_mode must be 'auto' or 'manual'")
		return false
	}
	api.server.SetUDPPolicy(req.UDP.Enabled, req.UDP.MaxLeases)
	api.server.SetTCPPortPolicy(req.TCPPort.Enabled, req.TCPPort.MaxLeases)
	savePolicyState(api.policyStatePath, runtime)
	return true
}

func normalizePolicyIdentityKey(w http.ResponseWriter, raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	name, address, ok := strings.Cut(raw, types.IdentityKeySeparator)
	if !ok {
		utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidRequest, "invalid identity")
		return "", false
	}
	normalizedIdentity, err := identity.NormalizeIdentity(types.Identity{Name: name, Address: address})
	if err != nil {
		utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidRequest, "invalid identity")
		return "", false
	}
	return normalizedIdentity.Key(), true
}

func applyLeasePolicyUpdate(w http.ResponseWriter, runtime *policy.Runtime, identityKey string, req types.LeasePolicyUpdate) bool {
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
			runtime.BPSManager().DeleteIdentityBPS(identityKey)
		} else {
			runtime.BPSManager().SetIdentityBPS(identityKey, *req.BPS)
		}
	}
	if req.IsBanned != nil {
		if *req.IsBanned {
			runtime.BanIdentity(identityKey)
		} else {
			runtime.UnbanIdentity(identityKey)
		}
	}
	approver := runtime.Approver()
	if req.IsDenied != nil {
		if *req.IsDenied {
			approver.Deny(identityKey)
			approver.Revoke(identityKey)
		} else {
			approver.Undeny(identityKey)
		}
	}
	if req.IsApproved != nil {
		if *req.IsApproved {
			approver.Approve(identityKey)
			approver.Undeny(identityKey)
		} else {
			approver.Revoke(identityKey)
		}
	}
	return true
}

func (api *RelayAPI) handleWalletChallenge(w http.ResponseWriter, r *http.Request) {
	req, ok := utils.DecodeJSONRequestAs[types.WalletAuthChallengeRequest](w, r, controlBodyLimit, utils.InvalidRequestError(errors.New("invalid request body")))
	if !ok {
		return
	}
	resp, err := api.auth.IssueChallenge(req, adminAuthDomain(r, api.server.RelayIdentity().Name), adminAuthURI(r, types.PathAdminAuthLogin), time.Now().UTC())
	if err != nil {
		writeWalletAuthError(w, err)
		return
	}
	utils.WriteAPIData(w, http.StatusCreated, resp)
}

func (api *RelayAPI) handleWalletLogin(w http.ResponseWriter, r *http.Request) {
	req, ok := utils.DecodeJSONRequestAs[types.WalletAuthLoginRequest](w, r, controlBodyLimit, utils.InvalidRequestError(errors.New("invalid request body")))
	if !ok {
		return
	}
	token, walletAddress, err := api.auth.Login(req, time.Now().UTC())
	if err != nil {
		writeWalletAuthError(w, err)
		return
	}

	utils.WriteAPIData(w, http.StatusOK, types.WalletAuthLoginResponse{
		AccessToken:   token,
		WalletAddress: walletAddress,
	})
}

func (api *RelayAPI) authenticatedWallet(r *http.Request) (string, bool) {
	return api.auth.ValidateSession(adminAccessToken(r))
}

func adminAuthDomain(r *http.Request, fallback string) string {
	domain := strings.TrimSpace(r.Host)
	if domain != "" {
		return domain
	}
	return strings.TrimSpace(fallback)
}

func adminAuthURI(r *http.Request, endpointPath string) string {
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	return (&url.URL{
		Scheme: scheme,
		Host:   adminAuthDomain(r, "localhost"),
		Path:   endpointPath,
	}).String()
}

func adminAccessToken(r *http.Request) string {
	parts := strings.Fields(r.Header.Get("Authorization"))
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

func writeWalletAuthError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, auth.ErrWalletAuthUnauthorized):
		utils.WriteAPIError(w, http.StatusForbidden, types.APIErrorCodeUnauthorized, err.Error())
	case errors.Is(err, auth.ErrWalletAuthChallengeNotFound), errors.Is(err, auth.ErrWalletAuthChallengeExpired), errors.Is(err, auth.ErrWalletAuthInvalidSignature):
		utils.WriteAPIError(w, http.StatusUnauthorized, types.APIErrorCodeUnauthorized, err.Error())
	default:
		utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidRequest, err.Error())
	}
}

func savePolicyState(path string, runtime *policy.Runtime) {
	path = strings.TrimSpace(path)
	if path == "" {
		return
	}

	approver := runtime.Approver()
	udpEnabled := runtime.IsUDPEnabled()
	udpMaxLeases := runtime.UDPMaxLeases()
	tcpPortEnabled := runtime.IsTCPPortEnabled()
	tcpPortMaxLeases := runtime.TCPPortMaxLeases()
	payload := persistedPolicyState{
		ApprovalMode:         string(approver.Mode()),
		ApprovedIdentityKeys: approver.ApprovedKeys(),
		DeniedIdentityKeys:   approver.DeniedKeys(),
		BannedIdentityKeys:   runtime.BannedIdentityKeys(),
		BannedIPs:            runtime.IPFilter().BannedIPs(),
		IdentityBPS:          runtime.BPSManager().IdentityBPSLimits(),
		UDPEnabled:           &udpEnabled,
		UDPMaxLeases:         &udpMaxLeases,
		TCPPortEnabled:       &tcpPortEnabled,
		TCPPortMaxLeases:     &tcpPortMaxLeases,
	}
	_ = utils.WriteJSONFile(path, payload, 0o600)
}

type persistedPolicyState struct {
	ApprovalMode         string           `json:"approval_mode"`
	ApprovedIdentityKeys []string         `json:"approved_identity_keys,omitempty"`
	DeniedIdentityKeys   []string         `json:"denied_identity_keys,omitempty"`
	BannedIdentityKeys   []string         `json:"banned_identity_keys,omitempty"`
	BannedIPs            []string         `json:"banned_ips,omitempty"`
	IdentityBPS          map[string]int64 `json:"identity_bps,omitempty"`
	UDPEnabled           *bool            `json:"udp_enabled,omitempty"`
	UDPMaxLeases         *int             `json:"udp_max_leases,omitempty"`
	TCPPortEnabled       *bool            `json:"tcp_port_enabled,omitempty"`
	TCPPortMaxLeases     *int             `json:"tcp_port_max_leases,omitempty"`
}

func applyOptionalPolicy(enabled *bool, maxLeases *int, getEnabled func() bool, getMax func() int, set func(bool, int)) {
	if enabled == nil && maxLeases == nil {
		return
	}
	e := getEnabled()
	m := getMax()
	if enabled != nil {
		e = *enabled
	}
	if maxLeases != nil {
		m = *maxLeases
	}
	set(e, m)
}

func (s persistedPolicyState) apply(server *portal.Server) error {
	if server == nil {
		return nil
	}
	runtime := server.PolicyRuntime()
	if runtime == nil {
		return nil
	}
	if mode := strings.TrimSpace(s.ApprovalMode); mode != "" {
		if err := runtime.Approver().SetMode(policy.Mode(mode)); err != nil {
			return err
		}
	}
	runtime.Approver().SetDecisions(
		identity.NormalizeIdentityKeys(s.ApprovedIdentityKeys),
		identity.NormalizeIdentityKeys(s.DeniedIdentityKeys),
	)
	runtime.SetBannedIdentityKeys(identity.NormalizeIdentityKeys(s.BannedIdentityKeys))
	runtime.IPFilter().SetBannedIPs(s.BannedIPs)
	runtime.BPSManager().SetIdentityBPSLimits(identity.NormalizeIdentityKeyBPS(s.IdentityBPS))
	applyOptionalPolicy(s.UDPEnabled, s.UDPMaxLeases, runtime.IsUDPEnabled, runtime.UDPMaxLeases, server.SetUDPPolicy)
	applyOptionalPolicy(s.TCPPortEnabled, s.TCPPortMaxLeases, runtime.IsTCPPortEnabled, runtime.TCPPortMaxLeases, server.SetTCPPortPolicy)
	return nil
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
	data, err := embeddedDistFS.ReadFile("dist/tunnel/" + filename)
	if err != nil {
		redirectURL := types.OfficialReleaseBaseURL + "/latest/download/" + filename
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

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
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
