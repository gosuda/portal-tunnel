package main

import (
	"crypto/subtle"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/policy"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

const (
	cookieName     = "portal_admin"
	adminBodyLimit = 1 << 16
)

type adminAuth struct {
	sessions  map[string]time.Time
	secretKey string
	mu        sync.RWMutex
}

func newAdminAuth(secretKey string) (*adminAuth, error) {
	secretKey = strings.TrimSpace(secretKey)
	if secretKey == "" {
		return nil, errors.New("admin secret key is required")
	}

	return &adminAuth{
		secretKey: secretKey,
		sessions:  make(map[string]time.Time),
	}, nil
}

func (a *adminAuth) AuthEnabled() bool {
	return a != nil && a.secretKey != ""
}

func (a *adminAuth) ValidateKey(key string) bool {
	if !a.AuthEnabled() {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a.secretKey), []byte(key)) == 1
}

func (a *adminAuth) CreateSession() (string, error) {
	token := utils.RandomID("")

	a.mu.Lock()
	defer a.mu.Unlock()
	a.sessions[token] = time.Now().Add(24 * time.Hour)
	a.cleanupExpiredSessionsLocked()
	return token, nil
}

func (a *adminAuth) ValidateSession(token string) bool {
	if token == "" {
		return false
	}

	a.mu.RLock()
	defer a.mu.RUnlock()

	expiry, ok := a.sessions[token]
	return ok && time.Now().Before(expiry)
}

func (a *adminAuth) DeleteSession(token string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.sessions, token)
}

func (a *adminAuth) cleanupExpiredSessionsLocked() {
	now := time.Now()
	for token, expiry := range a.sessions {
		if now.After(expiry) {
			delete(a.sessions, token)
		}
	}
}

func loadAdminState(path string, runtime *policy.Runtime) (persistedAdminState, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return persistedAdminState{}, nil
	}

	var payload persistedAdminState
	if _, err := utils.ReadJSONFileIfExists(path, &payload); err != nil {
		return persistedAdminState{}, err
	}
	if err := payload.apply(runtime); err != nil {
		return persistedAdminState{}, err
	}
	return payload, nil
}

func (f *Frontend) serveAdmin(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimSuffix(strings.TrimSpace(r.URL.Path), "/")
	if path == "" {
		path = types.PathRoot
	}

	switch path {
	case types.PathAdmin:
		if r.Method == http.MethodGet {
			f.ServeAppStatic(w, r, "")
			return
		}
		http.NotFound(w, r)
		return
	case types.PathAdminLogin:
		if r.Method == http.MethodGet {
			f.ServeAppStatic(w, r, "")
			return
		}
		if r.Method == http.MethodPost {
			f.handleLogin(w, r)
			return
		}
		utils.MethodNotAllowedError().Write(w)
		return
	case types.PathAdminLogout:
		if !utils.RequireMethod(w, r, http.MethodPost) {
			return
		}
		if cookie, err := r.Cookie(cookieName); err == nil && cookie.Value != "" {
			f.auth.DeleteSession(cookie.Value)
		}
		http.SetCookie(w, &http.Cookie{
			Name:     cookieName,
			Value:    "",
			Path:     types.PathAdmin,
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   -1,
		})
		utils.WriteAPIData(w, http.StatusOK, map[string]any{})
		return
	case types.PathAdminAuthStatus:
		if !utils.RequireMethod(w, r, http.MethodGet) {
			return
		}
		utils.WriteAPIData(w, http.StatusOK, types.AdminAuthStatusResponse{
			Authenticated: f.isAuthenticated(r),
			AuthEnabled:   f.auth.AuthEnabled(),
		})
		return
	}

	if !f.isAuthenticated(r) {
		utils.WriteAPIError(w, http.StatusUnauthorized, types.APIErrorCodeUnauthorized, "unauthorized")
		return
	}

	runtime := f.server.PolicyRuntime()
	methodNotAllowed := utils.MethodNotAllowedError()
	invalidRequestBody := utils.InvalidRequestError(errors.New("invalid request body"))

	switch path {
	case types.PathAdminSnapshot:
		if !utils.RequireMethod(w, r, http.MethodGet) {
			return
		}
		leases := f.server.AdminLeases()
		f.attachAutomaticAdminThumbnails(leases)
		utils.WriteAPIData(w, http.StatusOK, types.AdminSnapshotResponse{
			ApprovalMode:       string(runtime.Approver().Mode()),
			LandingPageEnabled: f.isLandingPageEnabled(),
			Leases:             leases,
			UDP: types.AdminUDPSettingsResponse{
				Enabled:   runtime.IsUDPEnabled(),
				MaxLeases: runtime.UDPMaxLeases(),
			},
			TCPPort: types.AdminTCPPortSettingsResponse{
				Enabled:   runtime.IsTCPPortEnabled(),
				MaxLeases: runtime.TCPPortMaxLeases(),
			},
		})
	case types.PathAdminLandingPage:
		if !utils.RequireMethod(w, r, http.MethodPost) {
			return
		}
		req, ok := utils.DecodeJSONRequestAs[types.AdminLandingPageSettingsRequest](w, r, adminBodyLimit, invalidRequestBody)
		if !ok {
			return
		}
		f.setLandingPageEnabled(req.Enabled)
		saveAdminState(f.adminSettingsPath, runtime, f.isLandingPageEnabled())
		utils.WriteAPIData(w, http.StatusOK, types.AdminLandingPageSettingsResponse{
			Enabled: f.isLandingPageEnabled(),
		})
	case types.PathAdminUDP:
		f.handlePortSettings(w, r, invalidRequestBody, runtime,
			runtime.SetUDPPolicy,
			func() any {
				return types.AdminUDPSettingsResponse{Enabled: runtime.IsUDPEnabled(), MaxLeases: runtime.UDPMaxLeases()}
			},
		)
	case types.PathAdminTCPPort:
		f.handlePortSettings(w, r, invalidRequestBody, runtime,
			runtime.SetTCPPortPolicy,
			func() any {
				return types.AdminTCPPortSettingsResponse{Enabled: runtime.IsTCPPortEnabled(), MaxLeases: runtime.TCPPortMaxLeases()}
			},
		)
	case types.PathAdminApproval:
		if !utils.RequireMethod(w, r, http.MethodPost) {
			return
		}
		req, ok := utils.DecodeJSONRequestAs[types.AdminApprovalModeRequest](w, r, adminBodyLimit, invalidRequestBody)
		if !ok {
			return
		}
		if err := runtime.Approver().SetMode(policy.Mode(strings.TrimSpace(req.Mode))); err != nil {
			utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidMode, "invalid mode (must be 'auto' or 'manual')")
			return
		}
		saveAdminState(f.adminSettingsPath, runtime, f.isLandingPageEnabled())
		utils.WriteAPIData(w, http.StatusOK, types.AdminApprovalModeResponse{
			ApprovalMode: string(runtime.Approver().Mode()),
		})
	default:
		switch {
		case strings.HasPrefix(path, types.PathAdminLeasesPrefix):
			rest := strings.TrimPrefix(path, types.PathAdminLeasesPrefix)
			parts := strings.Split(rest, "/")
			if len(parts) != 3 {
				http.NotFound(w, r)
				return
			}

			name, err := utils.DecodeBase64URLString(parts[0])
			if err != nil {
				utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidRequest, "invalid identity")
				return
			}
			address, err := utils.DecodeBase64URLString(parts[1])
			if err != nil {
				utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidAddress, "invalid address")
				return
			}
			identity, err := utils.NormalizeIdentity(types.Identity{
				Name:    name,
				Address: address,
			})
			if err != nil {
				utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidRequest, "invalid identity")
				return
			}
			identityKey := identity.Key()
			approver := runtime.Approver()

			type identityAction struct {
				post   func() bool // returns true if response was already written (error path)
				delete func()
			}
			actions := map[string]identityAction{
				"ban": {
					post:   func() bool { runtime.BanIdentity(identityKey); return false },
					delete: func() { runtime.UnbanIdentity(identityKey) },
				},
				"bps": {
					post: func() bool {
						req, ok := utils.DecodeJSONRequestAs[types.AdminBPSRequest](w, r, adminBodyLimit, invalidRequestBody)
						if !ok {
							return true
						}
						if req.BPS <= 0 {
							utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidRequest, "bps must be greater than zero")
							return true
						}
						runtime.BPSManager().SetIdentityBPS(identityKey, req.BPS)
						return false
					},
					delete: func() { runtime.BPSManager().DeleteIdentityBPS(identityKey) },
				},
				"approve": {
					post:   func() bool { approver.Approve(identityKey); approver.Undeny(identityKey); return false },
					delete: func() { approver.Revoke(identityKey) },
				},
				"deny": {
					post:   func() bool { approver.Deny(identityKey); return false },
					delete: func() { approver.Undeny(identityKey) },
				},
			}

			action, ok := actions[parts[2]]
			if !ok {
				http.NotFound(w, r)
				return
			}
			switch r.Method {
			case http.MethodPost:
				if action.post() {
					return
				}
			case http.MethodDelete:
				action.delete()
			default:
				methodNotAllowed.Write(w)
				return
			}
			saveAdminState(f.adminSettingsPath, runtime, f.isLandingPageEnabled())
			utils.WriteAPIData(w, http.StatusOK, map[string]any{})
		case strings.HasPrefix(path, types.PathAdminIPsPrefix):
			if !strings.HasSuffix(path, "/ban") {
				http.NotFound(w, r)
				return
			}

			rawIP := strings.TrimSuffix(strings.TrimPrefix(path, types.PathAdminIPsPrefix), "/ban")
			rawIP = strings.Trim(rawIP, "/")
			if net.ParseIP(rawIP) == nil {
				utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidIP, "invalid IP address")
				return
			}

			filter := runtime.IPFilter()
			switch r.Method {
			case http.MethodPost:
				filter.BanIP(rawIP)
			case http.MethodDelete:
				filter.UnbanIP(rawIP)
			default:
				methodNotAllowed.Write(w)
				return
			}
			saveAdminState(f.adminSettingsPath, runtime, f.isLandingPageEnabled())
			utils.WriteAPIData(w, http.StatusOK, map[string]any{})
		default:
			http.NotFound(w, r)
		}
	}
}

type portSettingsRequest struct {
	Enabled   bool `json:"enabled"`
	MaxLeases int  `json:"max_leases"`
}

func (f *Frontend) handlePortSettings(
	w http.ResponseWriter,
	r *http.Request,
	invalidBody utils.APIErrorResponse,
	runtime *policy.Runtime,
	setPolicy func(bool, int),
	buildResponse func() any,
) {
	if !utils.RequireMethod(w, r, http.MethodPost) {
		return
	}
	req, ok := utils.DecodeJSONRequestAs[portSettingsRequest](w, r, 1<<16, invalidBody)
	if !ok {
		return
	}
	if req.MaxLeases < 0 {
		utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidRequest, "max_leases must be non-negative")
		return
	}
	setPolicy(req.Enabled, req.MaxLeases)
	saveAdminState(f.adminSettingsPath, runtime, f.isLandingPageEnabled())
	utils.WriteAPIData(w, http.StatusOK, buildResponse())
}

func (f *Frontend) handleLogin(w http.ResponseWriter, r *http.Request) {
	if !utils.RequireMethod(w, r, http.MethodPost) {
		return
	}
	if !f.auth.AuthEnabled() {
		utils.WriteAPIError(w, http.StatusServiceUnavailable, types.APIErrorCodeAuthDisabled, "admin authentication is not configured")
		return
	}

	req, ok := utils.DecodeJSONRequestAs[types.AdminLoginRequest](w, r, adminBodyLimit, utils.InvalidRequestError(errors.New("invalid request body")))
	if !ok {
		return
	}
	if !f.auth.ValidateKey(req.Key) {
		utils.WriteAPIError(w, http.StatusUnauthorized, types.APIErrorCodeInvalidKey, "Invalid key")
		return
	}
	token, err := f.auth.CreateSession()
	if err != nil {
		utils.WriteAPIError(w, http.StatusInternalServerError, types.APIErrorCodeSessionCreateFailed, "failed to create admin session")
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    token,
		Path:     types.PathAdmin,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   86400,
	})
	utils.WriteAPIData(w, http.StatusOK, types.AdminLoginResponse{Success: true})
}

func (f *Frontend) isAuthenticated(r *http.Request) bool {
	if !f.auth.AuthEnabled() {
		return false
	}
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		return false
	}
	return f.auth.ValidateSession(cookie.Value)
}

func saveAdminState(path string, runtime *policy.Runtime, landingPageEnabled bool) {
	path = strings.TrimSpace(path)
	if path == "" {
		return
	}

	approver := runtime.Approver()
	udpEnabled := runtime.IsUDPEnabled()
	udpMaxLeases := runtime.UDPMaxLeases()
	tcpPortEnabled := runtime.IsTCPPortEnabled()
	tcpPortMaxLeases := runtime.TCPPortMaxLeases()
	payload := persistedAdminState{
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
		LandingPageEnabled:   &landingPageEnabled,
	}
	_ = utils.WriteJSONFile(path, payload, 0o600)
}

type persistedAdminState struct {
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
	LandingPageEnabled   *bool            `json:"landing_page_enabled,omitempty"`
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

func (s persistedAdminState) apply(runtime *policy.Runtime) error {
	if runtime == nil {
		return nil
	}
	if mode := strings.TrimSpace(s.ApprovalMode); mode != "" {
		if err := runtime.Approver().SetMode(policy.Mode(mode)); err != nil {
			return err
		}
	}
	runtime.Approver().SetDecisions(
		utils.NormalizeIdentityKeys(s.ApprovedIdentityKeys),
		utils.NormalizeIdentityKeys(s.DeniedIdentityKeys),
	)
	runtime.SetBannedIdentityKeys(utils.NormalizeIdentityKeys(s.BannedIdentityKeys))
	runtime.IPFilter().SetBannedIPs(s.BannedIPs)
	runtime.BPSManager().SetIdentityBPSLimits(utils.NormalizeIdentityKeyBPS(s.IdentityBPS))
	applyOptionalPolicy(s.UDPEnabled, s.UDPMaxLeases, runtime.IsUDPEnabled, runtime.UDPMaxLeases, runtime.SetUDPPolicy)
	applyOptionalPolicy(s.TCPPortEnabled, s.TCPPortMaxLeases, runtime.IsTCPPortEnabled, runtime.TCPPortMaxLeases, runtime.SetTCPPortPolicy)
	return nil
}
