package agent

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/sdk/appauth"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func (s *controlHandler) serveStatus(w http.ResponseWriter, r *http.Request, creds controlCredentials) {
	if !utils.RequireMethod(w, r, http.MethodGet) {
		return
	}
	status := s.manager.Snapshot()
	if creds.walletOK {
		status.WalletAddress = creds.wallet
	}
	if !creds.bearer {
		for i := range status.Tunnels {
			tunnel := &status.Tunnels[i]
			tunnel.Allow, tunnel.EmailList = nil, nil
			tunnel.EmailConfig, tunnel.AuthSMTPPasswordSet = appauth.EmailConfig{}, false
			if tunnel.Provider == appauth.ProviderEmail && tunnel.AuthProviderError != "" {
				tunnel.AuthProviderError = "smtp server check failed"
			}
		}
	}
	utils.WriteAPIData(w, http.StatusOK, status)
}

func (s *controlHandler) serveShutdown(w http.ResponseWriter, r *http.Request) {
	if !utils.RequireMethod(w, r, http.MethodPost) {
		return
	}
	utils.WriteAPIData(w, http.StatusAccepted, map[string]bool{"accepted": true})
	if s.shutdown != nil {
		go s.shutdown()
	}
}

func (s *controlHandler) serveAddTunnel(w http.ResponseWriter, r *http.Request) {
	if !utils.RequireMethod(w, r, http.MethodPost) {
		return
	}
	req, ok := utils.DecodeJSONRequest[AgentTunnelRequest](w, r, controlRequestBodyLimit)
	if !ok {
		return
	}
	if err := s.manager.AddTunnel(req); err != nil {
		utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidRequest, err.Error())
		return
	}
	utils.WriteAPIData(w, http.StatusAccepted, map[string]bool{"accepted": true})
}

func (s *controlHandler) serveTunnel(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, types.PathAgentTunnelsPrefix)
	tunnelID, action, ok := strings.Cut(rest, "/")
	tunnelID, err := url.PathUnescape(tunnelID)
	if err != nil || strings.TrimSpace(tunnelID) == "" {
		utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidRequest, "invalid tunnel id")
		return
	}
	if !ok {
		s.serveTunnelConfig(w, r, tunnelID)
		return
	}
	if action != "relays" {
		utils.WriteAPIError(w, http.StatusNotFound, types.APIErrorCodeNotFound, "not found")
		return
	}
	s.serveTunnelRelays(w, r, tunnelID)
}

func (s *controlHandler) serveTunnelRelays(w http.ResponseWriter, r *http.Request, tunnelID string) {
	if r.Method != http.MethodPost && r.Method != http.MethodDelete {
		utils.MethodNotAllowedError().Write(w)
		return
	}
	req, ok := utils.DecodeJSONRequest[AgentRelayRequest](w, r, controlRequestBodyLimit)
	if !ok {
		return
	}
	var err error
	if r.Method == http.MethodPost {
		err = s.manager.ConnectRelay(tunnelID, req.RelayURL)
	} else {
		err = s.manager.DisconnectRelay(tunnelID, req.RelayURL)
	}
	if err != nil {
		utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidRequest, err.Error())
		return
	}
	utils.WriteAPIData(w, http.StatusAccepted, map[string]bool{"accepted": true})
}

func (s *controlHandler) serveTunnelConfig(w http.ResponseWriter, r *http.Request, tunnelID string) {
	switch r.Method {
	case http.MethodDelete:
		if err := s.manager.DeleteTunnel(tunnelID); err != nil {
			utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidRequest, err.Error())
			return
		}
	case http.MethodPatch:
		req, ok := utils.DecodeJSONRequest[AgentTunnelUpdateRequest](w, r, controlRequestBodyLimit)
		if !ok {
			return
		}
		if err := s.manager.UpdateTunnel(tunnelID, req); err != nil {
			utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidRequest, err.Error())
			return
		}
	default:
		utils.MethodNotAllowedError().Write(w)
		return
	}
	utils.WriteAPIData(w, http.StatusAccepted, map[string]bool{"accepted": true})
}

func (s *controlHandler) serveAuthChallenge(w http.ResponseWriter, r *http.Request) bool {
	if !utils.RequireMethod(w, r, http.MethodPost) {
		return true
	}
	req, ok := utils.DecodeJSONRequest[types.WalletAuthChallengeRequest](w, r, controlRequestBodyLimit)
	if !ok {
		return true
	}
	resp, err := s.auth.issueChallenge(req, agentAuthDomain(r), agentAuthURI(r, types.PathAgentAuthLogin), time.Now().UTC())
	if err != nil {
		writeAgentWalletAuthError(w, err)
		return true
	}
	utils.WriteAPIData(w, http.StatusCreated, resp)
	return true
}

func (s *controlHandler) serveAuthLogin(w http.ResponseWriter, r *http.Request) bool {
	if !utils.RequireMethod(w, r, http.MethodPost) {
		return true
	}
	req, ok := utils.DecodeJSONRequest[types.WalletAuthLoginRequest](w, r, controlRequestBodyLimit)
	if !ok {
		return true
	}
	token, walletAddress, err := s.auth.login(req, agentAuthDomain(r), time.Now().UTC())
	if err != nil {
		writeAgentWalletAuthError(w, err)
		return true
	}
	http.SetCookie(w, &http.Cookie{
		Name:     agentCookieName,
		Value:    token,
		Path:     types.PathAgentPrefix,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   86400,
	})
	utils.WriteAPIData(w, http.StatusOK, types.WalletAuthLoginResponse{WalletAddress: walletAddress})
	return true
}

func (s *controlHandler) serveAuthLogout(w http.ResponseWriter, r *http.Request) bool {
	if !utils.RequireMethod(w, r, http.MethodPost) {
		return true
	}
	if cookie, err := r.Cookie(agentCookieName); err == nil && cookie.Value != "" {
		s.auth.deleteSession(cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     agentCookieName,
		Value:    "",
		Path:     types.PathAgentPrefix,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
	utils.WriteAPIData(w, http.StatusOK, map[string]any{})
	return true
}

func (s *controlHandler) serveAuthStatus(w http.ResponseWriter, r *http.Request) bool {
	if !utils.RequireMethod(w, r, http.MethodGet) {
		return true
	}
	walletAddress, authenticated := s.authenticatedWallet(r)
	utils.WriteAPIData(w, http.StatusOK, types.WalletAuthStatusResponse{
		Authenticated: authenticated,
		WalletAddress: walletAddress,
	})
	return true
}

func writeAgentWalletAuthError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, identity.ErrSIWEUnauthorized):
		utils.WriteAPIError(w, http.StatusForbidden, types.APIErrorCodeUnauthorized, err.Error())
	case errors.Is(err, identity.ErrSIWEChallengeNotFound), errors.Is(err, identity.ErrSIWEChallengeExpired), errors.Is(err, identity.ErrSIWEChallengeInvalid), errors.Is(err, identity.ErrSIWEInvalidSignature):
		utils.WriteAPIError(w, http.StatusUnauthorized, types.APIErrorCodeUnauthorized, err.Error())
	default:
		utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidRequest, err.Error())
	}
}
