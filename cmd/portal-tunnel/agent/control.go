package agent

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gosuda/portal-tunnel/v2/internal/identity"
	"github.com/gosuda/portal-tunnel/v2/internal/protocol"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

const (
	controlRequestBodyLimit = 8 << 10
	endpointFilename        = "agent-endpoint.json"
	agentCookieName         = "portal_agent"
)

var (
	ErrNotRunning     = errors.New("portal agent is not running")
	controlHTTPClient = utils.NewHTTPClient(utils.WithHTTPTimeout(5 * time.Second))
)

type endpoint struct {
	ControlAddr string `json:"control_addr"`
	Token       string `json:"token"`
}

type controlHandler struct {
	manager  *manager
	token    string
	auth     *identity.WalletAuthenticator
	shutdown func()
}

func (s *controlHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s.serveWalletAuth(w, r) {
		return
	}

	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	bearerAuthenticated := strings.HasPrefix(auth, "Bearer ") && strings.TrimSpace(strings.TrimPrefix(auth, "Bearer ")) == s.token
	walletAddress, walletAuthenticated := s.authenticatedWallet(r)
	allowed := bearerAuthenticated || (walletAuthenticated && r.URL.Path == protocol.PathAgentStatus)
	if !allowed {
		utils.WriteAPIError(w, http.StatusUnauthorized, types.APIErrorCodeUnauthorized, "unauthorized")
		return
	}

	switch {
	case r.URL.Path == protocol.PathAgentStatus:
		if !utils.RequireMethod(w, r, http.MethodGet) {
			return
		}
		status := s.manager.Snapshot()
		if walletAuthenticated {
			status.WalletAddress = walletAddress
		}
		utils.WriteAPIData(w, http.StatusOK, status)
	case r.URL.Path == protocol.PathAgentShutdown:
		if !utils.RequireMethod(w, r, http.MethodPost) {
			return
		}
		utils.WriteAPIData(w, http.StatusAccepted, map[string]bool{"accepted": true})
		if s.shutdown != nil {
			go s.shutdown()
		}
	case r.URL.Path == protocol.PathAgentTunnels:
		if !utils.RequireMethod(w, r, http.MethodPost) {
			return
		}
		req, ok := utils.DecodeJSONRequest[types.AgentTunnelRequest](w, r, controlRequestBodyLimit)
		if !ok {
			return
		}
		if err := s.manager.AddTunnel(req); err != nil {
			utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidRequest, err.Error())
			return
		}
		utils.WriteAPIData(w, http.StatusAccepted, map[string]bool{"accepted": true})
	case strings.HasPrefix(r.URL.Path, protocol.PathAgentTunnelsPrefix):
		rest := strings.TrimPrefix(r.URL.Path, protocol.PathAgentTunnelsPrefix)
		tunnelID, action, ok := strings.Cut(rest, "/")
		tunnelID, err := url.PathUnescape(tunnelID)
		if err != nil || strings.TrimSpace(tunnelID) == "" {
			utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidRequest, "invalid tunnel id")
			return
		}
		if !ok {
			switch r.Method {
			case http.MethodDelete:
				if err := s.manager.DeleteTunnel(tunnelID); err != nil {
					utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidRequest, err.Error())
					return
				}
			case http.MethodPatch:
				req, ok := utils.DecodeJSONRequest[types.AgentTunnelUpdateRequest](w, r, controlRequestBodyLimit)
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
			return
		}

		switch action {
		case "relays":
			switch r.Method {
			case http.MethodPost:
			case http.MethodDelete:
			default:
				utils.MethodNotAllowedError().Write(w)
				return
			}

			req, ok := utils.DecodeJSONRequest[types.AgentRelayRequest](w, r, controlRequestBodyLimit)
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
		default:
			utils.WriteAPIError(w, http.StatusNotFound, types.APIErrorCodeNotFound, "not found")
		}
	default:
		utils.WriteAPIError(w, http.StatusNotFound, types.APIErrorCodeNotFound, "not found")
	}
}

func (s *controlHandler) serveWalletAuth(w http.ResponseWriter, r *http.Request) bool {
	switch r.URL.Path {
	case protocol.PathAgentAuthChallenge:
		if !utils.RequireMethod(w, r, http.MethodPost) {
			return true
		}
		req, ok := utils.DecodeJSONRequest[protocol.WalletAuthChallengeRequest](w, r, controlRequestBodyLimit)
		if !ok {
			return true
		}
		resp, err := s.auth.IssueChallenge(req, agentAuthDomain(r), agentAuthURI(r, protocol.PathAgentAuthLogin), time.Now().UTC())
		if err != nil {
			writeAgentWalletAuthError(w, err)
			return true
		}
		utils.WriteAPIData(w, http.StatusCreated, resp)
		return true
	case protocol.PathAgentAuthLogin:
		if !utils.RequireMethod(w, r, http.MethodPost) {
			return true
		}
		req, ok := utils.DecodeJSONRequest[protocol.WalletAuthLoginRequest](w, r, controlRequestBodyLimit)
		if !ok {
			return true
		}
		token, walletAddress, err := s.auth.Login(req, time.Now().UTC())
		if err != nil {
			writeAgentWalletAuthError(w, err)
			return true
		}
		http.SetCookie(w, &http.Cookie{
			Name:     agentCookieName,
			Value:    token,
			Path:     protocol.PathAgentPrefix,
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   86400,
		})
		utils.WriteAPIData(w, http.StatusOK, protocol.WalletAuthLoginResponse{WalletAddress: walletAddress})
		return true
	case protocol.PathAgentAuthLogout:
		if !utils.RequireMethod(w, r, http.MethodPost) {
			return true
		}
		if cookie, err := r.Cookie(agentCookieName); err == nil && cookie.Value != "" {
			s.auth.DeleteSession(cookie.Value)
		}
		http.SetCookie(w, &http.Cookie{
			Name:     agentCookieName,
			Value:    "",
			Path:     protocol.PathAgentPrefix,
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   -1,
		})
		utils.WriteAPIData(w, http.StatusOK, map[string]any{})
		return true
	case protocol.PathAgentAuthStatus:
		if !utils.RequireMethod(w, r, http.MethodGet) {
			return true
		}
		walletAddress, authenticated := s.authenticatedWallet(r)
		utils.WriteAPIData(w, http.StatusOK, protocol.WalletAuthStatusResponse{
			Authenticated: authenticated,
			WalletAddress: walletAddress,
		})
		return true
	default:
		return false
	}
}

func (s *controlHandler) authenticatedWallet(r *http.Request) (string, bool) {
	if s == nil || s.auth == nil {
		return "", false
	}
	cookie, err := r.Cookie(agentCookieName)
	if err != nil {
		return "", false
	}
	return s.auth.ValidateSession(cookie.Value)
}

func agentAuthDomain(r *http.Request) string {
	domain := strings.TrimSpace(r.Host)
	if domain != "" {
		return domain
	}
	return "localhost"
}

func agentAuthURI(r *http.Request, endpointPath string) string {
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	return (&url.URL{
		Scheme: scheme,
		Host:   agentAuthDomain(r),
		Path:   endpointPath,
	}).String()
}

func writeAgentWalletAuthError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, identity.ErrWalletAuthUnauthorized):
		utils.WriteAPIError(w, http.StatusForbidden, types.APIErrorCodeUnauthorized, err.Error())
	case errors.Is(err, identity.ErrWalletAuthChallengeNotFound), errors.Is(err, identity.ErrWalletAuthChallengeExpired), errors.Is(err, identity.ErrWalletAuthInvalidSignature):
		utils.WriteAPIError(w, http.StatusUnauthorized, types.APIErrorCodeUnauthorized, err.Error())
	default:
		utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidRequest, err.Error())
	}
}

func Status(ctx context.Context, stateDir string) (types.AgentStatusResponse, error) {
	var status types.AgentStatusResponse
	err := controlRequest(ctx, stateDir, http.MethodGet, protocol.PathAgentStatus, nil, &status)
	return status, err
}

func Shutdown(ctx context.Context, stateDir string) error {
	return controlRequest(ctx, stateDir, http.MethodPost, protocol.PathAgentShutdown, nil, nil)
}

func AddTunnel(ctx context.Context, stateDir string, req types.AgentTunnelRequest) error {
	return controlRequest(ctx, stateDir, http.MethodPost, protocol.PathAgentTunnels, req, nil)
}

func DeleteTunnel(ctx context.Context, stateDir, tunnelID string) error {
	path := protocol.PathAgentTunnelsPrefix + url.PathEscape(tunnelID)
	return controlRequest(ctx, stateDir, http.MethodDelete, path, nil, nil)
}

func ConnectRelay(ctx context.Context, stateDir, tunnelID, relayURL string) error {
	path := protocol.PathAgentTunnelsPrefix + url.PathEscape(tunnelID) + "/relays"
	return controlRequest(ctx, stateDir, http.MethodPost, path, types.AgentRelayRequest{RelayURL: relayURL}, nil)
}

func DisconnectRelay(ctx context.Context, stateDir, tunnelID, relayURL string) error {
	path := protocol.PathAgentTunnelsPrefix + url.PathEscape(tunnelID) + "/relays"
	return controlRequest(ctx, stateDir, http.MethodDelete, path, types.AgentRelayRequest{RelayURL: relayURL}, nil)
}

func UpdateTunnel(ctx context.Context, stateDir, tunnelID string, req types.AgentTunnelUpdateRequest) error {
	path := protocol.PathAgentTunnelsPrefix + url.PathEscape(tunnelID)
	return controlRequest(ctx, stateDir, http.MethodPatch, path, req, nil)
}

func controlRequest(ctx context.Context, stateDir, method, path string, payload any, out any) error {
	stateDir = strings.TrimSpace(stateDir)
	if stateDir == "" {
		return errors.New("state dir is required")
	}
	var endpoint endpoint
	if err := utils.ReadJSONFile(filepath.Join(stateDir, endpointFilename), &endpoint); err != nil {
		if os.IsNotExist(err) {
			return ErrNotRunning
		}
		return err
	}
	if strings.TrimSpace(endpoint.ControlAddr) == "" || strings.TrimSpace(endpoint.Token) == "" {
		return errors.New("agent endpoint state is incomplete")
	}
	baseURL, err := url.Parse("http://" + endpoint.ControlAddr)
	if err != nil {
		return err
	}
	headers := http.Header{"Authorization": []string{"Bearer " + endpoint.Token}}
	err = utils.HTTPDoAPIPath(ctx, controlHTTPClient, baseURL, method, path, payload, headers, out)
	if controlDialError(err) {
		return ErrNotRunning
	}
	return err
}

func controlDialError(err error) bool {
	var opErr *net.OpError
	return errors.As(err, &opErr) && opErr.Op == "dial"
}
