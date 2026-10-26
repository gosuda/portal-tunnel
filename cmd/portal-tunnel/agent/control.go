package agent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/siweauth"
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
	manager            *manager
	token              string
	auth               *walletAuthenticator
	shutdown           func()
	authority          string
	localhostAuthority string
}

func (s *controlHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !s.trustedLocalRequest(r) {
		utils.WriteAPIError(w, http.StatusForbidden, types.APIErrorCodeUnauthorized, "untrusted agent request origin")
		return
	}
	if s.serveWalletAuth(w, r) {
		return
	}

	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	bearerAuthenticated := strings.HasPrefix(auth, "Bearer ") && strings.TrimSpace(strings.TrimPrefix(auth, "Bearer ")) == s.token
	walletAddress, walletAuthenticated := s.authenticatedWallet(r)
	allowed := bearerAuthenticated || (walletAuthenticated && r.URL.Path == types.PathAgentStatus)
	if !allowed {
		utils.WriteAPIError(w, http.StatusUnauthorized, types.APIErrorCodeUnauthorized, "unauthorized")
		return
	}

	switch {
	case r.URL.Path == types.PathAgentStatus:
		if !utils.RequireMethod(w, r, http.MethodGet) {
			return
		}
		status := s.manager.Snapshot()
		if walletAuthenticated {
			status.WalletAddress = walletAddress
		}
		if !bearerAuthenticated {
			// A wallet session is read-only and may be open to any wallet, so it
			// does not learn who may sign in to a tunnel.
			for i := range status.Tunnels {
				status.Tunnels[i].AuthAllowedWallets = nil
			}
		}
		utils.WriteAPIData(w, http.StatusOK, status)
	case r.URL.Path == types.PathAgentShutdown:
		if !utils.RequireMethod(w, r, http.MethodPost) {
			return
		}
		utils.WriteAPIData(w, http.StatusAccepted, map[string]bool{"accepted": true})
		if s.shutdown != nil {
			go s.shutdown()
		}
	case r.URL.Path == types.PathAgentTunnels:
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
	case strings.HasPrefix(r.URL.Path, types.PathAgentTunnelsPrefix):
		rest := strings.TrimPrefix(r.URL.Path, types.PathAgentTunnelsPrefix)
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
		default:
			utils.WriteAPIError(w, http.StatusNotFound, types.APIErrorCodeNotFound, "not found")
		}
	default:
		utils.WriteAPIError(w, http.StatusNotFound, types.APIErrorCodeNotFound, "not found")
	}
}

// trustedLocalRequest requires the listener's actual authority (or its
// localhost alias). Browsers must also send the same Origin when they send
// one; clients without an Origin header, such as the local CLI, remain valid.
// Never use X-Forwarded-Host or DNS resolution to authorize an HTTP Host.
func (s *controlHandler) trustedLocalRequest(r *http.Request) bool {
	if s.authority == "" || r.Host == "" {
		return false
	}
	if r.Host != s.authority && r.Host != s.localhostAuthority {
		return false
	}
	origins := r.Header.Values("Origin")
	if len(origins) == 0 {
		return true
	}
	if len(origins) != 1 {
		return false
	}
	scheme := "http://"
	if r.TLS != nil {
		scheme = "https://"
	}
	return origins[0] == scheme+r.Host
}

func (s *controlHandler) serveWalletAuth(w http.ResponseWriter, r *http.Request) bool {
	switch r.URL.Path {
	case types.PathAgentAuthChallenge:
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
	case types.PathAgentAuthLogin:
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
	case types.PathAgentAuthLogout:
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
	case types.PathAgentAuthStatus:
		if !utils.RequireMethod(w, r, http.MethodGet) {
			return true
		}
		walletAddress, authenticated := s.authenticatedWallet(r)
		utils.WriteAPIData(w, http.StatusOK, types.WalletAuthStatusResponse{
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
	return s.auth.validateSession(cookie.Value)
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
	case errors.Is(err, siweauth.ErrUnauthorized):
		utils.WriteAPIError(w, http.StatusForbidden, types.APIErrorCodeUnauthorized, err.Error())
	case errors.Is(err, siweauth.ErrChallengeNotFound), errors.Is(err, siweauth.ErrChallengeExpired), errors.Is(err, siweauth.ErrChallengeInvalid), errors.Is(err, siweauth.ErrInvalidSignature):
		utils.WriteAPIError(w, http.StatusUnauthorized, types.APIErrorCodeUnauthorized, err.Error())
	default:
		utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidRequest, err.Error())
	}
}

func Status(ctx context.Context, stateDir string) (AgentStatusResponse, error) {
	var status AgentStatusResponse
	err := controlRequest(ctx, stateDir, http.MethodGet, types.PathAgentStatus, nil, &status)
	return status, err
}

func Shutdown(ctx context.Context, stateDir string) error {
	return controlRequest(ctx, stateDir, http.MethodPost, types.PathAgentShutdown, nil, nil)
}

func AddTunnel(ctx context.Context, stateDir string, req AgentTunnelRequest) error {
	return controlRequest(ctx, stateDir, http.MethodPost, types.PathAgentTunnels, req, nil)
}

func DeleteTunnel(ctx context.Context, stateDir, tunnelID string) error {
	path := types.PathAgentTunnelsPrefix + url.PathEscape(tunnelID)
	return controlRequest(ctx, stateDir, http.MethodDelete, path, nil, nil)
}

func ConnectRelay(ctx context.Context, stateDir, tunnelID, relayURL string) error {
	path := types.PathAgentTunnelsPrefix + url.PathEscape(tunnelID) + "/relays"
	return controlRequest(ctx, stateDir, http.MethodPost, path, AgentRelayRequest{RelayURL: relayURL}, nil)
}

func DisconnectRelay(ctx context.Context, stateDir, tunnelID, relayURL string) error {
	path := types.PathAgentTunnelsPrefix + url.PathEscape(tunnelID) + "/relays"
	return controlRequest(ctx, stateDir, http.MethodDelete, path, AgentRelayRequest{RelayURL: relayURL}, nil)
}

func UpdateTunnel(ctx context.Context, stateDir, tunnelID string, req AgentTunnelUpdateRequest) error {
	path := types.PathAgentTunnelsPrefix + url.PathEscape(tunnelID)
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
		if runtime.GOOS == "windows" && os.IsPermission(err) {
			return fmt.Errorf("read agent endpoint: %w; run the CLI from an elevated terminal to control a Windows service", err)
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
