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

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

var (
	errStateDirIsRequired             = errors.New("state dir is required")
	errAgentEndpointStateIsIncomplete = errors.New("agent endpoint state is incomplete")
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
	creds := s.controlCredentials(r)
	if !creds.bearer && (!creds.walletOK || r.URL.Path != types.PathAgentStatus) {
		utils.WriteAPIError(w, http.StatusUnauthorized, types.APIErrorCodeUnauthorized, "unauthorized")
		return
	}
	switch {
	case r.URL.Path == types.PathAgentStatus:
		s.serveStatus(w, r, creds)
	case r.URL.Path == types.PathAgentShutdown:
		s.serveShutdown(w, r)
	case r.URL.Path == types.PathAgentTunnels:
		s.serveAddTunnel(w, r)
	case strings.HasPrefix(r.URL.Path, types.PathAgentTunnelsPrefix):
		s.serveTunnel(w, r)
	default:
		utils.WriteAPIError(w, http.StatusNotFound, types.APIErrorCodeNotFound, "not found")
	}
}

type controlCredentials struct {
	bearer   bool
	wallet   string
	walletOK bool
}

func (s *controlHandler) controlCredentials(r *http.Request) controlCredentials {
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	bearerAuthenticated := strings.HasPrefix(auth, "Bearer ") && strings.TrimSpace(strings.TrimPrefix(auth, "Bearer ")) == s.token
	walletAddress, walletAuthenticated := s.authenticatedWallet(r)
	return controlCredentials{
		bearer:   bearerAuthenticated,
		wallet:   walletAddress,
		walletOK: walletAuthenticated,
	}
}

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
		return s.serveAuthChallenge(w, r)
	case types.PathAgentAuthLogin:
		return s.serveAuthLogin(w, r)
	case types.PathAgentAuthLogout:
		return s.serveAuthLogout(w, r)
	case types.PathAgentAuthStatus:
		return s.serveAuthStatus(w, r)
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
		return errStateDirIsRequired
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
		return errAgentEndpointStateIsIncomplete
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
