package agent

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

const (
	controlRequestBodyLimit = 8 << 10
	endpointFilename        = "agent-endpoint.json"
)

var controlHTTPClient = utils.NewHTTPClient(utils.WithHTTPTimeout(5 * time.Second))

type endpoint struct {
	ControlAddr string `json:"control_addr"`
	Token       string `json:"token"`
}

type controlHandler struct {
	manager  *manager
	token    string
	shutdown func()
}

func (s *controlHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(auth, "Bearer ") || strings.TrimSpace(strings.TrimPrefix(auth, "Bearer ")) != s.token {
		utils.WriteAPIError(w, http.StatusUnauthorized, types.APIErrorCodeUnauthorized, "unauthorized")
		return
	}

	switch {
	case r.URL.Path == types.PathAgentStatus:
		if !utils.RequireMethod(w, r, http.MethodGet) {
			return
		}
		utils.WriteAPIData(w, http.StatusOK, s.manager.Snapshot())
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
		req, ok := utils.DecodeJSONRequest[types.AgentTunnelRequest](w, r, controlRequestBodyLimit)
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
			if !utils.RequireMethod(w, r, http.MethodDelete) {
				return
			}
			if err := s.manager.DeleteTunnel(tunnelID); err != nil {
				utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidRequest, err.Error())
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
		case "multi-hop":
			switch r.Method {
			case http.MethodPost:
				req, ok := utils.DecodeJSONRequest[types.AgentMultiHopRequest](w, r, controlRequestBodyLimit)
				if !ok {
					return
				}
				if err := s.manager.SetMultiHop(tunnelID, req.Relays); err != nil {
					utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidRequest, err.Error())
					return
				}
			case http.MethodDelete:
				if err := s.manager.SetMultiHop(tunnelID, nil); err != nil {
					utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidRequest, err.Error())
					return
				}
			default:
				utils.MethodNotAllowedError().Write(w)
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

func Status(ctx context.Context, stateDir string) (types.AgentStatusResponse, error) {
	var status types.AgentStatusResponse
	err := controlRequest(ctx, stateDir, http.MethodGet, types.PathAgentStatus, nil, &status)
	return status, err
}

func Shutdown(ctx context.Context, stateDir string) error {
	return controlRequest(ctx, stateDir, http.MethodPost, types.PathAgentShutdown, nil, nil)
}

func AddTunnel(ctx context.Context, stateDir string, req types.AgentTunnelRequest) error {
	return controlRequest(ctx, stateDir, http.MethodPost, types.PathAgentTunnels, req, nil)
}

func DeleteTunnel(ctx context.Context, stateDir, tunnelID string) error {
	path := types.PathAgentTunnelsPrefix + url.PathEscape(tunnelID)
	return controlRequest(ctx, stateDir, http.MethodDelete, path, nil, nil)
}

func ConnectRelay(ctx context.Context, stateDir, tunnelID, relayURL string) error {
	path := types.PathAgentTunnelsPrefix + url.PathEscape(tunnelID) + "/relays"
	return controlRequest(ctx, stateDir, http.MethodPost, path, types.AgentRelayRequest{RelayURL: relayURL}, nil)
}

func DisconnectRelay(ctx context.Context, stateDir, tunnelID, relayURL string) error {
	path := types.PathAgentTunnelsPrefix + url.PathEscape(tunnelID) + "/relays"
	return controlRequest(ctx, stateDir, http.MethodDelete, path, types.AgentRelayRequest{RelayURL: relayURL}, nil)
}

func SetMultiHop(ctx context.Context, stateDir, tunnelID string, relayURLs []string) error {
	path := types.PathAgentTunnelsPrefix + url.PathEscape(tunnelID) + "/multi-hop"
	if relayURLs == nil {
		return controlRequest(ctx, stateDir, http.MethodDelete, path, nil, nil)
	}
	return controlRequest(ctx, stateDir, http.MethodPost, path, types.AgentMultiHopRequest{Relays: relayURLs}, nil)
}

func controlRequest(ctx context.Context, stateDir, method, path string, payload any, out any) error {
	stateDir = strings.TrimSpace(stateDir)
	if stateDir == "" {
		return errors.New("state dir is required")
	}
	var endpoint endpoint
	if err := utils.ReadJSONFile(filepath.Join(stateDir, endpointFilename), &endpoint); err != nil {
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
	return utils.HTTPDoAPIPath(ctx, controlHTTPClient, baseURL, method, path, payload, headers, out)
}
