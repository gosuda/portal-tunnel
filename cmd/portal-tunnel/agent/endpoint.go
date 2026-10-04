package agent

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/gosuda/portal-tunnel/v2/utils"
)

const (
	endpointFilename = "agent-endpoint.json"
	endpointFileMode = 0o600
)

type endpoint struct {
	ControlAddr string `json:"control_addr"`
	Token       string `json:"token"`
}

func writeEndpoint(stateDir string, ep endpoint) error {
	return utils.WriteJSONFile(filepath.Join(stateDir, endpointFilename), ep, endpointFileMode)
}

func removeEndpoint(stateDir string) {
	_ = os.Remove(filepath.Join(stateDir, endpointFilename))
}

func readEndpoint(stateDir string) (endpoint, error) {
	var ep endpoint
	if err := utils.ReadJSONFile(filepath.Join(stateDir, endpointFilename), &ep); err != nil {
		if os.IsNotExist(err) {
			return endpoint{}, ErrNotRunning
		}
		return endpoint{}, err
	}
	if strings.TrimSpace(ep.ControlAddr) == "" || strings.TrimSpace(ep.Token) == "" {
		return endpoint{}, errors.New("agent endpoint state is incomplete")
	}
	return ep, nil
}
