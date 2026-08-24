package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWaitAgentStoppedReturnsStatusErrors(t *testing.T) {
	stateDir := t.TempDir()
	endpointPath := filepath.Join(stateDir, "agent-endpoint.json")
	if err := os.WriteFile(endpointPath, []byte(`{}`), 0o600); err != nil {
		t.Fatalf("write incomplete agent endpoint: %v", err)
	}

	err := waitAgentStopped(t.Context(), stateDir)
	if err == nil {
		t.Fatal("waitAgentStopped() error = nil, want incomplete endpoint error")
	}
	if !strings.Contains(err.Error(), "agent endpoint state is incomplete") {
		t.Fatalf("waitAgentStopped() error = %q, want incomplete endpoint error", err)
	}
}

func TestWaitAgentStoppedAcceptsMissingEndpoint(t *testing.T) {
	if err := waitAgentStopped(t.Context(), t.TempDir()); err != nil {
		t.Fatalf("waitAgentStopped() error = %v, want nil for stopped agent", err)
	}
}
