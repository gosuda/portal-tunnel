package e2e_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pelletier/go-toml/v2"

	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/agent"
	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/tunnel"
)

func startAgentWithConfig(t *testing.T, ctx context.Context, cancel context.CancelFunc, serviceAddr, relayURL string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	discovery := false
	cfg := agent.Config{
		Agent: agent.AgentConfig{StateDir: dir, ControlAddr: "127.0.0.1:0"},
		Tunnels: []agent.TunnelConfig{{ID: "web", Config: tunnel.Config{
			Name: "web", TargetAddr: serviceAddr,
			RelayURLs: []string{relayURL}, Discovery: &discovery,
		}}},
	}
	data, err := toml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := agent.LoadExistingConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- agent.Run(ctx, loaded) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("stop agent: %v", err)
			}
		case <-time.After(15 * time.Second):
			t.Error("agent did not stop")
		}
	})
	return dir
}

func findAgentPublicURL(status agent.AgentStatusResponse, relayURL string) (string, bool) {
	for _, tunnel := range status.Tunnels {
		if tunnel.ID != "web" {
			continue
		}
		for _, relay := range tunnel.Relays {
			if relay.RelayURL == relayURL && relay.PublicURL != "" {
				return relay.PublicURL, true
			}
		}
	}
	return "", false
}

func waitAgentRelay(t *testing.T, ctx context.Context, dir, relayURL string) string {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		status, err := agent.Status(ctx, dir)
		if err != nil {
			<-time.After(100 * time.Millisecond)
			continue
		}
		if publicURL, ok := findAgentPublicURL(status, relayURL); ok {
			return publicURL
		}
		<-time.After(100 * time.Millisecond)
	}
	t.Fatalf("agent relay %s never became available", relayURL)
	return ""
}
func assertSavedAgentTunnel(t *testing.T, path, relayURL, description string, maxRelays int) {
	t.Helper()
	saved, err := agent.LoadExistingConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(saved.Tunnels) != 1 {
		t.Fatalf("saved tunnels = %d, want 1", len(saved.Tunnels))
	}
	web := saved.Tunnels[0]
	if len(web.RelayURLs) != 1 || web.RelayURLs[0] != relayURL || web.Description != description || web.MaxActiveRelays != maxRelays {
		t.Fatalf("saved settings do not retain the configured relay and updates: relays=%v description=%q max=%d", web.RelayURLs, web.Description, web.MaxActiveRelays)
	}
}

func addAgentTunnel(t *testing.T, ctx context.Context, dir, targetAddr, relayURL string) {
	t.Helper()
	discovery := false
	if err := agent.AddTunnel(ctx, dir, agent.AgentTunnelRequest{
		ID: "other", TargetAddr: targetAddr,
		RelayURLs: []string{relayURL}, Discovery: &discovery,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestAgentSettingsPreserveRuntimeRelayMembership(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	relayA := startMembershipRelay(t, ctx)
	relayB := startMembershipRelay(t, ctx)
	service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, marker)
	}))
	t.Cleanup(service.Close)

	dir := startAgentWithConfig(t, ctx, cancel, service.Listener.Addr().String(), relayA.relayURL)
	publicA := waitAgentRelay(t, ctx, dir, relayA.relayURL)
	waitServesMarker(t, "agent initial relay", relayA, publicA, 15*time.Second)
	if err := agent.ConnectRelay(ctx, dir, "web", relayB.relayURL); err != nil {
		t.Fatal(err)
	}
	publicB := waitAgentRelay(t, ctx, dir, relayB.relayURL)
	waitServesMarker(t, "agent added relay", relayB, publicB, 15*time.Second)
	if err := agent.DisconnectRelay(ctx, dir, "web", relayA.relayURL); err != nil {
		t.Fatal(err)
	}

	addAgentTunnel(t, ctx, dir, service.Listener.Addr().String(), relayA.relayURL)
	waitServesMarker(t, "agent relay after adding another tunnel", relayB, publicB, 15*time.Second)
	description := "updated metadata"
	maxRelays := 2
	if err := agent.UpdateTunnel(ctx, dir, "web", agent.AgentTunnelUpdateRequest{
		Metadata: &agent.AgentMetadataRequest{Description: &description}, MaxActiveRelays: &maxRelays,
	}); err != nil {
		t.Fatal(err)
	}
	if err := agent.DeleteTunnel(ctx, dir, "other"); err != nil {
		t.Fatal(err)
	}
	waitServesMarker(t, "agent relay after saved changes", relayB, publicB, 15*time.Second)
	if _, served := tenantGet(relayA.sniAddr, relayA.certPath, publicA); served {
		t.Fatal("saved changes reconnected the removed relay")
	}
	assertSavedAgentTunnel(t, filepath.Join(dir, "config.toml"), relayA.relayURL, description, maxRelays)
}
