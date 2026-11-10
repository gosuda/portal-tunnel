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

func TestAgentSettingsPreserveRuntimeRelayMembership(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	relayA := startMembershipRelay(t, ctx)
	relayB := startMembershipRelay(t, ctx)
	service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, marker)
	}))
	t.Cleanup(service.Close)

	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	discovery := false
	cfg := agent.Config{
		Agent: agent.AgentConfig{StateDir: dir, ControlAddr: "127.0.0.1:0"},
		Tunnels: []agent.TunnelConfig{{ID: "web", Config: tunnel.Config{
			Name: "web", TargetAddr: service.Listener.Addr().String(),
			RelayURLs: []string{relayA.relayURL}, Discovery: &discovery,
		}}},
	}
	data, err := toml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err = agent.LoadExistingConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- agent.Run(ctx, cfg) }()
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

	waitRelay := func(relayURL string) string {
		t.Helper()
		deadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(deadline) {
			status, err := agent.Status(ctx, dir)
			if err != nil {
				<-time.After(100 * time.Millisecond)
				continue
			}
			for _, tunnel := range status.Tunnels {
				if tunnel.ID != "web" {
					continue
				}
				for _, relay := range tunnel.Relays {
					if relay.RelayURL == relayURL && relay.PublicURL != "" {
						return relay.PublicURL
					}
				}
			}
			<-time.After(100 * time.Millisecond)
		}
		t.Fatalf("agent relay %s never became available", relayURL)
		return ""
	}
	publicA := waitRelay(relayA.relayURL)
	waitServesMarker(t, "agent initial relay", relayA, publicA, 15*time.Second)
	if err := agent.ConnectRelay(ctx, dir, "web", relayB.relayURL); err != nil {
		t.Fatal(err)
	}
	publicB := waitRelay(relayB.relayURL)
	waitServesMarker(t, "agent added relay", relayB, publicB, 15*time.Second)
	if err := agent.DisconnectRelay(ctx, dir, "web", relayA.relayURL); err != nil {
		t.Fatal(err)
	}

	description := "updated metadata"
	maxRelays := 2
	if err := agent.AddTunnel(ctx, dir, agent.AgentTunnelRequest{
		ID: "other", TargetAddr: service.Listener.Addr().String(),
		RelayURLs: []string{relayA.relayURL}, Discovery: &discovery,
	}); err != nil {
		t.Fatal(err)
	}
	waitServesMarker(t, "agent relay after adding another tunnel", relayB, publicB, 15*time.Second)
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
	saved, err := agent.LoadExistingConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(saved.Tunnels) != 1 {
		t.Fatalf("saved tunnels = %d, want 1", len(saved.Tunnels))
	}
	web := saved.Tunnels[0]
	if len(web.RelayURLs) != 1 || web.RelayURLs[0] != relayA.relayURL || web.Description != description || web.MaxActiveRelays != maxRelays {
		t.Fatalf("saved settings do not retain the configured relay and updates: relays=%v description=%q max=%d", web.RelayURLs, web.Description, web.MaxActiveRelays)
	}
}
