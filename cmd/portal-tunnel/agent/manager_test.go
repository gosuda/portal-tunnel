package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
)

// unreachableRelay keeps started tunnels off the network: they come up with
// one relay that never connects.
const unreachableRelay = "https://127.0.0.1:1"

func testTunnel(id string) TunnelConfig {
	discovery := false
	return TunnelConfig{ID: id, TargetAddr: "127.0.0.1:3000", RelayURLs: []string{unreachableRelay}, Discovery: &discovery}
}

// testManager builds a manager from a config file written and loaded the way
// the agent does, so it starts from normalized settings.
func testManager(t *testing.T, tunnels ...TunnelConfig) (*manager, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	cfg := Config{Agent: AgentConfig{StateDir: dir}, Tunnels: tunnels}
	// writeConfigDocument secures an existing file before it rewrites it, and
	// on Windows a file that is not there yet cannot be secured.
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeConfigDocument(path, 0o600, cfg); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadExistingConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	return newManager(loaded, DefaultControlAddr), path
}

func startManager(t *testing.T, m *manager) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	m.Start(ctx)
	t.Cleanup(func() {
		cancel()
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer stopCancel()
		_ = m.Stop(stopCtx)
	})
}

func tunnelStatus(t *testing.T, m *manager, id string) AgentTunnelStatus {
	t.Helper()
	for _, status := range m.Snapshot().Tunnels {
		if status.ID == id {
			return status
		}
	}
	t.Fatalf("tunnel %q not in status", id)
	return AgentTunnelStatus{}
}

func callControl(t *testing.T, m *manager, method, path, body string) (int, string) {
	t.Helper()
	handler := &controlHandler{manager: m, token: "test-token", authority: "127.0.0.1:4018", localhostAuthority: "localhost:4018"}
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Host = "127.0.0.1:4018"
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

func savedTunnel(t *testing.T, path, id string) TunnelConfig {
	t.Helper()
	cfg, err := LoadExistingConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, tunnel := range cfg.Tunnels {
		if tunnel.ID == id {
			return tunnel
		}
	}
	t.Fatalf("tunnel %q not saved", id)
	return TunnelConfig{}
}

func TestAddTunnelStaticSite(t *testing.T) {
	site := t.TempDir()
	if err := os.WriteFile(filepath.Join(site, "index.html"), []byte("<h1>hi</h1>"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A Windows path has backslashes, so the site path is JSON-encoded.
	siteJSON, err := json.Marshal(site)
	if err != nil {
		t.Fatal(err)
	}
	common := `"discovery":false,"relays":["` + unreachableRelay + `"]`

	t.Run("accepted", func(t *testing.T) {
		m, path := testManager(t)
		startManager(t, m)
		if code, resp := callControl(t, m, http.MethodPost, types.PathAgentTunnels, `{"id":"site","serve":`+string(siteJSON)+`,`+common+`}`); code != http.StatusAccepted {
			t.Fatalf("status = %d, body = %s", code, resp)
		}
		// A static site gets no default target.
		if saved := savedTunnel(t, path, "site"); saved.Serve != site || saved.TargetAddr != "" {
			t.Fatalf("saved static tunnel = %+v", saved)
		}
		if status := tunnelStatus(t, m, "site"); status.Serve != site || status.TargetAddr != "" {
			t.Fatalf("static tunnel status = %+v", status)
		}
	})

	t.Run("rejected", func(t *testing.T) {
		m, path := testManager(t, testTunnel("existing"))
		for _, tc := range []struct{ name, body string }{
			{name: "with target", body: `{"id":"site","serve":` + string(siteJSON) + `,"target_addr":"127.0.0.1:3000",` + common + `}`},
			{name: "with routes", body: `{"id":"site","serve":` + string(siteJSON) + `,"http_routes":[{"prefix":"/","upstream":"http://127.0.0.1:3000"}],` + common + `}`},
		} {
			t.Run(tc.name, func(t *testing.T) {
				fileBefore, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				code, resp := callControl(t, m, http.MethodPost, types.PathAgentTunnels, tc.body)
				if code != http.StatusBadRequest || !strings.Contains(resp, "static serving cannot be combined") {
					t.Fatalf("status = %d, body = %s; want 400 refusing the combination", code, resp)
				}
				if fileAfter, err := os.ReadFile(path); err != nil || !bytes.Equal(fileBefore, fileAfter) {
					t.Fatalf("rejected tunnel changed the config file (err %v):\n%s", err, fileAfter)
				}
				if got := len(m.Snapshot().Tunnels); got != 1 {
					t.Fatalf("tunnels = %d, want only the existing one", got)
				}
			})
		}
	})
}
