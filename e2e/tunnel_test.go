package e2e_test

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/agent"
	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/gateway"
	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestCanonicalTunnel(t *testing.T) {
	h := newHarness(t)
	publicURL := h.waitForPublicURL()
	publicOrigin, err := url.Parse(publicURL)
	if err != nil {
		t.Fatalf("parse public URL: %v", err)
	}
	portalOrigin, err := url.Parse(h.server.PortalURL())
	if err != nil {
		t.Fatalf("parse portal URL: %v", err)
	}
	if publicOrigin.Port() != portalOrigin.Port() {
		t.Fatalf("public URL port = %q, want canonical PORTAL_URL port %q", publicOrigin.Port(), portalOrigin.Port())
	}
	if got := h.get(publicURL); got != marker {
		t.Fatalf("tenant response = %q, want %q", got, marker)
	}
}

func TestSharedTunnelRuntime(t *testing.T) {
	site := t.TempDir()
	if err := os.WriteFile(filepath.Join(site, "index.html"), []byte(marker), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"stream", "routed", "static", "protected"} {
		t.Run(mode, func(t *testing.T) {
			// Isolate relay admission budgets as well as tunnel lifecycles.
			h := newHarness(t)
			target, err := url.Parse(h.service.URL)
			if err != nil {
				t.Fatal(err)
			}
			cfg := agent.TunnelConfig{Name: mode, TargetAddr: target.Host}
			switch mode {
			case "routed":
				cfg.TargetAddr = ""
				cfg.HTTPRoutes = []agent.HTTPRouteConfig{{Prefix: "/", Upstream: h.service.URL}}
			case "static":
				cfg.TargetAddr, cfg.Serve = "", site
			case "protected":
				cfg.Auth = "credential"
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			cfg.Discovery = new(bool)
			cfg.RelayURLs = []string{h.server.PortalURL()}
			cfg.IdentityPath = filepath.Join(t.TempDir(), "identity.json")
			runtime, err := agent.StartTunnel(ctx, cfg)
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- runtime.Run(ctx) }()
			t.Cleanup(func() {
				cancel()
				_ = runtime.Close()
				select {
				case err := <-done:
					if err != nil && !errors.Is(err, context.Canceled) {
						t.Errorf("stop runtime: %v", err)
					}
				case <-time.After(5 * time.Second):
					t.Error("runtime did not stop")
				}
			})
			ready, err := runtime.WaitReady(ctx)
			if err != nil || len(ready) != 1 {
				t.Fatalf("ready: %v, %v", ready, err)
			}
			client := relayControlClient(t, h.stateDir)
			client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
			client.Transport.(*http.Transport).DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, h.sniAddr)
			}
			request, err := http.NewRequestWithContext(ctx, http.MethodGet, ready[0].PublicURL+"/marker", nil)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.Auth != "" {
				response, err := client.Do(request)
				if err != nil {
					t.Fatal(err)
				}
				response.Body.Close()
				if response.StatusCode != http.StatusSeeOther {
					t.Fatalf("unauthenticated status: %d", response.StatusCode)
				}
				credential, err := gateway.IssueApplicationCredential(
					runtime.Identity, request.URL.Host, "reader", time.Now().Add(time.Minute),
				)
				if err != nil {
					t.Fatal(err)
				}
				request.Header.Set(types.HeaderAccessCredential, credential)
			}
			response, err := client.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err != nil || response.StatusCode != http.StatusOK || string(body) != marker {
				t.Fatalf("tenant response: status=%d body=%q err=%v", response.StatusCode, body, err)
			}
		})
	}
}
