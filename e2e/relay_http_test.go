package e2e_test

import (
	"context"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal"
	"github.com/gosuda/portal-tunnel/v2/types"
)

// stopRelay runs the public shutdown lifecycle and fails the test if either
// phase misbehaves.
func stopRelay(t *testing.T, server *portal.Server) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		t.Errorf("shutdown relay: %v", err)
	}
	if err := server.Wait(); err != nil {
		t.Errorf("wait for relay: %v", err)
	}
}

// The HTTP redirect listener is a security boundary: every plain-HTTP visitor
// must land on the one canonical portal origin, with nothing request- or
// attacker-controlled carried over.
func TestRelayHTTPRedirect(t *testing.T) {
	t.Run("enabled answers only with the canonical origin", func(t *testing.T) {
		for _, hsts := range []bool{false, true} {
			t.Run("hsts="+strconv.FormatBool(hsts), func(t *testing.T) {
				redirectAddr := "127.0.0.1:" + strconv.Itoa(harnessPort(t))
				sniPort := harnessPort(t)
				// net/url accepts HTTPS schemes regardless of their spelling;
				// the redirect target must still come out canonical.
				scheme := "HTTPS"
				if hsts {
					scheme = "hTtPs"
				}
				server, err := portal.NewServer(portal.ServerConfig{
					PortalURL:     scheme + "://localhost:4017/base/?configured=discarded#fragment",
					StateDir:      t.TempDir(),
					SNIListenAddr: "127.0.0.1:" + strconv.Itoa(sniPort),
					HTTPRedirect:  types.HTTPRedirectConfig{Enabled: true, Addr: redirectAddr, HSTS: hsts},
				})
				if err != nil {
					t.Fatalf("create portal server: %v", err)
				}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				if err := server.Start(ctx, nil); err != nil {
					t.Fatalf("start portal server: %v", err)
				}

				client := &http.Client{
					// Connection-per-request: the redirect semantics under test
					// must not depend on transport pooling, and an idle pooled
					// connection would hold Shutdown open until its deadline.
					Transport:     &http.Transport{DisableKeepAlives: true},
					CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
					Timeout:       10 * time.Second,
				}
				t.Cleanup(func() { client.CloseIdleConnections() })
				for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodPost, http.MethodOptions} {
					req, err := http.NewRequest(method, "http://"+redirectAddr+"//tenant/path?secret=discarded", nil)
					if err != nil {
						t.Fatalf("build %s request: %v", method, err)
					}
					if method == http.MethodOptions {
						req.URL.Path = "*"
						req.URL.RawQuery = ""
					}
					req.Host = "attacker.example"
					req.Header.Set("X-Forwarded-Host", "other-attacker.example")
					resp, err := client.Do(req)
					if err != nil {
						t.Fatalf("%s redirect request: %v", method, err)
					}
					resp.Body.Close()
					const wantLocation = "https://localhost:4017/base"
					if resp.StatusCode != http.StatusMovedPermanently || resp.Header.Get("Location") != wantLocation {
						t.Fatalf("%s: status=%d Location=%q, want 301 to %s with request path, query, fragment, Host and X-Forwarded-Host discarded",
							method, resp.StatusCode, resp.Header.Get("Location"), wantLocation)
					}
					wantHSTS := ""
					if hsts {
						wantHSTS = "max-age=31536000"
					}
					if got := resp.Header.Get("Strict-Transport-Security"); got != wantHSTS {
						t.Fatalf("%s: Strict-Transport-Security=%q, want %q", method, got, wantHSTS)
					}
				}

				stopRelay(t, server)
				listener, err := net.Listen("tcp", redirectAddr)
				if err != nil {
					t.Fatalf("redirect port not released after shutdown: %v", err)
				}
				listener.Close()
			})
		}
	})

	t.Run("disabled leaves the configured address unbound", func(t *testing.T) {
		redirectAddr := "127.0.0.1:" + strconv.Itoa(harnessPort(t))
		sniPort := harnessPort(t)
		stateDir := t.TempDir()
		server, err := portal.NewServer(portal.ServerConfig{
			PortalURL:     "https://localhost:4017",
			StateDir:      stateDir,
			SNIListenAddr: "127.0.0.1:" + strconv.Itoa(sniPort),
			HTTPRedirect:  types.HTTPRedirectConfig{Addr: redirectAddr},
		})
		if err != nil {
			t.Fatalf("create portal server: %v", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		if err := server.Start(ctx, nil); err != nil {
			t.Fatalf("start portal server: %v", err)
		}

		// With the redirect disabled the configured address stays free for
		// anyone else to bind.
		listener, err := net.Listen("tcp", redirectAddr)
		if err != nil {
			t.Fatalf("disabled redirect must not bind the configured address %s: %v", redirectAddr, err)
		}
		listener.Close()

		waitForRelayCertificateMaterial(t, stateDir)
		client := relayControlClient(t, stateDir)
		resp, err := client.Get("https://127.0.0.1:" + strconv.Itoa(sniPort) + types.PathHealthz)
		if err != nil {
			t.Fatalf("GET %s over SNI TLS: %v", types.PathHealthz, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s status=%d, want 200", types.PathHealthz, resp.StatusCode)
		}
		stopRelay(t, server)
	})

	t.Run("bind failure cleans up and retries", func(t *testing.T) {
		redirectAddr := "127.0.0.1:" + strconv.Itoa(harnessPort(t))
		sniPort := harnessPort(t)
		cfg := portal.ServerConfig{
			PortalURL:     "https://localhost:4017",
			StateDir:      t.TempDir(),
			SNIListenAddr: "127.0.0.1:" + strconv.Itoa(sniPort),
			HTTPRedirect:  types.HTTPRedirectConfig{Enabled: true, Addr: redirectAddr},
		}
		occupied, err := net.Listen("tcp", redirectAddr)
		if err != nil {
			t.Fatalf("occupy redirect address: %v", err)
		}
		server, err := portal.NewServer(cfg)
		if err != nil {
			t.Fatalf("create portal server: %v", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		if startErr := server.Start(ctx, nil); startErr == nil {
			stopRelay(t, server)
			t.Fatal("Start() succeeded with the redirect address already occupied")
		}
		if err := occupied.Close(); err != nil {
			t.Fatalf("release occupied redirect address: %v", err)
		}
		// A failed Start must not leak the SNI listener it had already bound.
		rebound, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(sniPort))
		if err != nil {
			t.Fatalf("failed Start leaked the SNI listener: %v", err)
		}
		rebound.Close()

		retry, err := portal.NewServer(cfg)
		if err != nil {
			t.Fatalf("create retry portal server: %v", err)
		}
		if err := retry.Start(ctx, nil); err != nil {
			t.Fatalf("retry Start() after releasing the redirect address: %v", err)
		}
		client := &http.Client{
			Transport:     &http.Transport{DisableKeepAlives: true},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
			Timeout:       10 * time.Second,
		}
		t.Cleanup(func() { client.CloseIdleConnections() })
		resp, err := client.Get("http://" + redirectAddr + "/ignored")
		if err != nil {
			t.Fatalf("GET retry redirect: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusMovedPermanently || resp.Header.Get("Location") != "https://localhost:4017" {
			t.Fatalf("retry: status=%d Location=%q, want 301 to the canonical origin", resp.StatusCode, resp.Header.Get("Location"))
		}
		stopRelay(t, retry)
		listener, err := net.Listen("tcp", redirectAddr)
		if err != nil {
			t.Fatalf("retry shutdown leaked redirect listener: %v", err)
		}
		listener.Close()
	})
}
