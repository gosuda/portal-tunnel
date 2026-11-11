package e2e_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal"
	"github.com/gosuda/portal-tunnel/v2/portal/acme"
	"github.com/gosuda/portal-tunnel/v2/portal/discovery"
	"github.com/gosuda/portal-tunnel/v2/types"
)

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

func awaitServeExit(t *testing.T, serveResult <-chan error) {
	t.Helper()
	select {
	case err := <-serveResult:
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Serve() error after cancellation = %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Serve() did not return after cancellation")
	}
}

func bootServingRelay(t *testing.T, ctx context.Context, handler http.Handler) (*http.Client, string, <-chan error) {
	t.Helper()
	sniPort := harnessPort(t, "127.0.0.1")
	stateDir := t.TempDir()
	server, err := portal.NewServer(portal.ServerConfig{
		PortalURL:     "https://localhost:4017",
		StateDir:      stateDir,
		SNIListenAddr: "127.0.0.1:" + strconv.Itoa(sniPort),
	})
	if err != nil {
		t.Fatalf("create portal server: %v", err)
	}
	serveResult := make(chan error, 1)
	go func() {
		serveResult <- server.Serve(ctx, relayHandler(server, handler))
	}()
	waitForRelayCertificateMaterial(t, stateDir)
	client := relayControlClient(t, stateDir)
	baseURL := "https://127.0.0.1:" + strconv.Itoa(sniPort)
	waitRelayReady(t, client, baseURL, serveResult)
	return client, baseURL, serveResult
}

func assertRelayRoutes(t *testing.T, client *http.Client, baseURL string) {
	t.Helper()
	for _, route := range []struct {
		path   string
		status int
	}{
		{"/app", http.StatusNoContent},
		{"/missing", http.StatusNotFound},
	} {
		resp, err := client.Get(baseURL + route.path)
		if err != nil {
			t.Fatalf("GET %s: %v", route.path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != route.status {
			t.Fatalf("GET %s status=%d, want %d", route.path, resp.StatusCode, route.status)
		}
	}
}

func TestRelayServeRoutesAndCancellation(t *testing.T) {
	t.Run("application handler coexists with relay routes", func(t *testing.T) {
		appHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/app" {
				http.NotFound(w, r)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		})
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		client, baseURL, serveResult := bootServingRelay(t, ctx, appHandler)
		assertRelayRoutes(t, client, baseURL)
		cancel()
		awaitServeExit(t, serveResult)
	})
}

func startControlRelay(t *testing.T, ctx context.Context, cfg portal.ServerConfig) *portal.Server {
	t.Helper()
	server, err := portal.NewServer(cfg)
	if err != nil {
		t.Fatalf("create portal server: %v", err)
	}
	if err := server.Start(ctx, relayHandler(server, nil)); err != nil {
		t.Fatalf("start portal server: %v", err)
	}
	return server
}

func assertDomainCompatibility(t *testing.T, client *http.Client, baseURL string) {
	t.Helper()
	resp, err := client.Get(baseURL + types.PathSDKDomain)
	if err != nil {
		t.Fatalf("GET %s: %v", types.PathSDKDomain, err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		t.Fatalf("GET %s status=%d, want 200", types.PathSDKDomain, resp.StatusCode)
	}
	var domain types.APIEnvelope[types.DomainResponse]
	if err := json.NewDecoder(resp.Body).Decode(&domain); err != nil {
		resp.Body.Close()
		t.Fatalf("decode %s response: %v", types.PathSDKDomain, err)
	}
	resp.Body.Close()
	if !domain.OK {
		t.Fatalf("GET %s response ok=false", types.PathSDKDomain)
	}
	if domain.Data.ProtocolVersion != types.SDKVersion {
		t.Fatalf("DomainResponse.ProtocolVersion = %q, want %q", domain.Data.ProtocolVersion, types.SDKVersion)
	}
	if domain.Data.ReleaseVersion != types.ReleaseVersion {
		t.Fatalf("DomainResponse.ReleaseVersion = %q, want %q", domain.Data.ReleaseVersion, types.ReleaseVersion)
	}
}

func assertDiscoverySelfDescriptor(t *testing.T, discoveryEnvelope types.APIEnvelope[types.DiscoveryResponse]) {
	t.Helper()
	if len(discoveryEnvelope.Data.Relays) != 1 {
		t.Fatalf("discovery envelope contains %d relay descriptors, want exactly 1",
			len(discoveryEnvelope.Data.Relays))
	}
	descriptor := discoveryEnvelope.Data.Relays[0]
	if descriptor.APIHTTPSAddr != "https://localhost:4017" {
		t.Fatalf("discovery self descriptor APIHTTPSAddr = %q, want %q",
			descriptor.APIHTTPSAddr, "https://localhost:4017")
	}
	if _, err := discovery.VerifyRelayDescriptor(descriptor); err != nil {
		t.Fatalf("discovery self descriptor failed signature verification: %v", err)
	}
	if discoveryEnvelope.Data.ReleaseVersion != types.ReleaseVersion {
		t.Fatalf("discovery envelope ReleaseVersion = %q, want %q", discoveryEnvelope.Data.ReleaseVersion, types.ReleaseVersion)
	}
	if release, ok := discoveryEnvelope.Data.RelayReleaseVersions["https://localhost:4017"]; ok {
		t.Fatalf("discovery envelope reports self release observation %q", release)
	}
}

func assertDiscoveryEnabled(t *testing.T, client *http.Client, baseURL string) {
	t.Helper()
	resp, err := client.Get(baseURL + types.PathDiscovery)
	if err != nil {
		t.Fatalf("GET %s: %v", types.PathDiscovery, err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		t.Fatalf("GET %s status=%d, want 200 with discovery enabled", types.PathDiscovery, resp.StatusCode)
	}
	var discoveryEnvelope types.APIEnvelope[types.DiscoveryResponse]
	if err := json.NewDecoder(resp.Body).Decode(&discoveryEnvelope); err != nil {
		resp.Body.Close()
		t.Fatalf("decode %s response: %v", types.PathDiscovery, err)
	}
	resp.Body.Close()
	if !discoveryEnvelope.OK || discoveryEnvelope.Data.ProtocolVersion != types.DiscoveryVersion {
		t.Fatalf("discovery envelope ok=%v ProtocolVersion=%q, want ok envelope with protocol %q",
			discoveryEnvelope.OK, discoveryEnvelope.Data.ProtocolVersion, types.DiscoveryVersion)
	}
	assertDiscoverySelfDescriptor(t, discoveryEnvelope)
}

func assertDiscoveryDisabled(t *testing.T, client *http.Client, baseURL string) {
	t.Helper()
	resp, err := client.Get(baseURL + types.PathDiscovery)
	if err != nil {
		t.Fatalf("GET %s: %v", types.PathDiscovery, err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("GET %s status=%d, want 404 with discovery disabled", types.PathDiscovery, resp.StatusCode)
	}
}

func bootCompatibilityRelay(t *testing.T, ctx context.Context, keyDir string, sniPort int) (*portal.Server, string) {
	t.Helper()
	server := startControlRelay(t, ctx, portal.ServerConfig{
		PortalURL:        "https://localhost:4017",
		StateDir:         t.TempDir(),
		ACME:             acme.Config{KeyDir: keyDir},
		SNIListenAddr:    "127.0.0.1:" + strconv.Itoa(sniPort),
		DiscoveryEnabled: true,
	})
	baseURL := "https://127.0.0.1:" + strconv.Itoa(sniPort)
	return server, baseURL
}

func TestRelayDomainCompatibilityAndDiscovery(t *testing.T) {
	t.Run("domain reports compatibility info with discovery enabled", func(t *testing.T) {
		sniPort := harnessPort(t, "127.0.0.1")
		keyDir := t.TempDir()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		server, baseURL := bootCompatibilityRelay(t, ctx, keyDir, sniPort)
		defer stopRelay(t, server)
		waitForRelayCertificateMaterial(t, keyDir)
		client := relayControlClient(t, keyDir)
		assertDomainCompatibility(t, client, baseURL)
		assertDiscoveryEnabled(t, client, baseURL)
	})

	t.Run("discovery disabled answers not found", func(t *testing.T) {
		sniPort := harnessPort(t, "127.0.0.1")
		stateDir := t.TempDir()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		server := startControlRelay(t, ctx, portal.ServerConfig{
			PortalURL:     "https://localhost:4017",
			StateDir:      stateDir,
			SNIListenAddr: "127.0.0.1:" + strconv.Itoa(sniPort),
		})
		defer stopRelay(t, server)
		waitForRelayCertificateMaterial(t, stateDir)
		client := relayControlClient(t, stateDir)
		assertDiscoveryDisabled(t, client, "https://127.0.0.1:"+strconv.Itoa(sniPort))
	})
}
