package e2e_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal"
	"github.com/gosuda/portal-tunnel/v2/portal/acme"
	"github.com/gosuda/portal-tunnel/v2/types"
)

// waitForRelayCertificateMaterial polls until the relay has persisted both
// halves of its local certificate material under dir, which local ACME does
// during startup.
func waitForRelayCertificateMaterial(t *testing.T, dir string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		persisted := true
		for _, name := range []string{"fullchain.pem", "privatekey.pem"} {
			if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
				persisted = false
				break
			}
		}
		if persisted {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("relay did not persist certificate material under %s", dir)
		}
		<-time.After(10 * time.Millisecond)
	}
}

// relayControlClient returns an HTTPS client that trusts the relay's local
// certificate. Requests use an IP literal, so no SNI is sent and the relay's
// ingress router serves the control plane.
func relayControlClient(t *testing.T, stateDir string) *http.Client {
	t.Helper()
	certPEM, err := os.ReadFile(filepath.Join(stateDir, "fullchain.pem"))
	if err != nil {
		t.Fatalf("read relay certificate: %v", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certPEM) {
		t.Fatalf("relay certificate is not a usable PEM chain")
	}
	transport := &http.Transport{
		TLSClientConfig:   &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		DisableKeepAlives: true,
	}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 10 * time.Second}
}

// waitRelayReady polls healthz until the serve loop accepts traffic, failing
// if Serve exits first.
func waitRelayReady(t *testing.T, client *http.Client, baseURL string, serveResult <-chan error) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		resp, err := client.Get(baseURL + types.PathHealthz)
		if err == nil {
			resp.Body.Close()
			return
		}
		select {
		case serveErr := <-serveResult:
			t.Fatalf("Serve() exited before readiness: %v", serveErr)
		case <-deadline:
			t.Fatalf("Serve() did not become ready: %v", err)
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// awaitServeExit requires the cancelled serve loop to return within the
// graceful-shutdown budget; nil or a context error are both a clean exit.
func awaitServeExit(t *testing.T, serveResult <-chan error) {
	t.Helper()
	// This deadline dominates the shutdown budget so a slow but correct
	// shutdown still fits.
	select {
	case err := <-serveResult:
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Serve() error after cancellation = %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Serve() did not return after cancellation")
	}
}

// Serve is the public lifecycle entry point: relay-owned routes answer
// alongside the mounted application handler, and cancelling the context ends
// the serve loop within the shutdown budget.
func TestRelayServeRoutesAndCancellation(t *testing.T) {
	t.Run("application handler coexists with relay routes", func(t *testing.T) {
		sniPort := harnessPort(t)
		stateDir := t.TempDir()
		// x402 composition is owned by cmd/relay-server (#490), not by the
		// relay core, so this e2e pins only the routing coexistence.
		server, err := portal.NewServer(portal.ServerConfig{
			PortalURL:     "https://localhost:4017",
			StateDir:      stateDir,
			SNIListenAddr: "127.0.0.1:" + strconv.Itoa(sniPort),
		})
		if err != nil {
			t.Fatalf("create portal server: %v", err)
		}
		appHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/app" {
				http.NotFound(w, r)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		})
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		serveResult := make(chan error, 1)
		go func() {
			serveResult <- server.Serve(ctx, appHandler)
		}()

		waitForRelayCertificateMaterial(t, stateDir)
		client := relayControlClient(t, stateDir)
		baseURL := "https://127.0.0.1:" + strconv.Itoa(sniPort)
		waitRelayReady(t, client, baseURL, serveResult)

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

		cancel()
		awaitServeExit(t, serveResult)
	})

	t.Run("nil handler keeps the relay root", func(t *testing.T) {
		sniPort := harnessPort(t)
		stateDir := t.TempDir()
		server, err := portal.NewServer(portal.ServerConfig{
			PortalURL:     "https://localhost:4017",
			StateDir:      stateDir,
			SNIListenAddr: "127.0.0.1:" + strconv.Itoa(sniPort),
		})
		if err != nil {
			t.Fatalf("create portal server: %v", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		serveResult := make(chan error, 1)
		go func() {
			serveResult <- server.Serve(ctx, nil)
		}()

		waitForRelayCertificateMaterial(t, stateDir)
		client := relayControlClient(t, stateDir)
		baseURL := "https://127.0.0.1:" + strconv.Itoa(sniPort)
		waitRelayReady(t, client, baseURL, serveResult)

		for _, route := range []struct {
			path   string
			status int
		}{
			{"/", http.StatusOK},
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

		cancel()
		awaitServeExit(t, serveResult)
	})
}

// Start with no ACME.KeyDir keeps the certificate material under StateDir,
// serves the public healthz route, and gates the keyless signing path:
// an unauthenticated sign request must be rejected.
func TestRelayStartInitializesLocalACMEAndGatesSignPath(t *testing.T) {
	sniPort := harnessPort(t)
	stateDir := t.TempDir()
	server, err := portal.NewServer(portal.ServerConfig{
		PortalURL:     "https://localhost:4017",
		StateDir:      stateDir,
		SNIListenAddr: "127.0.0.1:" + strconv.Itoa(sniPort),
	})
	if err != nil {
		t.Fatalf("create portal server: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := server.Start(ctx, nil); err != nil {
		t.Fatalf("start portal server: %v", err)
	}
	defer stopRelay(t, server)

	waitForRelayCertificateMaterial(t, stateDir)
	client := relayControlClient(t, stateDir)
	baseURL := "https://127.0.0.1:" + strconv.Itoa(sniPort)
	for _, route := range []struct {
		path   string
		status int
	}{
		{types.PathHealthz, http.StatusOK},
		{types.PathV1Sign, http.StatusForbidden},
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

// /sdk/domain is the compatibility contract a client bootstraps from, an
// explicitly configured ACME.KeyDir must be honored, and the relay discovery
// envelope is served only when discovery is enabled.
func TestRelayDomainCompatibilityAndDiscovery(t *testing.T) {
	t.Run("domain reports compatibility info with discovery enabled", func(t *testing.T) {
		sniPort := harnessPort(t)
		keyDir := t.TempDir()
		server, err := portal.NewServer(portal.ServerConfig{
			PortalURL:        "https://localhost:4017",
			StateDir:         t.TempDir(),
			ACME:             acme.Config{KeyDir: keyDir},
			SNIListenAddr:    "127.0.0.1:" + strconv.Itoa(sniPort),
			DiscoveryEnabled: true,
		})
		if err != nil {
			t.Fatalf("create portal server: %v", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		if err := server.Start(ctx, nil); err != nil {
			t.Fatalf("start portal server: %v", err)
		}
		defer stopRelay(t, server)

		// Certificate material lands in the explicitly configured KeyDir,
		// not the state directory.
		waitForRelayCertificateMaterial(t, keyDir)
		client := relayControlClient(t, keyDir)
		baseURL := "https://127.0.0.1:" + strconv.Itoa(sniPort)

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
		resp, err = client.Get(baseURL + types.PathDiscovery)
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
		selfCount := 0
		for _, descriptor := range discoveryEnvelope.Data.Relays {
			if descriptor.APIHTTPSAddr != "https://localhost:4017" {
				continue
			}
			selfCount++
			if descriptor.Signature == "" {
				t.Fatal("discovery self descriptor has no signature")
			}
		}
		if selfCount != 1 {
			t.Fatalf("discovery envelope contains %d self descriptors, want 1", selfCount)
		}
		if discoveryEnvelope.Data.ReleaseVersion != types.ReleaseVersion {
			t.Fatalf("discovery envelope ReleaseVersion = %q, want %q", discoveryEnvelope.Data.ReleaseVersion, types.ReleaseVersion)
		}
		if release, ok := discoveryEnvelope.Data.RelayReleaseVersions["https://localhost:4017"]; ok {
			t.Fatalf("discovery envelope reports self release observation %q", release)
		}
	})

	t.Run("discovery disabled answers not found", func(t *testing.T) {
		sniPort := harnessPort(t)
		stateDir := t.TempDir()
		server, err := portal.NewServer(portal.ServerConfig{
			PortalURL:     "https://localhost:4017",
			StateDir:      stateDir,
			SNIListenAddr: "127.0.0.1:" + strconv.Itoa(sniPort),
		})
		if err != nil {
			t.Fatalf("create portal server: %v", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		if err := server.Start(ctx, nil); err != nil {
			t.Fatalf("start portal server: %v", err)
		}
		defer stopRelay(t, server)

		waitForRelayCertificateMaterial(t, stateDir)
		client := relayControlClient(t, stateDir)
		resp, err := client.Get("https://127.0.0.1:" + strconv.Itoa(sniPort) + types.PathDiscovery)
		if err != nil {
			t.Fatalf("GET %s: %v", types.PathDiscovery, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("GET %s status=%d, want 404 with discovery disabled", types.PathDiscovery, resp.StatusCode)
		}
	})
}
