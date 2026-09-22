package e2e_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
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
		negotiateDomain := func(protocolVersion string) types.DomainResponse {
			req, err := http.NewRequest(http.MethodGet, baseURL+types.PathSDKDomain, nil)
			if err != nil {
				t.Fatalf("new domain request: %v", err)
			}
			if protocolVersion != "" {
				req.Header.Set(types.HeaderProtocolVersion, protocolVersion)
			}
			domainResp, err := client.Do(req)
			if err != nil {
				t.Fatalf("GET %s: %v", types.PathSDKDomain, err)
			}
			defer domainResp.Body.Close()
			if domainResp.StatusCode != http.StatusOK {
				t.Fatalf("GET %s status=%d, want 200", types.PathSDKDomain, domainResp.StatusCode)
			}
			var envelope types.APIEnvelope[types.DomainResponse]
			if err := json.NewDecoder(domainResp.Body).Decode(&envelope); err != nil {
				t.Fatalf("decode %s response: %v", types.PathSDKDomain, err)
			}
			if !envelope.OK {
				t.Fatalf("GET %s response ok=false", types.PathSDKDomain)
			}
			return envelope.Data
		}

		prevMin := types.SDKVersionMin
		types.SDKVersionMin = strconv.Itoa(types.ProtocolVersionNum(types.SDKVersion) - 1)
		defer func() { types.SDKVersionMin = prevMin }()

		inWindow := negotiateDomain(types.SDKVersionMin)
		if inWindow.ProtocolVersion != types.SDKVersionMin {
			t.Fatalf("in-window negotiation = %q, want echoed request %q", inWindow.ProtocolVersion, types.SDKVersionMin)
		}
		outOfWindow := negotiateDomain("1")
		if outOfWindow.ProtocolVersion != types.SDKVersion {
			t.Fatalf("out-of-window negotiation = %q, want current %q", outOfWindow.ProtocolVersion, types.SDKVersion)
		}
		if outOfWindow.ProtocolVersionMin != types.SDKVersionMin {
			t.Fatalf("DomainResponse.ProtocolVersionMin = %q, want %q", outOfWindow.ProtocolVersionMin, types.SDKVersionMin)
		}
		legacy := negotiateDomain("")
		if legacy.ProtocolVersion != types.SDKVersionMin {
			t.Fatalf("legacy negotiation = %q, want window floor %q", legacy.ProtocolVersion, types.SDKVersionMin)
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
		// The envelope must carry the relay's own signed descriptor: the
		// discovery response is a projection of the relay set, so an empty
		// Relays list would leave peers with nothing to route to.
		if len(discoveryEnvelope.Data.Relays) != 1 {
			t.Fatalf("discovery envelope Relays = %d entries, want the relay's own descriptor", len(discoveryEnvelope.Data.Relays))
		}
		if self := discoveryEnvelope.Data.Relays[0]; self.APIHTTPSAddr != "https://localhost:4017" || self.Signature == "" {
			t.Fatalf("discovery self descriptor = %+v, want api_https_addr https://localhost:4017 with a signature", self)
		}
		if discoveryEnvelope.Data.ReleaseVersion != types.ReleaseVersion {
			t.Fatalf("discovery envelope ReleaseVersion = %q, want %q", discoveryEnvelope.Data.ReleaseVersion, types.ReleaseVersion)
		}
		// A lonely relay has contacted no peers, so it must not fabricate an
		// observation about itself.
		if len(discoveryEnvelope.Data.RelayReleaseVersions) != 0 {
			t.Fatalf("discovery envelope RelayReleaseVersions = %+v, want none from a relay with no observed peers", discoveryEnvelope.Data.RelayReleaseVersions)
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

// startPriorReleaseRelay boots the in-process relay the prior-release
// binaries dial. PortalURL must stay the SNI dial address: old clients
// compare the reported reverse endpoint host with the relay URL verbatim.
func startPriorReleaseRelay(t *testing.T) (int, string) {
	t.Helper()
	sniPort := harnessPort(t)
	keyDir := t.TempDir()
	server, err := portal.NewServer(portal.ServerConfig{
		PortalURL:     "https://localhost:" + strconv.Itoa(sniPort),
		StateDir:      t.TempDir(),
		ACME:          acme.Config{KeyDir: keyDir},
		SNIListenAddr: "127.0.0.1:" + strconv.Itoa(sniPort),
		SNIPort:       sniPort,
	})
	if err != nil {
		t.Fatalf("create portal server: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := server.Start(ctx, nil); err != nil {
		t.Fatalf("start portal server: %v", err)
	}
	t.Cleanup(func() { stopRelay(t, server) })
	waitForRelayCertificateMaterial(t, keyDir)
	return sniPort, keyDir
}

func TestPriorReleaseClientRejectedAtVersionGate(t *testing.T) {
	priorBinary := buildPriorReleaseBinary(t, "v2.4.3")

	sniPort, keyDir := startPriorReleaseRelay(t)

	runCtx, cancelRun := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelRun()
	expose := exec.CommandContext(runCtx, priorBinary, "expose",
		"--relays", "localhost:"+strconv.Itoa(sniPort),
		"--discovery=false",
		"127.0.0.1:1")
	expose.Dir = t.TempDir()
	expose.Env = append(os.Environ(), "SSL_CERT_FILE="+filepath.Join(keyDir, "fullchain.pem"))
	output, err := expose.CombinedOutput()
	if err == nil {
		t.Fatalf("prior release client succeeded against an incompatible relay; output:\n%s", output)
	}
	if !strings.Contains(string(output), "protocol version mismatch") {
		t.Fatalf("prior release client failed for a reason other than the version gate; output:\n%s", output)
	}
}

func buildPriorReleaseBinary(t *testing.T, tag string) string {
	t.Helper()
	if testing.Short() {
		t.Skip("builds the prior release from a git worktree")
	}

	worktree := t.TempDir()
	if out, err := exec.Command("git", "worktree", "add", "--detach", worktree, tag).CombinedOutput(); err != nil {
		t.Skipf("git worktree %s unavailable: %v: %s", tag, err, out)
	}
	t.Cleanup(func() {
		_ = exec.Command("git", "worktree", "remove", "--force", worktree).Run()
	})
	priorBinary := filepath.Join(t.TempDir(), "portal")
	build := exec.Command("go", "build", "-o", priorBinary, "./cmd/portal-tunnel")
	build.Dir = worktree
	if out, err := build.CombinedOutput(); err != nil {
		t.Skipf("build %s failed: %v: %s", tag, err, out)
	}
	return priorBinary
}

// TestPriorReleaseClientServesThroughRelay pins the compatibility oracle for
// the negotiation window floor: the newest released dialect (v2.5.0,
// protocol 10) must register and serve traffic through the current relay
// unchanged. Any wire-level change without a protocol bump fails here first.
func TestPriorReleaseClientServesThroughRelay(t *testing.T) {
	priorBinary := buildPriorReleaseBinary(t, "v2.5.0")

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("prior-release-ok"))
	}))
	defer upstream.Close()

	sniPort, keyDir := startPriorReleaseRelay(t)

	var output syncBuffer
	pr, pw := io.Pipe()
	expose := exec.Command(priorBinary, "expose",
		"--relays", "localhost:"+strconv.Itoa(sniPort),
		"--discovery=false",
		strings.TrimPrefix(upstream.URL, "http://"))
	expose.Dir = t.TempDir()
	expose.Env = append(os.Environ(), "SSL_CERT_FILE="+filepath.Join(keyDir, "fullchain.pem"))
	expose.Stdout = pw
	expose.Stderr = pw
	if err := expose.Start(); err != nil {
		t.Fatalf("start prior release client: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		done <- expose.Wait()
		pw.Close()
	}()

	publicURLCh := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(pr)
		for scanner.Scan() {
			line := scanner.Text()
			output.append(line)
			if idx := strings.Index(line, "service ready at "); idx >= 0 {
				ready := line[idx+len("service ready at "):]
				if cut := strings.IndexAny(ready, " \t\x1b"); cut >= 0 {
					ready = ready[:cut]
				}
				publicURLCh <- ready
			}
		}
	}()

	var publicURL string
	select {
	case publicURL = <-publicURLCh:
	case err := <-done:
		t.Fatalf("prior release client exited before readiness: %v\n%s", err, output.String())
	case <-time.After(30 * time.Second):
		t.Fatalf("prior release client never reported readiness\n%s", output.String())
	}

	for i := 0; i < 20; i++ {
		if body, ok := tenantGet("127.0.0.1:"+strconv.Itoa(sniPort), filepath.Join(keyDir, "fullchain.pem"), publicURL); ok {
			if !strings.Contains(body, "prior-release-ok") {
				t.Fatalf("tenant round trip served unexpected body %q", body)
			}
			_ = expose.Process.Kill()
			<-done
			return
		}
		select {
		case err := <-done:
			t.Fatalf("prior release client exited after readiness: %v\n%s", err, output.String())
		case <-time.After(500 * time.Millisecond):
		}
	}
	t.Fatalf("prior release client registered at %s but the tunnel path never served; client output:\n%s", publicURL, output.String())
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) append(line string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf.WriteString(line)
	b.buf.WriteString("\n")
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
