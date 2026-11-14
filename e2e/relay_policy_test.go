package e2e_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/sdk"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func buildRelayBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "relay-server.exe")
	build := exec.CommandContext(t.Context(), "go", "build", "-o", bin, "./cmd/relay-server")
	build.Dir = ".."
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build relay: %v\n%s", err, output)
	}
	return bin
}

func relayTenantClient(t *testing.T, client *http.Client, base *url.URL) *http.Client {
	t.Helper()
	transport := client.Transport.(*http.Transport).Clone()
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, base.Host)
	}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 5 * time.Second}
}

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

func runPolicyRelayProcess(t *testing.T, ctx context.Context, bin string, commandArgs, args []string) (<-chan error, func()) {
	t.Helper()
	command := exec.CommandContext(ctx, bin, append(commandArgs, args...)...)
	command.Dir = t.TempDir()
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	serveResult := make(chan error, 1)
	exited := make(chan struct{})
	go func() {
		serveResult <- command.Wait()
		close(exited)
	}()
	return serveResult, func() {
		<-exited
		if t.Failed() {
			t.Log(output.String())
		}
	}
}

func openPolicyRelayControl(t *testing.T, stateDir string, base *url.URL, serveResult <-chan error) *http.Client {
	t.Helper()
	waitForRelayCertificateMaterial(t, stateDir)
	client := relayControlClient(t, stateDir)
	waitRelayReady(t, client, base.String(), serveResult)
	return client
}

func startPolicyRelay(t *testing.T, stateDir string, args ...string) (context.Context, *url.URL, *http.Client) {
	t.Helper()
	bin := buildRelayBinary(t)
	frontend := t.TempDir()
	if err := os.WriteFile(filepath.Join(frontend, "index.html"), []byte("portal"), 0o600); err != nil {
		t.Fatal(err)
	}
	port := strconv.Itoa(harnessPort(t, "127.0.0.1"))
	base, err := url.Parse("https://127.0.0.1:" + port)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	commandArgs := []string{
		"--portal-url", "https://localhost:" + port,
		"--identity-path", stateDir,
		"--frontend-dir", frontend,
		"--admin-token", "admin-test",
	}
	serveResult, waitRelay := runPolicyRelayProcess(t, ctx, bin, commandArgs, args)
	t.Cleanup(func() {
		cancel()
		waitRelay()
	})
	return ctx, base, openPolicyRelayControl(t, stateDir, base, serveResult)
}

func generatePolicyIdentities(t *testing.T, names ...string) []types.Identity {
	t.Helper()
	identities := make([]types.Identity, len(names))
	for i, name := range names {
		var err error
		identities[i], err = identity.Generate(name)
		if err != nil {
			t.Fatal(err)
		}
	}
	return identities
}

func exposePolicyIdentities(t *testing.T, ctx context.Context, relayPort string, identities []types.Identity) {
	t.Helper()
	for _, tenant := range identities {
		exposure, err := sdk.Expose(ctx, tenant, []string{"https://localhost:" + relayPort})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = exposure.Close() })
		readyCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		_, err = exposure.WaitReady(readyCtx)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
	}
}

func startBandwidthPhase(t *testing.T, stateDir string, identities []types.Identity, defaultBPS int) (context.Context, *url.URL, *http.Client) {
	t.Helper()
	ctx, base, client := startPolicyRelay(t, stateDir, "--default-identity-bps", strconv.Itoa(defaultBPS))
	exposePolicyIdentities(t, ctx, base.Port(), identities)
	return ctx, base, client
}

func checkPolicyLimits(t *testing.T, ctx context.Context, client *http.Client, base *url.URL, identities []types.Identity, want []int64) {
	t.Helper()
	headers := http.Header{"Authorization": {"Bearer admin-test"}}
	var state types.PolicyStateResponse
	if err := utils.HTTPDoAPIPath(ctx, client, base, http.MethodGet, types.PathPolicyState, nil, headers, &state); err != nil {
		t.Fatal(err)
	}
	got := make(map[string]int64)
	for _, lease := range state.Leases {
		got[lease.IdentityKey] = lease.BPS
	}
	for i, tenant := range identities {
		if limit, found := got[tenant.Key()]; !found || limit != want[i] {
			t.Fatalf("identity %s limit = %d (found %v), want %d", tenant.Name, limit, found, want[i])
		}
	}
}

func postLeasePolicyUpdate(t *testing.T, ctx context.Context, client *http.Client, base *url.URL, update types.LeasePolicyUpdate) {
	t.Helper()
	headers := http.Header{"Authorization": {"Bearer admin-test"}}
	if err := utils.HTTPDoAPIPath(ctx, client, base, http.MethodPost, types.PathPolicyLeases, update, headers, nil); err != nil {
		t.Fatal(err)
	}
}

func checkBandwidthOverrides(t *testing.T, stateDir string, identities []types.Identity) {
	t.Helper()
	ctx, base, client := startBandwidthPhase(t, stateDir, identities, types.DefaultIdentityBPS)
	checkPolicyLimits(t, ctx, client, base, identities, []int64{types.DefaultIdentityBPS, types.DefaultIdentityBPS, types.DefaultIdentityBPS})
	for i, bps := range []int64{4 * types.DefaultIdentityBPS, 0} {
		postLeasePolicyUpdate(t, ctx, client, base, types.LeasePolicyUpdate{IdentityKey: identities[i].Key(), BPS: &bps})
	}
	checkPolicyLimits(t, ctx, client, base, identities, []int64{4 * types.DefaultIdentityBPS, 0, types.DefaultIdentityBPS})
}

func checkBandwidthReset(t *testing.T, stateDir string, identities []types.Identity) {
	t.Helper()
	defaultBPS := 2 * types.DefaultIdentityBPS
	ctx, base, client := startBandwidthPhase(t, stateDir, identities, defaultBPS)
	checkPolicyLimits(t, ctx, client, base, identities, []int64{4 * types.DefaultIdentityBPS, 0, int64(defaultBPS)})

	zero := int64(0)
	conflict := types.LeasePolicyUpdate{IdentityKey: identities[0].Key(), BPS: &zero, ResetBPS: true}
	err := utils.HTTPDoAPIPath(ctx, client, base, http.MethodPost, types.PathPolicyLeases, conflict, http.Header{"Authorization": {"Bearer admin-test"}}, nil)
	if apiErr, ok := errors.AsType[*types.APIRequestError](err); !ok || apiErr.StatusCode != http.StatusBadRequest {
		t.Fatalf("conflicting bandwidth update: %v", err)
	}
	checkPolicyLimits(t, ctx, client, base, identities, []int64{4 * types.DefaultIdentityBPS, 0, int64(defaultBPS)})

	for _, tenant := range identities[:2] {
		postLeasePolicyUpdate(t, ctx, client, base, types.LeasePolicyUpdate{IdentityKey: tenant.Key(), ResetBPS: true})
	}
	checkPolicyLimits(t, ctx, client, base, identities, []int64{int64(defaultBPS), int64(defaultBPS), int64(defaultBPS)})
}

func checkBandwidthInheritance(t *testing.T, stateDir string, identities []types.Identity) {
	t.Helper()
	defaultBPS := 3 * types.DefaultIdentityBPS
	ctx, base, client := startBandwidthPhase(t, stateDir, identities, defaultBPS)
	checkPolicyLimits(t, ctx, client, base, identities, []int64{int64(defaultBPS), int64(defaultBPS), int64(defaultBPS)})
}

func TestRelayIdentityBandwidthDefaultsAndOverrides(t *testing.T) {
	stateDir := t.TempDir()
	identities := generatePolicyIdentities(t, "upgraded", "unlimited", "inherited")
	t.Run("initial defaults and overrides", func(t *testing.T) {
		checkBandwidthOverrides(t, stateDir, identities)
	})
	t.Run("survive restart and reset", func(t *testing.T) {
		checkBandwidthReset(t, stateDir, identities)
	})
	t.Run("restore inheritance after restart", func(t *testing.T) {
		checkBandwidthInheritance(t, stateDir, identities)
	})
}

func ptr[T any](value T) *T { return &value }

func waitPolicyLease(t *testing.T, ctx context.Context, client *http.Client, base *url.URL) types.PolicyLease {
	t.Helper()
	headers := http.Header{"Authorization": {"Bearer admin-test"}}
	deadline := time.After(15 * time.Second)
	for {
		var state types.PolicyStateResponse
		if err := utils.HTTPDoAPIPath(ctx, client, base, http.MethodGet, types.PathPolicyState, nil, headers, &state); err != nil {
			t.Fatal(err)
		}
		if len(state.Leases) > 0 {
			return state.Leases[0]
		}
		select {
		case <-deadline:
			t.Fatal("lease never registered")
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func setLeasePolicy(t *testing.T, ctx context.Context, client *http.Client, base *url.URL, update types.LeasePolicyUpdate) {
	t.Helper()
	headers := http.Header{"Authorization": {"Bearer admin-test"}}
	if err := utils.HTTPDoAPIPath(ctx, client, base, http.MethodPost, types.PathPolicyLeases, update, headers, new(struct{})); err != nil {
		t.Fatal(err)
	}
}
