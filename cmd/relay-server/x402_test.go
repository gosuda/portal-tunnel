package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal"
	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestResolveX402FacilitatorRequiresRecipient(t *testing.T) {
	cfg := appConfig{X402Enabled: true}
	if _, err := resolveX402Facilitator(cfg); err == nil {
		t.Fatal("resolveX402Facilitator() error = nil, want error for enabled x402 without recipient")
	}
	cfg.X402PayTo = "0xrecipient"
	settings, err := resolveX402Facilitator(cfg)
	if err != nil {
		t.Fatalf("resolveX402Facilitator() error = %v, want nil with recipient set", err)
	}
	if !settings.Enabled || settings.Testnet {
		t.Fatalf("resolveX402Facilitator() = %+v, want enabled mainnet with recipient set", settings)
	}

	testnetSettings, err := resolveX402Facilitator(appConfig{X402Enabled: true, X402Testnet: true, X402PayTo: "0xrecipient"})
	if err != nil {
		t.Fatalf("resolveX402Facilitator() error = %v, want nil with recipient set", err)
	}
	if !testnetSettings.Enabled || !testnetSettings.Testnet {
		t.Fatalf("resolveX402Facilitator() = %+v, want enabled testnet with recipient set", testnetSettings)
	}

	disabled, err := resolveX402Facilitator(appConfig{X402PayTo: "0xrecipient"})
	if err != nil {
		t.Fatalf("resolveX402Facilitator() error = %v, want nil when disabled", err)
	}
	if disabled.Enabled {
		t.Fatalf("resolveX402Facilitator() = %+v, want disabled without --x402-enabled", disabled)
	}
}

// Enabling the facilitator must interpose it on /api/x402 only: the payment
// endpoints answer without reaching the relay handler, and every other path
// still does. With payments disabled the relay handler must see /api/x402 too.
func TestComposeRelayHandlerMountsFacilitatorOnlyWhenEnabled(t *testing.T) {
	var relayHits []string
	relayAPI := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		relayHits = append(relayHits, r.URL.Path)
		if r.URL.Path == types.X402SupportedPath {
			w.WriteHeader(http.StatusTeapot)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	disabled, err := composeRelayHandler(x402FacilitatorSettings{}, nil, relayAPI)
	if err != nil {
		t.Fatalf("composeRelayHandler() error = %v, want nil when disabled", err)
	}
	rec := httptest.NewRecorder()
	disabled.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, types.X402SupportedPath, nil))
	if rec.Code != http.StatusTeapot {
		t.Fatalf("disabled facilitator status = %d, want relay handler to own %s (%d)", rec.Code, types.X402SupportedPath, http.StatusTeapot)
	}

	enabled, err := composeRelayHandler(x402FacilitatorSettings{Enabled: true}, nil, relayAPI)
	if err != nil {
		t.Fatalf("composeRelayHandler() error = %v, want nil when enabled", err)
	}
	rec = httptest.NewRecorder()
	enabled.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, types.X402SupportedPath, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s status = %d, want %d from the mounted facilitator", types.X402SupportedPath, rec.Code, http.StatusOK)
	}
	rec = httptest.NewRecorder()
	enabled.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/app", nil))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("GET /app status = %d, want %d from the relay handler", rec.Code, http.StatusNoContent)
	}
	if len(relayHits) != 2 || relayHits[0] != types.X402SupportedPath || relayHits[1] != "/app" {
		t.Fatalf("relay handler saw %v, want [%s /app] (the facilitator must answer %s)", relayHits, types.X402SupportedPath, types.X402SupportedPath)
	}
}

// GET /sdk/domain must serve the composed report in the production wiring:
// with the facilitator enabled, runServer hands the path to the application
// (ApplicationOwnsDomainReport), portal's apiHandler delegates it, and the
// composed handler merges the facilitator block onto server.DomainReport().
// A wrapper exercised in isolation never sees that delegated traffic, so this
// drives a real portal.Server request path — SNI listener and apiHandler
// included — and fails if portal answers the path itself.
func TestRelayServesComposedDomainX402Metadata(t *testing.T) {
	port := relayTestPort(t)
	portalURL := "https://127.0.0.1:" + strconv.Itoa(port)
	stateDir := t.TempDir()
	server, err := portal.NewServer(portal.ServerConfig{
		PortalURL:                   portalURL,
		StateDir:                    stateDir,
		SNIListenAddr:               "127.0.0.1:" + strconv.Itoa(port),
		SNIPort:                     port,
		ApplicationOwnsDomainReport: true,
	})
	if err != nil {
		t.Fatalf("create relay server: %v", err)
	}
	relayAPI, err := NewRelayAPI(server, filepath.Join(stateDir, types.RelayPolicyFilename), "", frontendDir(t), false)
	if err != nil {
		t.Fatalf("create relay api: %v", err)
	}
	handler, err := composeRelayHandler(x402FacilitatorSettings{
		Enabled:   true,
		Testnet:   true,
		PayTo:     "0xrecipient",
		PortalURL: portalURL,
	}, server, relayAPI.Handler())
	if err != nil {
		t.Fatalf("compose relay handler: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(ctx, handler) }()
	t.Cleanup(func() {
		cancel()
		shutdownCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if err := server.Shutdown(shutdownCtx); err != nil {
			t.Errorf("shutdown relay server: %v", err)
		}
		if err := server.Wait(); err != nil {
			t.Errorf("wait for relay server: %v", err)
		}
		select {
		case err := <-serveDone:
			if err != nil && !errors.Is(err, context.Canceled) {
				t.Errorf("serve relay server: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("relay server did not stop")
		}
	})

	// An IP-literal dial sends no SNI, so the SNI listener routes the
	// connection to the control plane (same shape as the e2e authority
	// rotation suite). TLS verification is skipped: loopback self-signed.
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		Timeout:   2 * time.Second,
	}
	var body []byte
	var lastErr error
	deadline := time.Now().Add(15 * time.Second)
	for body == nil {
		resp, err := client.Get(portalURL + types.PathSDKDomain)
		if err != nil {
			lastErr = err
		} else {
			raw, readErr := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			switch {
			case readErr != nil:
				lastErr = readErr
			case resp.StatusCode != http.StatusOK:
				lastErr = fmt.Errorf("status %d", resp.StatusCode)
			default:
				body = raw
				continue
			}
		}
		if !time.Now().Before(deadline) {
			t.Fatalf("GET %s did not answer: %v", types.PathSDKDomain, lastErr)
		}
		<-time.After(100 * time.Millisecond)
	}

	var envelope types.APIEnvelope[types.DomainResponse]
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatalf("decode /sdk/domain response: %v", err)
	}
	if !envelope.OK {
		t.Fatalf("/sdk/domain envelope not ok: %+v", envelope)
	}
	info := envelope.Data.X402
	facilitatorURL := portalURL + types.PathX402Facilitator
	if !info.Enabled || info.URL != facilitatorURL || info.PayTo != "0xrecipient" {
		t.Fatalf("domain x402 metadata = %+v, want enabled with url %q and pay-to 0xrecipient", info, facilitatorURL)
	}
	if envelope.Data.ProtocolVersion != types.SDKVersion {
		t.Fatalf("domain protocol_version = %q, want relay-owned %q preserved through composition", envelope.Data.ProtocolVersion, types.SDKVersion)
	}
}

// frontendDir builds the minimal frontend directory NewRelayAPI accepts when
// the embedded dist is not built in the worktree.
func frontendDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("portal"), 0600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// relayTestPort allocates an explicit listener port outside the kernel's
// ephemeral range. The relay config needs a concrete port before startup, and
// a released ephemeral probe port can be stolen by any parallel bind(":0")
// before the relay rebinds it.
func relayTestPort(t *testing.T) int {
	t.Helper()
	lo, hi := ephemeralPortRange()
	start, end := 31000, 32100
	if start <= hi && end >= lo {
		start, end = hi+1, min(hi+1100, 65535)
	}
	for port := start; port <= end; port++ {
		listener, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err != nil {
			continue
		}
		if err := listener.Close(); err != nil {
			t.Fatalf("close port probe: %v", err)
		}
		return port
	}
	t.Fatal("no free listener port outside the ephemeral range")
	return 0
}

// ephemeralPortRange reports the kernel's automatic port allocation range,
// assuming the common default when it cannot be read.
func ephemeralPortRange() (lo, hi int) {
	data, err := os.ReadFile("/proc/sys/net/ipv4/ip_local_port_range")
	if err != nil {
		return 49152, 65535
	}
	fields := strings.Fields(string(data))
	if len(fields) != 2 {
		return 49152, 65535
	}
	parsedLo, loErr := strconv.Atoi(fields[0])
	parsedHi, hiErr := strconv.Atoi(fields[1])
	if loErr != nil || hiErr != nil {
		return 49152, 65535
	}
	return parsedLo, parsedHi
}
