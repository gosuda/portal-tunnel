package portal

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/gosuda/portal-tunnel/v2/portal/transport"
	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestNewServerRejectsPortalURLCredentialsWithoutEchoingThem(t *testing.T) {
	_, err := NewServer(ServerConfig{
		PortalURL: "https://user:secret@localhost",
		StateDir:  t.TempDir(),
	})
	if err == nil {
		t.Fatal("NewServer() error = nil, want credential rejection")
	}
	if strings.Contains(err.Error(), "user") || strings.Contains(err.Error(), "secret") {
		t.Fatalf("NewServer() error exposes PORTAL_URL credentials: %q", err)
	}
}

func TestHTTPRedirectTargetValidation(t *testing.T) {
	for _, target := range []string{"http://localhost:4017", "http://relay.example", "//relay.example", "https://user:pass@relay.example", "https://relay.example:0", "https://relay.example:65536", "https://relay.example:bad", "https://relay.example:", "https:///missing-host", "https://./"} {
		t.Run(target, func(t *testing.T) {
			if _, err := NormalizeHTTPRedirectConfig(types.HTTPRedirectConfig{Enabled: true}, target); err == nil {
				t.Fatal("NormalizeHTTPRedirectConfig() error = nil, want invalid redirect target rejection")
			}
		})
	}

	// net/url accepts HTTPS schemes regardless of their spelling.
	for _, hsts := range []bool{false, true} {
		scheme := "HTTPS"
		if hsts {
			scheme = "hTtPs"
		}
		t.Run(scheme, func(t *testing.T) {
			cfg, err := NormalizeHTTPRedirectConfig(types.HTTPRedirectConfig{
				Enabled: true,
				HSTS:    hsts,
			}, scheme+"://localhost:4017/base/?configured=discarded#fragment")
			if err != nil {
				t.Fatalf("NormalizeHTTPRedirectConfig() error = %v, want %q scheme accepted", err, scheme)
			}
			if !cfg.Enabled || cfg.Addr != types.DefaultHTTPRedirectAddr || cfg.HSTS != hsts {
				t.Fatalf("NormalizeHTTPRedirectConfig() cfg = %+v, want enabled config with default redirect address and hsts=%v", cfg, hsts)
			}
		})
	}
}

func TestNewServerSeparatesPublicAndLocalSNIPorts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		portalURL      string
		localSNIPort   int
		wantLocalPort  int
		wantPublicPort int
	}{
		{"default ports", "https://relay.example.com", 0, 443, 443},
		{"local bind override", "https://relay.example.com", 8443, 8443, 443},
		{"explicit public port", "https://relay.example.com:9443", 443, 443, 9443},
		{"unoverridden listener follows public port", "https://relay.example.com:9443", 0, 9443, 9443},
		{"explicit override keeps mapped listener", "https://localhost:8443", 443, 443, 8443},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg, err := ValidateServerConfig(ServerConfig{
				PortalURL: tc.portalURL,
				StateDir:  t.TempDir(),
				SNIPort:   tc.localSNIPort,
			})
			if err != nil {
				t.Fatalf("ValidateServerConfig() error = %v", err)
			}
			if got := cfg.SNIPort; got != tc.wantLocalPort {
				t.Fatalf("ServerConfig.SNIPort = %d, want local port %d", got, tc.wantLocalPort)
			}
			// DefaultSNIPort is the shared derivation: the public port is the
			// PORTAL_URL port, and an unoverridden local listener follows it.
			if got := DefaultSNIPort(cfg.PortalURL); got != tc.wantPublicPort {
				t.Fatalf("DefaultSNIPort(%q) = %d, want public port %d", cfg.PortalURL, got, tc.wantPublicPort)
			}
		})
	}
}

func TestRegisterLeaseWithUDPAndRawTCP(t *testing.T) {
	t.Parallel()

	registry := newTestRegistry(t, true, true)
	_, resp, err := registry.Register(types.RegisterChallengeRequest{
		Identity:   newTestLeaseIdentity(t, "demo"),
		UDPEnabled: true,
		TCPEnabled: true,
	}, "203.0.113.10", "", types.RelayDescriptor{}, nil)
	if err != nil {
		t.Fatalf("registry.Register() error = %v", err)
	}
	if resp.SNIPort != 443 {
		t.Fatalf("RegisterResponse.SNIPort = %d, want registry public port 443", resp.SNIPort)
	}
	if !resp.UDPEnabled || !resp.TCPEnabled || resp.UDPAddr == "" || resp.TCPAddr == "" {
		t.Fatalf("RegisterResponse transports = %+v, want UDP and raw TCP endpoints", resp)
	}
	if _, ok := registry.Lookup("demo.example.com"); !ok {
		t.Fatal("Lookup(derived public hostname) = false, want registered lease")
	}
}

func TestRawPortsAreAllocatedPerIdentity(t *testing.T) {
	t.Parallel()

	registry := newTestRegistry(t, true, true)
	register := func(clientIP string) types.RegisterResponse {
		t.Helper()
		_, resp, err := registry.Register(types.RegisterChallengeRequest{
			Identity:   newTestLeaseIdentity(t, "shared"),
			UDPEnabled: true,
			TCPEnabled: true,
		}, clientIP, "", types.RelayDescriptor{}, nil)
		if err != nil {
			t.Fatalf("registry.Register() error = %v", err)
		}
		return resp
	}

	first := register("203.0.113.10")
	second := register("203.0.113.11")
	if first.UDPAddr == second.UDPAddr || first.TCPAddr == second.TCPAddr {
		t.Fatalf("different identities shared raw endpoints: first=%+v second=%+v", first, second)
	}
}

// A connector that cannot open a raw stream - a browser - reaches the reverse session
// over a WebSocket, carrying the reverse capability as a subprotocol since the WebSocket
// constructor cannot set headers.
func TestConnectAcceptsWebSocketReverseSession(t *testing.T) {
	t.Parallel()

	_, relayURL, capability := newConnectTestRelay(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	socket, _, err := websocket.Dial(ctx, wsURL(relayURL), &websocket.DialOptions{
		Subprotocols: []string{types.ReverseSubprotocol, capability},
	})
	if err != nil {
		t.Fatalf("Dial() error = %v, want an accepted reverse session", err)
	}
	t.Cleanup(func() { _ = socket.CloseNow() })

	// Only the marker comes back, so the handshake response does not echo the credential.
	if got := socket.Subprotocol(); got != types.ReverseSubprotocol {
		t.Fatalf("Subprotocol() = %q, want %q", got, types.ReverseSubprotocol)
	}
}

// The WebSocket carrier takes its capability only from the subprotocols, beside the
// marker; the raw carrier's header does not admit it.
func TestConnectRejectsWebSocketWithoutCapability(t *testing.T) {
	t.Parallel()

	_, relayURL, capability := newConnectTestRelay(t)
	for name, opts := range map[string]*websocket.DialOptions{
		"no capability": {Subprotocols: []string{types.ReverseSubprotocol}},
		"no marker":     {Subprotocols: []string{capability}},
		"header only": {
			Subprotocols: []string{types.ReverseSubprotocol},
		},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		socket, _, err := websocket.Dial(ctx, wsURL(relayURL), opts)
		cancel()
		if err == nil {
			_ = socket.CloseNow()
			t.Errorf("%s: Dial() error = nil, want the session refused", name)
		}
	}
}

// The session is admitted for one lease and ends with it.
func TestConnectEndsWebSocketSessionWithTheLease(t *testing.T) {
	t.Parallel()

	server, relayURL, capability := newConnectTestRelay(t)
	lease, err := server.registry.admitReverseCapability(capability)
	if err != nil {
		t.Fatalf("admitReverseCapability() error = %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	session, err := transport.DialReverseMux(ctx, relayURL, capability)
	if err != nil {
		t.Fatalf("DialReverseMux() error = %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })

	lease.stream.Close()
	select {
	case <-session.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("reverse session still open after its lease closed")
	}
}

func newConnectTestRelay(t *testing.T) (*Server, *url.URL, string) {
	t.Helper()

	registry := newTestRegistry(t, false, false)
	_, registered, err := registry.Register(types.RegisterChallengeRequest{
		Identity: newTestLeaseIdentity(t, "browser"),
	}, "203.0.113.10", "", types.RelayDescriptor{}, nil)
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	server := &Server{registry: registry}
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		server.HandleConnect(w, r, "203.0.113.10")
	}))
	t.Cleanup(relay.Close)

	relayURL, err := url.Parse(relay.URL + types.PathSDKConnect)
	if err != nil {
		t.Fatal(err)
	}
	return server, relayURL, registered.ReverseEndpoint.Capability
}

func wsURL(relayURL *url.URL) string {
	return strings.Replace(relayURL.String(), "http://", "ws://", 1)
}
