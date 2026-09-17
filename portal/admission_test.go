package portal

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func TestPreAuthBudgetsAndVerifiedIdentityHandoff(t *testing.T) {
	server, err := NewServer(ServerConfig{PortalURL: "https://localhost", StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	// Invalid requests pay their endpoint cost, without any extra failure penalty.
	for range 4 {
		req := httptest.NewRequest(http.MethodPost, types.PathSDKRegister, strings.NewReader(`{}`))
		response := httptest.NewRecorder()
		server.handleRegister(response, req)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("register status = %d", response.Code)
		}
	}
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, types.PathSDKRegisterChallenge, strings.NewReader(`{}`))
	server.handleRegisterChallenge(response, req)
	if response.Code != http.StatusTooManyRequests || response.Header().Get("Retry-After") == "" {
		t.Fatalf("shared endpoint budget: %d, %v", response.Code, response.Header())
	}
	record, registered, err := server.registry.Register(types.RegisterChallengeRequest{Identity: newTestLeaseIdentity(t, "verified")}, "192.0.2.1", "", types.RelayDescriptor{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(record.Close)
	response = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, types.PathSDKRenew, strings.NewReader(`{"access_token":"`+registered.AccessToken+`"}`))
	server.handleRenew(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("verified identity consumed source budget: %d %s", response.Code, response.Body.String())
	}
	server.PolicyRuntime().BanIdentity(record.Key())
	response = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, types.PathSDKConnect, nil)
	req.Header.Set(types.HeaderReverseCapability, registered.ReverseEndpoint.Capability)
	server.handleConnect(response, req)
	if response.Code != http.StatusForbidden {
		t.Fatalf("identity routing ban bypassed: %d", response.Code)
	}

}

func TestPublicIngressPreservesRegistrationPeer(t *testing.T) {
	server, err := NewServer(ServerConfig{PortalURL: "https://localhost", StateDir: t.TempDir(), APIListenAddr: "127.0.0.1:0", SNIListenAddr: "127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := server.Start(ctx, nil); err != nil {
		t.Fatal(err)
	}
	// A distinct loopback source detects an accidental internal TCP re-dial.
	dialer := &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.2")}, Timeout: 5 * time.Second}
	transport := &http.Transport{DialContext: dialer.DialContext, TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "localhost"}}
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	t.Cleanup(func() {
		transport.CloseIdleConnections()
		cancel()
		if err := server.Wait(); err != nil {
			t.Error(err)
		}
	})
	leaseIdentity := newTestLeaseIdentity(t, "peer")
	headers := http.Header{"X-Forwarded-For": {"198.51.100.99"}, "X-Real-IP": {"198.51.100.99"}}
	// Both public SNI handoff and direct API preserve the socket source; forwarded
	// headers remain untrusted by default on both paths.
	for _, listener := range []net.Listener{server.sniListener, server.apiListener} {
		base, err := url.Parse("https://" + listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		var challenge types.RegisterChallengeResponse
		if err := utils.HTTPDoAPIPath(ctx, client, base, http.MethodPost, types.PathSDKRegisterChallenge, types.RegisterChallengeRequest{Identity: leaseIdentity}, headers, &challenge); err != nil {
			t.Fatal(err)
		}
		signature, err := identity.NewLocalAuthority(leaseIdentity).SignEthereumPersonalMessage(challenge.SIWEMessage)
		if err != nil {
			t.Fatal(err)
		}
		var registered types.RegisterResponse
		if err := utils.HTTPDoAPIPath(ctx, client, base, http.MethodPost, types.PathSDKRegister, types.RegisterRequest{ChallengeID: challenge.ChallengeID, SIWEMessage: challenge.SIWEMessage, SIWESignature: signature}, headers, &registered); err != nil {
			t.Fatal(err)
		}
		leases := server.PolicyLeases()
		if len(leases) != 1 || leases[0].ClientIP != "127.0.0.2" {
			t.Fatalf("registration peer = %+v", leases)
		}
	}
}
