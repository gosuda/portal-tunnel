package e2e_test

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal"
	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

// The single public ingress path — the SNI listener handing control-plane
// TLS connections in-process to the API server — must keep the registering
// TCP source as the lease client IP; forwarded headers stay untrusted by
// default, so a spoofed X-Forwarded-For cannot buy a fresh NAT budget.
func TestPublicIngressPreservesRegistrationPeer(t *testing.T) {
	sniPort := harnessPort(t)
	server, err := portal.NewServer(portal.ServerConfig{
		PortalURL:     "https://localhost",
		StateDir:      t.TempDir(),
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
	leaseIdentity, err := identity.Generate("peer-ingress")
	if err != nil {
		t.Fatalf("generate lease identity: %v", err)
	}
	headers := http.Header{"X-Forwarded-For": {"198.51.100.99"}, "X-Real-IP": {"198.51.100.99"}}
	// SNI "localhost" equals the relay identity name from PortalURL, so the
	// SNI listener routes this connection to the control-plane API server;
	// the socket peer must survive that in-process handoff.
	base, err := url.Parse("https://127.0.0.1:" + strconv.Itoa(sniPort))
	if err != nil {
		t.Fatalf("parse ingress base URL: %v", err)
	}
	var challenge types.RegisterChallengeResponse
	if err := utils.HTTPDoAPIPath(ctx, client, base, http.MethodPost, types.PathSDKRegisterChallenge, types.RegisterChallengeRequest{Identity: leaseIdentity}, headers, &challenge); err != nil {
		t.Fatalf("register challenge: %v", err)
	}
	signature, err := identity.NewLocalAuthority(leaseIdentity).SignEthereumPersonalMessage(challenge.SIWEMessage)
	if err != nil {
		t.Fatalf("sign challenge: %v", err)
	}
	var registered types.RegisterResponse
	if err := utils.HTTPDoAPIPath(ctx, client, base, http.MethodPost, types.PathSDKRegister, types.RegisterRequest{ChallengeID: challenge.ChallengeID, SIWEMessage: challenge.SIWEMessage, SIWESignature: signature}, headers, &registered); err != nil {
		t.Fatalf("register lease: %v", err)
	}
	leases := server.PolicyLeases()
	if len(leases) != 1 || leases[0].ClientIP != "127.0.0.2" {
		t.Fatalf("registration peer = %+v, want socket source 127.0.0.2", leases)
	}
}

// A routing-banned identity loses its reverse capability on the wire: the
// public connect endpoint must answer Forbidden before any connection is
// offered to the lease stream.
func TestConnectRejectsRoutingBannedIdentity(t *testing.T) {
	sniPort := harnessPort(t)
	server, err := portal.NewServer(portal.ServerConfig{
		PortalURL:     "https://localhost",
		StateDir:      t.TempDir(),
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
	transport := &http.Transport{DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext, TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "localhost"}}
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	t.Cleanup(func() {
		transport.CloseIdleConnections()
		cancel()
		if err := server.Wait(); err != nil {
			t.Error(err)
		}
	})
	leaseIdentity, err := identity.Generate("banned-ingress")
	if err != nil {
		t.Fatalf("generate lease identity: %v", err)
	}
	// The transport sends SNI "localhost", the relay identity name from
	// PortalURL, so the SNI listener hands this connection to the
	// control-plane API server — public API surface only, no direct listener.
	base, err := url.Parse("https://127.0.0.1:" + strconv.Itoa(sniPort))
	if err != nil {
		t.Fatalf("parse API base URL: %v", err)
	}
	var challenge types.RegisterChallengeResponse
	if err := utils.HTTPDoAPIPath(ctx, client, base, http.MethodPost, types.PathSDKRegisterChallenge, types.RegisterChallengeRequest{Identity: leaseIdentity}, nil, &challenge); err != nil {
		t.Fatalf("register challenge: %v", err)
	}
	signature, err := identity.NewLocalAuthority(leaseIdentity).SignEthereumPersonalMessage(challenge.SIWEMessage)
	if err != nil {
		t.Fatalf("sign challenge: %v", err)
	}
	var registered types.RegisterResponse
	if err := utils.HTTPDoAPIPath(ctx, client, base, http.MethodPost, types.PathSDKRegister, types.RegisterRequest{ChallengeID: challenge.ChallengeID, SIWEMessage: challenge.SIWEMessage, SIWESignature: signature}, nil, &registered); err != nil {
		t.Fatalf("register lease: %v", err)
	}
	leases := server.PolicyLeases()
	if len(leases) != 1 || leases[0].IdentityKey == "" {
		t.Fatalf("policy leases = %+v, want the registered identity key", leases)
	}
	server.PolicyRuntime().BanIdentity(leases[0].IdentityKey)

	connect, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://127.0.0.1:"+strconv.Itoa(sniPort)+types.PathSDKConnect, nil)
	if err != nil {
		t.Fatalf("build connect request: %v", err)
	}
	connect.Header.Set(types.HeaderReverseCapability, registered.ReverseEndpoint.Capability)
	resp, err := client.Do(connect)
	if err != nil {
		t.Fatalf("connect request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("connect status = %d, want forbidden for banned identity", resp.StatusCode)
	}
}
