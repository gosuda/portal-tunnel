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

	"github.com/gosuda/portal-tunnel/v2/cmd/relay-server/policy"
	"github.com/gosuda/portal-tunnel/v2/portal"
	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func TestPublicIngressPreservesRegistrationPeer(t *testing.T) {
	sniPort := harnessPort(t, "127.0.0.1")
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
	if err := server.Start(ctx, relayHandler(server, nil)); err != nil {
		t.Fatalf("start portal server: %v", err)
	}
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

func TestConnectRejectsRoutingBannedIdentity(t *testing.T) {
	sniPort := harnessPort(t, "127.0.0.1")
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
	access := policy.NewStore()
	if err := server.Start(ctx, policy.Mux(server, nil, nil, nil, access, policy.DefaultPreAuthConfig())); err != nil {
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
	proposedAccess := access.Snapshot()
	identityKey, err := types.ParseServiceIdentityKey(leases[0].IdentityKey)
	if err != nil {
		t.Fatal(err)
	}
	proposedAccess.Ban(identityKey)
	committed := access.Commit(proposedAccess)
	server.SetServiceIdentityAccess(identityKey, committed.Access(identityKey), committed.Revision())

	if err := utils.HTTPDoAPIPath(ctx, client, base, http.MethodPost, types.PathSDKRegisterChallenge, types.RegisterChallengeRequest{Identity: leaseIdentity}, nil, &challenge); err != nil {
		t.Fatalf("register challenge after ban: %v", err)
	}

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
