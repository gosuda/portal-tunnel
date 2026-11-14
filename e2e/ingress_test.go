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

func registerLeaseIdentity(t *testing.T, ctx context.Context, client *http.Client, base *url.URL, leaseIdentity types.Identity, headers http.Header) types.RegisterResponse {
	t.Helper()
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
	return registered
}

func bootPeerIngressRelay(t *testing.T) (*portal.Server, context.Context, *http.Client, *url.URL) {
	t.Helper()
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
	if err := server.Start(ctx, relayHandler(server, nil)); err != nil {
		t.Fatalf("start portal server: %v", err)
	}
	client := trackPeerIngressClient(t, cancel, server)
	base, err := url.Parse("https://127.0.0.1:" + strconv.Itoa(sniPort))
	if err != nil {
		t.Fatalf("parse ingress base URL: %v", err)
	}
	return server, ctx, client, base
}

func trackPeerIngressClient(t *testing.T, cancel context.CancelFunc, server *portal.Server) *http.Client {
	t.Helper()
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
	return client
}

func registerPeerLease(t *testing.T, ctx context.Context, client *http.Client, base *url.URL) {
	t.Helper()
	leaseIdentity, err := identity.Generate("peer-ingress")
	if err != nil {
		t.Fatalf("generate lease identity: %v", err)
	}
	headers := http.Header{"X-Forwarded-For": {"198.51.100.99"}, "X-Real-IP": {"198.51.100.99"}}
	registerLeaseIdentity(t, ctx, client, base, leaseIdentity, headers)
}

func TestPublicIngressPreservesRegistrationPeer(t *testing.T) {
	server, ctx, client, base := bootPeerIngressRelay(t)
	registerPeerLease(t, ctx, client, base)
	leases := server.PolicyLeases()
	if len(leases) != 1 || leases[0].ClientIP != "127.0.0.2" {
		t.Fatalf("registration peer = %+v, want socket source 127.0.0.2", leases)
	}
}

func startBannedIngressServer(t *testing.T, ctx context.Context, sniPort int, access *policy.Store) *portal.Server {
	t.Helper()
	server, err := portal.NewServer(portal.ServerConfig{
		PortalURL:     "https://localhost",
		StateDir:      t.TempDir(),
		SNIListenAddr: "127.0.0.1:" + strconv.Itoa(sniPort),
	})
	if err != nil {
		t.Fatalf("create portal server: %v", err)
	}
	if err := server.Start(ctx, policy.Mux(server, nil, nil, nil, access, policy.DefaultPreAuthConfig())); err != nil {
		t.Fatalf("start portal server: %v", err)
	}
	return server
}

func bootBannedIngressRelay(t *testing.T, ctx context.Context) (*portal.Server, *policy.Store, *http.Client, *url.URL) {
	t.Helper()
	sniPort := harnessPort(t, "127.0.0.1")
	access := policy.NewStore()
	server := startBannedIngressServer(t, ctx, sniPort, access)
	transport := &http.Transport{DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext, TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "localhost"}}
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	t.Cleanup(func() {
		transport.CloseIdleConnections()
		if err := server.Wait(); err != nil {
			t.Error(err)
		}
	})
	base, err := url.Parse("https://127.0.0.1:" + strconv.Itoa(sniPort))
	if err != nil {
		t.Fatalf("parse API base URL: %v", err)
	}
	return server, access, client, base
}

func banRegisteredIdentity(t *testing.T, server *portal.Server, access *policy.Store, leases []types.PolicyLease) {
	t.Helper()
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
}

func assertBannedConnectForbidden(t *testing.T, ctx context.Context, client *http.Client, base *url.URL, capability string) {
	t.Helper()
	connect, err := http.NewRequestWithContext(ctx, http.MethodGet, base.String()+types.PathSDKConnect, nil)
	if err != nil {
		t.Fatalf("build connect request: %v", err)
	}
	connect.Header.Set(types.HeaderReverseCapability, capability)
	request, err := client.Do(connect)
	if err != nil {
		t.Fatalf("connect request: %v", err)
	}
	defer request.Body.Close()
	if request.StatusCode != http.StatusForbidden {
		t.Fatalf("connect status = %d, want forbidden for banned identity", request.StatusCode)
	}
}

func assertBannedIdentityRejected(t *testing.T, ctx context.Context, client *http.Client, base *url.URL, leaseIdentity types.Identity, capability string) {
	t.Helper()
	var challenge types.RegisterChallengeResponse
	if err := utils.HTTPDoAPIPath(ctx, client, base, http.MethodPost, types.PathSDKRegisterChallenge, types.RegisterChallengeRequest{Identity: leaseIdentity}, nil, &challenge); err != nil {
		t.Fatalf("register challenge after ban: %v", err)
	}
	assertBannedConnectForbidden(t, ctx, client, base, capability)
}

func TestConnectRejectsRoutingBannedIdentity(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server, access, client, base := bootBannedIngressRelay(t, ctx)
	leaseIdentity, err := identity.Generate("banned-ingress")
	if err != nil {
		t.Fatalf("generate lease identity: %v", err)
	}
	registered := registerLeaseIdentity(t, ctx, client, base, leaseIdentity, nil)
	banRegisteredIdentity(t, server, access, server.PolicyLeases())
	assertBannedIdentityRejected(t, ctx, client, base, leaseIdentity, registered.ReverseEndpoint.Capability)
}
