package e2e_test

import (
	"context"
	"crypto/tls"
	"errors"
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

func bootSNIRelay(t *testing.T) (*portal.Server, context.Context, string) {
	t.Helper()
	port := harnessPort(t, "127.0.0.1")
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	relay, err := portal.NewServer(portal.ServerConfig{PortalURL: "https://" + addr, StateDir: t.TempDir(), SNIListenAddr: addr, SNIPort: port})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	if err := relay.Start(ctx, relayHandler(relay, nil)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		if err := relay.Shutdown(context.Background()); err != nil {
			t.Error(err)
		}
		if err := relay.Wait(); err != nil {
			t.Error(err)
		}
	})
	return relay, ctx, addr
}

func fillSNIConnections(t *testing.T, addr string) []net.Conn {
	t.Helper()
	var peers []net.Conn
	for range 129 {
		peer, err := net.DialTimeout("tcp", addr, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = peer.Close() })
		peers = append(peers, peer)
	}
	return peers
}

func assertSNIBackpressure(t *testing.T, peers []net.Conn) {
	t.Helper()
	var buf [1]byte
	_ = peers[128].SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	_, err := peers[128].Read(buf[:])
	var netErr net.Error
	if err == nil || (errors.As(err, &netErr) && netErr.Timeout()) {
		t.Fatalf("over-capacity SNI connection not promptly closed: %v", err)
	}
	_ = peers[0].SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if _, err := peers[0].Read(buf[:]); !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("admitted stalled connection closed prematurely: %v", err)
	}
	for _, peer := range peers {
		_ = peer.Close()
	}
}

func awaitSNIAdmissionRecovery(t *testing.T, ctx context.Context, addr string) {
	t.Helper()
	recoveryCtx, recoveryCancel := context.WithTimeout(ctx, 3*time.Second)
	defer recoveryCancel()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		dialer := tls.Dialer{Config: &tls.Config{InsecureSkipVerify: true}}
		conn, err := dialer.DialContext(recoveryCtx, "tcp", addr)
		if err == nil {
			_ = conn.Close()
			break
		}
		select {
		case <-recoveryCtx.Done():
			t.Fatalf("SNI admission did not recover: %v", err)
		case <-ticker.C:
		}
	}
}

func assertShutdownClosesPending(t *testing.T, relay *portal.Server, pending net.Conn) {
	t.Helper()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer shutdownCancel()
	if err := relay.Shutdown(shutdownCtx); err != nil {
		t.Fatal(err)
	}
	if err := relay.Wait(); err != nil {
		t.Fatal(err)
	}
	var buf [1]byte
	_ = pending.SetReadDeadline(time.Now().Add(time.Second))
	var netErr net.Error
	if _, err := pending.Read(buf[:]); err == nil || (errors.As(err, &netErr) && netErr.Timeout()) {
		t.Fatalf("shutdown left SNI socket open: %v", err)
	}
}

func TestSNIPendingAdmissionAndShutdown(t *testing.T) {
	relay, ctx, addr := bootSNIRelay(t)
	peers := fillSNIConnections(t, addr)
	assertSNIBackpressure(t, peers)
	awaitSNIAdmissionRecovery(t, ctx, addr)
	pending, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer pending.Close()
	assertShutdownClosesPending(t, relay, pending)
}

func bootSaturationRelay(t *testing.T) (context.Context, *http.Client, *url.URL) {
	t.Helper()
	minPort := harnessPort(t, "127.0.0.1")
	maxPort := minPort
	for range 8 {
		maxPort = harnessPort(t, "127.0.0.1")
	}
	port := harnessPort(t, "127.0.0.1")
	base, _ := url.Parse("https://127.0.0.1:" + strconv.Itoa(port))
	server, err := portal.NewServer(portal.ServerConfig{PortalURL: base.String(), StateDir: t.TempDir(), SNIListenAddr: base.Host, SNIPort: port, MinPort: minPort, MaxPort: maxPort})
	if err != nil {
		t.Fatal(err)
	}
	if err := server.SetTransportPolicy(false, 0, true, 0); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	if err := server.Start(ctx, relayHandler(server, nil)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); _ = server.Shutdown(context.Background()); _ = server.Wait() })
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, DisableKeepAlives: true}
	t.Cleanup(func() { tr.CloseIdleConnections() })
	return ctx, &http.Client{Transport: tr, Timeout: 3 * time.Second}, base
}

func registerSaturationLeases(t *testing.T, ctx context.Context, client *http.Client, base *url.URL) []types.RegisterResponse {
	t.Helper()
	leases := make([]types.RegisterResponse, 9)
	for i := range leases {
		id, err := identity.Generate("saturation-" + strconv.Itoa(i))
		if err != nil {
			t.Fatal(err)
		}
		var challenge types.RegisterChallengeResponse
		if err := utils.HTTPDoAPIPath(ctx, client, base, http.MethodPost, types.PathSDKRegisterChallenge, types.RegisterChallengeRequest{Identity: id, TCPEnabled: true, TTL: 60}, nil, &challenge); err != nil {
			t.Fatal(err)
		}
		sig, err := identity.NewLocalAuthority(id).SignEthereumPersonalMessage(challenge.SIWEMessage)
		if err != nil {
			t.Fatal(err)
		}
		if err := utils.HTTPDoAPIPath(ctx, client, base, http.MethodPost, types.PathSDKRegister, types.RegisterRequest{ChallengeID: challenge.ChallengeID, SIWEMessage: challenge.SIWEMessage, SIWESignature: sig}, nil, &leases[i]); err != nil {
			t.Fatal(err)
		}
	}
	return leases
}

func assertLeasePortOverflowRejected(t *testing.T, addr string) {
	t.Helper()
	extra, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	var byteBuf [1]byte
	_ = extra.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	_, err = extra.Read(byteBuf[:])
	_ = extra.Close()
	var netErr net.Error
	if err == nil || (errors.As(err, &netErr) && netErr.Timeout()) {
		t.Fatalf("lease overflow not rejected: %v", err)
	}
}

func saturateTCPPorts(t *testing.T, leases []types.RegisterResponse) []net.Conn {
	t.Helper()
	var pending []net.Conn
	for _, lease := range leases[:8] {
		_, rawPort, err := net.SplitHostPort(lease.TCPAddr)
		if err != nil {
			t.Fatal(err)
		}
		addr := net.JoinHostPort("127.0.0.1", rawPort)
		for range 128 {
			conn, err := net.DialTimeout("tcp", addr, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = conn.Close() })
			pending = append(pending, conn)
		}
		assertLeasePortOverflowRejected(t, addr)
	}
	return pending
}

func assertAggregateOverflowRejected(t *testing.T, leases []types.RegisterResponse) {
	t.Helper()
	_, ninthPort, err := net.SplitHostPort(leases[8].TCPAddr)
	if err != nil {
		t.Fatal(err)
	}
	overflow, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", ninthPort), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	var byteBuf [1]byte
	_ = overflow.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	_, err = overflow.Read(byteBuf[:])
	_ = overflow.Close()
	var netErr net.Error
	if err == nil || (errors.As(err, &netErr) && netErr.Timeout()) {
		t.Fatalf("aggregate overflow not rejected: %v", err)
	}
}

func renewAndConnectUnderSaturation(t *testing.T, ctx context.Context, client *http.Client, base *url.URL, leases []types.RegisterResponse, fillStarted time.Time) {
	t.Helper()
	var renewal types.RenewResponse
	if err := utils.HTTPDoAPIPath(ctx, client, base, http.MethodPost, types.PathSDKRenew, types.RenewRequest{AccessToken: leases[0].AccessToken, TTL: 60}, nil, &renewal); err != nil {
		t.Fatalf("tenant saturation blocked fresh root TLS/renew: %v", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, base.String()+types.PathSDKConnect, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set(types.HeaderReverseCapability, leases[8].ReverseEndpoint.Capability)
	request.Header.Set("Connection", "Upgrade")
	request.Header.Set("Upgrade", "raw")
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("tenant saturation blocked reverse authentication: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("reverse authentication under saturation = %d, want 101", response.StatusCode)
	}
	if time.Since(fillStarted) >= 10*time.Second {
		t.Fatal("control-plane assertion exceeded the reverse-wait budget")
	}
}

func assertControlPlanePendingExpired(t *testing.T, pending []net.Conn) {
	t.Helper()
	var byteBuf [1]byte
	_ = pending[0].SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	var netErr net.Error
	if _, err := pending[0].Read(byteBuf[:]); !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("saturation expired before control-plane assertion: %v", err)
	}
}

func TestTenantSaturationPreservesControlPlane(t *testing.T) {
	ctx, client, base := bootSaturationRelay(t)
	leases := registerSaturationLeases(t, ctx, client, base)
	fillStarted := time.Now()
	pending := saturateTCPPorts(t, leases)
	assertAggregateOverflowRejected(t, leases)
	renewAndConnectUnderSaturation(t, ctx, client, base, leases, fillStarted)
	assertControlPlanePendingExpired(t, pending)
}
