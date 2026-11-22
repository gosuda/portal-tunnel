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

func bootInspectionRelay(t *testing.T, perSource int) string {
	t.Helper()
	port := harnessPort(t, "127.0.0.1")
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	relay, err := portal.NewServer(portal.ServerConfig{PortalURL: "https://" + addr, StateDir: t.TempDir(), SNIListenAddr: addr, SNIPort: port, InspectionsPerSource: perSource})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	if err := relay.Start(ctx, relayHandler(relay, nil)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); _ = relay.Shutdown(context.Background()); _ = relay.Wait() })
	return addr
}

// holdInspections opens sockets that never send a ClientHello, so each holds
// an inspection slot until the relay's ClientHello deadline.
func holdInspections(t *testing.T, addr string, n int) []net.Conn {
	t.Helper()
	conns := make([]net.Conn, 0, n)
	for range n {
		conn, err := net.DialTimeout("tcp", addr, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		conns = append(conns, conn)
	}
	return conns
}

// rootHandshakes completes n simultaneous TLS handshakes with the relay API
// and reports how many succeeded.
func rootHandshakes(addr string, local net.Addr, n int) int {
	results := make(chan bool, n)
	for range n {
		go func() {
			dialer := tls.Dialer{NetDialer: &net.Dialer{Timeout: time.Second, LocalAddr: local}, Config: &tls.Config{InsecureSkipVerify: true}}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			conn, err := dialer.DialContext(ctx, "tcp", addr)
			if err == nil {
				_ = conn.Close()
			}
			results <- err == nil
		}()
	}
	succeeded := 0
	for range n {
		if <-results {
			succeeded++
		}
	}
	return succeeded
}

// One source may hold up to INSPECTIONS_PER_SOURCE sockets in ClientHello
// inspection. Concurrent handshakes below the budget all complete, the budget
// rejects only the overflow, and other sources keep their own budget.
func TestSNIInspectionPerSourceBudget(t *testing.T) {
	const perSource = 16
	addr := bootInspectionRelay(t, perSource)

	held := holdInspections(t, addr, perSource-4)
	if got := rootHandshakes(addr, nil, 4); got != 4 {
		t.Fatalf("%d of 4 concurrent handshakes below the per-source budget completed", got)
	}

	held = append(held, holdInspections(t, addr, 4)...)
	if got := rootHandshakes(addr, nil, 4); got != 0 {
		t.Fatalf("%d handshakes passed a saturated per-source budget", got)
	}
	other := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 2)}
	if probe, err := net.ListenTCP("tcp", other); err != nil {
		t.Logf("skip second source: %v", err)
	} else {
		_ = probe.Close()
		if got := rootHandshakes(addr, other, 4); got != 4 {
			t.Fatalf("saturated source blocked %d of 4 handshakes from another source", 4-got)
		}
	}

	for _, conn := range held {
		_ = conn.Close()
	}
	awaitSNIAdmissionRecovery(t, t.Context(), addr)
}

// Behind a TCP proxy every visitor shares one address. With the per-source
// budget disabled, that address keeps the whole server-wide budget.
func TestSNIInspectionSharedProxySource(t *testing.T) {
	addr := bootInspectionRelay(t, 0)
	holdInspections(t, addr, 32)
	if got := rootHandshakes(addr, nil, 8); got != 8 {
		t.Fatalf("%d of 8 handshakes from a shared proxy address completed", got)
	}
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
