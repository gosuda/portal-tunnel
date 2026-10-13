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

func TestSNIPendingAdmissionAndShutdown(t *testing.T) {
	port := harnessPort(t, "127.0.0.1")
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	relay, err := portal.NewServer(portal.ServerConfig{PortalURL: "https://" + addr, StateDir: t.TempDir(), SNIListenAddr: addr, SNIPort: port})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
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
	var peers []net.Conn
	for range 129 {
		peer, err := net.DialTimeout("tcp", addr, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = peer.Close() })
		peers = append(peers, peer)
	}
	var buf [1]byte
	_ = peers[128].SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	_, err = peers[128].Read(buf[:])
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
	// A completed ClientHello must transfer to the root HTTP server and release
	// the inspection slot, so stalled-peer pressure cannot exhaust future work.
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
	pending, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer pending.Close()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer shutdownCancel()
	if err := relay.Shutdown(shutdownCtx); err != nil {
		t.Fatal(err)
	}
	if err := relay.Wait(); err != nil {
		t.Fatal(err)
	}
	_ = pending.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := pending.Read(buf[:]); err == nil || (errors.As(err, &netErr) && netErr.Timeout()) {
		t.Fatalf("shutdown left SNI socket open: %v", err)
	}
}

func TestTenantSaturationPreservesControlPlane(t *testing.T) {
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
	defer cancel()
	if err := server.Start(ctx, relayHandler(server, nil)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); _ = server.Shutdown(context.Background()); _ = server.Wait() })
	// Every API request establishes fresh root TLS, so an existing keepalive
	// cannot hide lockout at the shared public listener.
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, DisableKeepAlives: true}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 3 * time.Second}
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
	var pending []net.Conn
	var byteBuf [1]byte
	fillStarted := time.Now()
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
		// The 129th close is also an accept-loop barrier: all 128 earlier sockets
		// reached this lease's admission boundary before the next lease is filled.
		extra, err := net.DialTimeout("tcp", addr, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		_ = extra.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		_, err = extra.Read(byteBuf[:])
		_ = extra.Close()
		var netErr net.Error
		if err == nil || (errors.As(err, &netErr) && netErr.Timeout()) {
			t.Fatalf("lease overflow not rejected: %v", err)
		}
	}
	// An otherwise empty ninth lease rules out merely hitting per-lease caps.
	_, ninthPort, err := net.SplitHostPort(leases[8].TCPAddr)
	if err != nil {
		t.Fatal(err)
	}
	overflow, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", ninthPort), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = overflow.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	_, err = overflow.Read(byteBuf[:])
	_ = overflow.Close()
	var netErr net.Error
	if err == nil || (errors.As(err, &netErr) && netErr.Timeout()) {
		t.Fatalf("aggregate overflow not rejected: %v", err)
	}
	var renewal types.RenewResponse
	if err := utils.HTTPDoAPIPath(ctx, client, base, http.MethodPost, types.PathSDKRenew, types.RenewRequest{AccessToken: leases[0].AccessToken, TTL: 60}, nil, &renewal); err != nil {
		t.Fatalf("tenant saturation blocked fresh root TLS/renew: %v", err)
	}
	h := &tcpLeaseHarness{t: t, server: server, client: client, base: base, lease: leases[8], carrier: "native"}
	reverse := h.openReverse()
	defer reverse.Close()
	if time.Since(fillStarted) >= 10*time.Second {
		t.Fatal("control-plane assertion exceeded the reverse-wait budget")
	}
	// The oldest waiter is still live: success did not rely on ten-second
	// claim expiry reclaiming the tenant budget during the control requests.
	_ = pending[0].SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if _, err := pending[0].Read(byteBuf[:]); !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("saturation expired before control-plane assertion: %v", err)
	}
}
