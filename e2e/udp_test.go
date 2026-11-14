package e2e_test

import (
	"bytes"
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/tunnel"
	"github.com/gosuda/portal-tunnel/v2/portal"
	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestUDPPortRelay(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1"} {
		t.Run(host, func(t *testing.T) {
			testUDPPortRelay(t, host, host, host)
		})
	}
}

func runUDPEchoServer(origin *net.UDPConn, originDone chan struct{}) {
	defer close(originDone)
	var payload [2048]byte
	for {
		n, peer, err := origin.ReadFromUDP(payload[:])
		if err != nil {
			return
		}
		if _, err := origin.WriteToUDP(payload[:n], peer); err != nil {
			return
		}
	}
}

func assertUDPClientEcho(t *testing.T, conn *net.UDPConn, client int) {
	t.Helper()
	for message := range 3 {
		payload := []byte("udp-" + strconv.Itoa(client) + "-" + strconv.Itoa(message))
		if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Write(payload); err != nil {
			t.Fatalf("send UDP payload: %v", err)
		}
		var reply [2048]byte
		n, err := conn.Read(reply[:])
		if err != nil {
			t.Fatalf("read UDP reply: %v", err)
		}
		if string(reply[:n]) != string(payload) {
			t.Fatalf("UDP reply = %q, want %q", reply[:n], payload)
		}
	}
}

func assertUDPEchoRoundTrip(t *testing.T, relayHost string, publicPort int) {
	t.Helper()
	for client := range 2 {
		conn, err := net.DialUDP("udp", &net.UDPAddr{IP: net.ParseIP(relayHost)}, &net.UDPAddr{IP: net.ParseIP(relayHost), Port: publicPort})
		if err != nil {
			t.Fatalf("dial UDP ingress: %v", err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		assertUDPClientEcho(t, conn, client)
	}
}

func testUDPPortRelay(t *testing.T, relayHost, relayName, originHost string) {
	t.Helper()
	origin, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(originHost)})
	if err != nil {
		if originHost == "::1" {
			t.Skipf("IPv6 loopback is unavailable: %v", err)
		}
		t.Fatalf("listen UDP origin: %v", err)
	}
	originDone := make(chan struct{})
	go runUDPEchoServer(origin, originDone)
	t.Cleanup(func() {
		_ = origin.Close()
		<-originDone
	})

	publicPort, _, _ := startUDPTestTunnel(t, relayHost, relayName, origin.LocalAddr().String())
	assertUDPEchoRoundTrip(t, relayHost, publicPort)
}

func startUDPServer(t *testing.T, ctx context.Context, config portal.ServerConfig) *portal.Server {
	t.Helper()
	relay, err := portal.NewServer(config)
	if err != nil {
		t.Fatalf("create UDP relay: %v", err)
	}
	if err := relay.SetTransportPolicy(true, 0, false, 0); err != nil {
		t.Fatalf("enable UDP transport: %v", err)
	}
	if err := relay.Start(ctx, relayHandler(relay, nil)); err != nil {
		t.Fatalf("start UDP relay: %v", err)
	}
	return relay
}

func proxyUDPTunnel(t *testing.T, ctx context.Context, runtime *tunnel.Runtime) func() {
	t.Helper()
	proxyCtx, proxyCancel := context.WithCancel(ctx)
	proxyDone := make(chan error, 1)
	go func() { proxyDone <- runtime.Run(proxyCtx) }()
	var stopOnce sync.Once
	stop := func() {
		stopOnce.Do(func() {
			proxyCancel()
			_ = runtime.Close()
			select {
			case err := <-proxyDone:
				if err != nil && !errors.Is(err, context.Canceled) {
					t.Errorf("proxy UDP: %v", err)
				}
			case <-time.After(10 * time.Second):
				t.Error("UDP proxy did not stop")
			}
		})
	}
	t.Cleanup(stop)
	return stop
}

func awaitUDPListenerRelease(t *testing.T, relayHost string, port int) {
	t.Helper()
	drainDeadline := time.Now().Add(10 * time.Second)
	drainPoll := time.NewTicker(20 * time.Millisecond)
	defer drainPoll.Stop()
	for {
		probe, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(relayHost), Port: port})
		if err == nil {
			_ = probe.Close()
			break
		}
		if time.Now().After(drainDeadline) {
			t.Fatalf("QUIC listener did not release restart port: %v", err)
		}
		<-drainPoll.C
	}
}

func awaitDatagramPublicPort(ctx context.Context, t *testing.T, runtime *tunnel.Runtime) int {
	t.Helper()
	ready, err := runtime.Exposure.WaitDatagramReady(ctx)
	if err != nil || len(ready) == 0 {
		t.Fatalf("wait for UDP backhaul: %v; relay statuses: %+v", err, runtime.Exposure.Relays())
	}
	_, portText, err := net.SplitHostPort(ready[0].UDPAddr)
	if err != nil {
		t.Fatalf("split public UDP address %q: %v", ready[0].UDPAddr, err)
	}
	publicPort, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("parse public UDP port %q: %v", portText, err)
	}
	return publicPort
}

func shutdownUDPServerForRestart(t *testing.T, ctx context.Context, relay *portal.Server) {
	t.Helper()
	shutdownCtx, shutdownCancel := context.WithTimeout(ctx, 5*time.Second)
	defer shutdownCancel()
	if err := relay.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("stop relay for restart: %v", err)
	}
	if err := relay.Wait(); err != nil {
		t.Fatalf("wait for stopped relay: %v", err)
	}
}

func ownUDPServerRestart(t *testing.T, ctx context.Context, config portal.ServerConfig, relayHost string, port int) func() {
	t.Helper()
	relay := startUDPServer(t, ctx, config)
	t.Cleanup(func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		if err := relay.Shutdown(shutdownCtx); err != nil {
			t.Errorf("shutdown UDP relay: %v", err)
		}
		if err := relay.Wait(); err != nil {
			t.Errorf("wait for UDP relay: %v", err)
		}
	})
	return func() {
		shutdownUDPServerForRestart(t, ctx, relay)
		awaitUDPListenerRelease(t, relayHost, port)
		relay = startUDPServer(t, ctx, config)
	}
}

func startUDPTestTunnel(t *testing.T, relayHost, relayName, originAddress string) (int, func(), func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	udpPort := harnessPort(t, relayHost)
	port := harnessPort(t, relayHost)
	relayURL := "https://" + net.JoinHostPort(relayName, strconv.Itoa(port))
	config := portal.ServerConfig{
		PortalURL:     relayURL,
		StateDir:      t.TempDir(),
		SNIListenAddr: net.JoinHostPort(relayHost, strconv.Itoa(port)),
		SNIPort:       port,
		MinPort:       udpPort,
		MaxPort:       udpPort,
	}
	restart := ownUDPServerRestart(t, ctx, config, relayHost, port)

	runtime, err := tunnel.Start(ctx, tunnel.Spec{
		Identity: tunnel.IdentitySpec{Name: "udp"},
		Relays:   tunnel.RelaySpec{URLs: []string{relayURL}},
		Transport: tunnel.TransportSpec{
			Target: originAddress,
			UDP:    &tunnel.UDPConfig{},
		},
	})
	if err != nil {
		t.Fatalf("start UDP tunnel: %v", err)
	}
	stop := proxyUDPTunnel(t, ctx, runtime)

	readyCtx, readyCancel := context.WithTimeout(ctx, 30*time.Second)
	defer readyCancel()
	publicPort := awaitDatagramPublicPort(readyCtx, t, runtime)
	return publicPort, restart, stop
}

func answerFallbackDNS(hostname string) dns.Handler {
	return dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(request)
		response.Authoritative = true
		for _, question := range request.Question {
			if !strings.EqualFold(question.Name, dns.Fqdn(hostname)) {
				response.Rcode = dns.RcodeNameError
				continue
			}
			header := dns.RR_Header{Name: question.Name, Rrtype: question.Qtype, Class: dns.ClassINET, Ttl: 1}
			switch question.Qtype {
			case dns.TypeA:
				response.Answer = append(response.Answer, &dns.A{Hdr: header, A: net.IPv4(127, 0, 0, 1)})
			case dns.TypeAAAA:
				response.Answer = append(response.Answer, &dns.AAAA{Hdr: header, AAAA: net.IPv6loopback})
			}
		}
		_ = w.WriteMsg(response)
	})
}

func driveLocalDNSService(t *testing.T, packet net.PacketConn, hostname string) {
	t.Helper()
	started := make(chan struct{})
	server := &dns.Server{
		PacketConn:        packet,
		NotifyStartedFunc: func() { close(started) },
		Handler:           answerFallbackDNS(hostname),
	}
	stopped := make(chan struct{})
	var serveErr error
	go func() {
		serveErr = server.ActivateAndServe()
		close(stopped)
	}()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.ShutdownContext(ctx)
		_ = packet.Close()
		select {
		case <-stopped:
			if serveErr != nil {
				t.Errorf("serve local DNS: %v", serveErr)
			}
		case <-ctx.Done():
			t.Error("local DNS server did not stop")
		}
	})
	select {
	case <-started:
	case <-stopped:
		t.Fatalf("start local DNS: %v", serveErr)
	}
}

func serveLocalDNSStub(t *testing.T, hostname string) net.PacketConn {
	t.Helper()
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for local DNS: %v", err)
	}
	driveLocalDNSService(t, packet, hostname)
	return packet
}

func overrideLocalDNSResolver(t *testing.T, packet net.PacketConn) {
	t.Helper()
	originalResolver := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "udp", packet.LocalAddr().String())
		},
	}
	t.Cleanup(func() { net.DefaultResolver = originalResolver })
}

func TestUDPRelayAddressFallback(t *testing.T) {
	const hostname = "fallback.localhost"
	packet := serveLocalDNSStub(t, hostname)
	overrideLocalDNSResolver(t, packet)

	for _, tc := range []struct {
		name string
		host string
	}{
		{name: "IPv4 relay", host: "127.0.0.1"},
		{name: "IPv6 relay", host: "::1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			testUDPPortRelay(t, tc.host, hostname, tc.host)
		})
	}
}

func dialRestartSender(t *testing.T, port int) *net.UDPConn {
	t.Helper()
	client, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func receiveOldSenderPacket(t *testing.T, origin *net.UDPConn) *net.UDPAddr {
	t.Helper()
	var buf [2048]byte
	_ = origin.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, peer, err := origin.ReadFromUDP(buf[:])
	if err != nil || string(buf[:n]) != "old sender" {
		t.Fatalf("old sender did not reach origin: %q, %v", buf[:n], err)
	}
	return peer
}

func assertRestartNewSenderServed(t *testing.T, newSender *net.UDPConn, buf []byte) {
	t.Helper()
	_ = newSender.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, err := newSender.Read(buf)
	if err != nil || string(buf[:n]) != "new reply" {
		t.Fatalf("new sender received stale reply or no reply: %q, %v", buf[:n], err)
	}
}

func assertNoStaleReplyCrossesRestart(t *testing.T, newSender *net.UDPConn, buf []byte) {
	t.Helper()
	_ = newSender.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if n, err := newSender.Read(buf); err == nil {
		t.Fatalf("unexpected delayed reply crossed lease boundary: %q", buf[:n])
	} else {
		var netErr net.Error
		if !errors.As(err, &netErr) || !netErr.Timeout() {
			t.Fatal(err)
		}
	}
}

func awaitNewSenderPacket(t *testing.T, origin *net.UDPConn, newSender *net.UDPConn, buf []byte) *net.UDPAddr {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	var newPeer *net.UDPAddr
	var n int
	var err error
	for time.Now().Before(deadline) {
		if _, err := newSender.Write([]byte("new sender")); err != nil && !errors.Is(err, syscall.ECONNREFUSED) {
			t.Fatal(err)
		}
		_ = origin.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, newPeer, err = origin.ReadFromUDP(buf)
		if err == nil {
			break
		}
		var netErr net.Error
		if !errors.As(err, &netErr) || !netErr.Timeout() {
			t.Fatal(err)
		}
	}
	if err != nil || string(buf[:n]) != "new sender" {
		t.Fatalf("new sender did not reach origin after restart: %q, %v", buf[:n], err)
	}
	return newPeer
}

func assertRestartIsolatesSenders(t *testing.T, origin *net.UDPConn, newSender *net.UDPConn, oldPeer *net.UDPAddr) {
	t.Helper()
	var buf [2048]byte
	newPeer := awaitNewSenderPacket(t, origin, newSender, buf[:])
	if _, err := origin.WriteToUDP([]byte("delayed old reply"), oldPeer); err != nil {
		t.Fatal(err)
	}
	if _, err := origin.WriteToUDP([]byte("new reply"), newPeer); err != nil {
		t.Fatal(err)
	}
	assertRestartNewSenderServed(t, newSender, buf[:])
	assertNoStaleReplyCrossesRestart(t, newSender, buf[:])
}

func TestUDPRelayRestartIsolatesSenderSockets(t *testing.T) {
	origin, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = origin.Close() })
	port, restart, _ := startUDPTestTunnel(t, "127.0.0.1", "127.0.0.1", origin.LocalAddr().String())
	oldSender := dialRestartSender(t, port)
	if _, err := oldSender.Write([]byte("old sender")); err != nil {
		t.Fatal(err)
	}
	oldPeer := receiveOldSenderPacket(t, origin)
	restart()
	newSender := dialRestartSender(t, port)
	assertRestartIsolatesSenders(t, origin, newSender, oldPeer)
}

func reclaimProxySocket(t *testing.T, peer *net.UDPAddr, stop func()) {
	t.Helper()
	stop()
	rebound, err := net.ListenUDP("udp4", peer)
	if err != nil {
		t.Fatalf("proxy close retained origin socket %s: %v", peer, err)
	}
	_ = rebound.Close()
}

func checkProxyCloseReleasesSocket(t *testing.T) {
	t.Helper()
	origin, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = origin.Close() })
	port, _, stop := startUDPTestTunnel(t, "127.0.0.1", "127.0.0.1", origin.LocalAddr().String())
	client, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if _, err := client.Write([]byte("live socket")); err != nil {
		t.Fatal(err)
	}
	_ = origin.SetReadDeadline(time.Now().Add(10 * time.Second))
	var payload [64]byte
	n, peer, err := origin.ReadFromUDP(payload[:])
	if err != nil || string(payload[:n]) != "live socket" {
		t.Fatalf("origin did not observe live proxy socket: %q, %v", payload[:n], err)
	}
	reclaimProxySocket(t, peer, stop)
}

func TestUDPProxyCloseReleasesOriginSocket(t *testing.T) {
	for attempt := range 3 {
		t.Run(strconv.Itoa(attempt), func(t *testing.T) {
			checkProxyCloseReleasesSocket(t)
		})
	}
}

func sendOversizedBurst(t *testing.T, client *net.UDPConn) {
	t.Helper()
	for _, size := range []int{types.MaxUDPPayloadSize + 1, 4096} {
		if _, err := client.Write(bytes.Repeat([]byte("x"), size)); err != nil {
			t.Fatalf("send oversized packet (%d): %v", size, err)
		}
	}
}

func assertValidPacketSurvives(t *testing.T, origin, client *net.UDPConn, valid []byte) {
	t.Helper()
	if _, err := client.Write(valid); err != nil {
		t.Fatal(err)
	}
	_ = origin.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 65535)
	n, peer, err := origin.ReadFromUDP(buf)
	if err != nil || !bytes.Equal(buf[:n], valid) {
		t.Fatalf("origin received oversized prefix or lost valid packet: size=%d err=%v", n, err)
	}
	if _, err := origin.WriteToUDP(bytes.Repeat([]byte("x"), 4096), peer); err != nil {
		t.Fatal(err)
	}
	if _, err := origin.WriteToUDP(valid, peer); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, err = client.Read(buf)
	if err != nil || !bytes.Equal(buf[:n], valid) {
		t.Fatalf("client received oversized prefix or lost valid reply: size=%d err=%v", n, err)
	}
}

func TestUDPOversizedPacketsDropWhole(t *testing.T) {
	origin, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = origin.Close() })
	port, _, _ := startUDPTestTunnel(t, "127.0.0.1", "127.0.0.1", origin.LocalAddr().String())
	client, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	valid := bytes.Repeat([]byte("v"), types.MaxUDPPayloadSize)
	sendOversizedBurst(t, client)
	assertValidPacketSurvives(t, origin, client, valid)
}
