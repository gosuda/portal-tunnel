package overlay

import (
	"context"
	"encoding/base32"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/auth"
	"github.com/gosuda/portal-tunnel/v2/portal/discovery"
	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

// The fake transport supplies I2P endpoint identities over local TCP. These
// tests exercise Portal's protocol, not I2P routing or NAT traversal.
type endpointAddr string

func (a endpointAddr) Network() string { return "i2p" }
func (a endpointAddr) String() string  { return string(a) }

type endpointConn struct {
	*net.TCPConn
	remote string
}

func (c *endpointConn) RemoteAddr() net.Addr {
	return endpointAddr(net.JoinHostPort(c.remote, types.RelayOverlayPort))
}

type endpointListener struct {
	net.Listener
	remote string
}

func (l endpointListener) Accept() (net.Conn, error) {
	c, e := l.Listener.Accept()
	if e != nil {
		return nil, e
	}
	return &endpointConn{TCPConn: c.(*net.TCPConn), remote: l.remote}, nil
}

type testNetwork struct{ address, remote string }

func (n testNetwork) DialI2P(ctx context.Context, _ string) (net.Conn, error) {
	c, e := (&net.Dialer{}).DialContext(ctx, "tcp", n.address)
	if e != nil {
		return nil, e
	}
	return &endpointConn{TCPConn: c.(*net.TCPConn), remote: n.remote}, nil
}

func testDestination(value byte) string {
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(strings.Repeat(string([]byte{value}), 32)))) + ".b32.i2p"
}

func testRuntime(t *testing.T, name, local, remote string, handler http.HandlerFunc) (*Runtime, types.RelayDescriptor) {
	t.Helper()
	signer, err := identity.ResolveSecp256k1Identity("")
	if err != nil {
		t.Fatal(err)
	}
	authority, err := identity.NewLocalAuthority(signer)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	desc, err := auth.SignRelayDescriptor(types.RelayDescriptor{Address: signer.Address, APIHTTPSAddr: "https://" + name + ".example", IVNPDestination: local, IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute)}, authority)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	catalog := discovery.NewRelaySet(nil)
	o := &Runtime{ctx: context.Background(), listener: endpointListener{Listener: listener, remote: remote}, destination: local, release: func() error { return nil }, self: func() (types.RelayDescriptor, error) { return desc, nil }, admit: catalog.AdmitOverlayPeer, handler: handler, conns: make(map[*trackedConn]struct{})}
	done := make(chan error, 1)
	go func() { done <- o.Serve() }()
	t.Cleanup(func() {
		_ = o.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(time.Second):
			t.Error("overlay server did not stop")
		}
	})
	return o, desc
}

func TestAuthenticatedExchangeRetainsNetworkAndBufferedStream(t *testing.T) {
	aHost, bHost := testDestination(1), testDestination(2)
	var bDesc types.RelayDescriptor
	b, bDescriptor := testRuntime(t, "b", bHost, aHost, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case types.PathDiscovery:
			utils.WriteAPIData(w, http.StatusOK, types.DiscoveryResponse{ProtocolVersion: types.DiscoveryVersion, Relays: []types.RelayDescriptor{bDesc}})
		case types.PathRelayConnect:
			if r.Header.Get(types.HeaderAccessToken) != "lease-token" {
				http.Error(w, "unauthorized", http.StatusForbidden)
				return
			}
			c, rw, err := w.(http.Hijacker).Hijack()
			if err != nil {
				return
			}
			defer c.Close()
			_, _ = fmt.Fprintf(rw, "HTTP/1.1 200 OK\r\n%s: %s\r\n\r\nready", types.HeaderRelayDescriptor, w.Header().Get(types.HeaderRelayDescriptor))
			_ = rw.Flush()
			_, _ = io.Copy(c, c)
		}
	})
	bDesc = bDescriptor
	a, _ := testRuntime(t, "a", aHost, bHost, http.NotFound)
	a.network = testNetwork{address: b.listener.Addr().String(), remote: bHost}
	for range 2 {
		resp, err := a.DiscoverRelay(context.Background(), bDesc)
		if err != nil || len(resp.Relays) != 1 {
			t.Fatalf("discovery: %v %v", resp, err)
		}
	}
	if c, err := a.OpenStream(context.Background(), bDesc, "wrong"); err == nil {
		_ = c.Close()
		t.Fatal("invalid lease token accepted")
	}
	stream, err := a.OpenStream(context.Background(), bDesc, "lease-token")
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(2 * time.Second))
	ready := make([]byte, 5)
	if _, err := io.ReadFull(stream, ready); err != nil || string(ready) != "ready" {
		t.Fatalf("buffered response lost: %q %v", ready, err)
	}
	if _, err := stream.Write([]byte("ciphertext")); err != nil {
		t.Fatal(err)
	}
	echoed := make([]byte, 10)
	if _, err := io.ReadFull(stream, echoed); err != nil || string(echoed) != "ciphertext" {
		t.Fatalf("stream: %q %v", echoed, err)
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Read(make([]byte, 1)); err == nil {
		t.Fatal("hijacked stream survived shutdown")
	}
}

func TestOverlayRejectsWrongDestinationAndHonorsCancellation(t *testing.T) {
	aHost, bHost := testDestination(3), testDestination(4)
	entered := make(chan struct{}, 1)
	b, bDesc := testRuntime(t, "b", bHost, aHost, func(w http.ResponseWriter, r *http.Request) { entered <- struct{}{}; <-r.Context().Done() })
	a, _ := testRuntime(t, "a", aHost, bHost, http.NotFound)
	a.network = testNetwork{address: b.listener.Addr().String(), remote: aHost}
	if c, err := a.OpenStream(context.Background(), bDesc, "token"); err == nil {
		_ = c.Close()
		t.Fatal("wrong I2P destination accepted")
	}
	a.network = testNetwork{address: b.listener.Addr().String(), remote: bHost}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := a.OpenStream(ctx, bDesc, "token"); done <- err }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("request did not arrive")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled request succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not close stream")
	}
}
