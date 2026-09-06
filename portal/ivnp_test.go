package portal

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"gosuda.org/ivnp"
	"gosuda.org/ivnp/dataplane"
	"gosuda.org/ivnp/foundation"

	"github.com/gosuda/portal-tunnel/v2/portal/auth"
	"github.com/gosuda/portal-tunnel/v2/portal/discovery"
	"github.com/gosuda/portal-tunnel/v2/types"
)

// Only tunnel delivery is in memory. Both endpoints execute IVNP's real
// Streaming signatures, handshake, sequence handling, and peer metadata.
type ivnpTestFabric map[foundation.Hash]*dataplane.StreamingTunnelTunnelNetwork

func (f ivnpTestFabric) SendTunnel(ctx context.Context, d dataplane.StreamingTunnelDelivery) error {
	peer := f[d.To]
	if peer == nil {
		return errors.New("unknown test destination")
	}
	return peer.HandleDelivery(ctx, d)
}

type ivnpTestEndpoint struct {
	ivnp.DestinationEndpoint
	network *dataplane.StreamingTunnelTunnelNetwork
}

func (e *ivnpTestEndpoint) B32() string { return e.network.B32() }
func (e *ivnpTestEndpoint) DialI2P(ctx context.Context, addr string) (net.Conn, error) {
	return e.network.DialI2P(ctx, addr)
}
func (e *ivnpTestEndpoint) ListenI2P(ctx context.Context, addr string) (net.Listener, error) {
	return e.network.ListenI2P(ctx, addr)
}

func TestIVNPReverseBackhaul(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	fabric := make(ivnpTestFabric)
	servers := make([]*Server, 2)
	descriptors := make([]types.RelayDescriptor, 2)
	for i := range servers {
		local, err := foundation.GenerateLegacyLocalDestination()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(local.ReleaseSensitive)
		network, err := dataplane.StreamingTunnelNewTunnelNetwork(dataplane.StreamingTunnelTunnelNetworkConfig{Destination: local, Sender: fabric})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = network.Close() })
		fabric[local.Hash()] = network
		registry := newTestRegistry(t)
		t.Cleanup(func() {
			for _, record := range registry.CloseAll() {
				record.Close()
			}
		})
		servers[i] = &Server{registry: registry, relaySet: discovery.NewRelaySet(nil), ivnpEndpoint: &ivnpTestEndpoint{network: network}, ivnpSlots: make(chan struct{}, 4)}
		servers[i].ivnpReady.Store(true)
		servers[i].ivnpContext = ctx
		now := time.Now().UTC()
		descriptors[i], err = auth.SignRelayDescriptor(types.RelayDescriptor{
			Address:         registry.tokenAuthority.Identity().Address,
			Version:         types.DiscoveryVersion,
			APIHTTPSAddr:    "https://" + string(rune('a'+i)) + ".example",
			IVNPDestination: local.B32(), IssuedAt: now, ExpiresAt: now.Add(time.Minute),
		}, registry.tokenAuthority)
		if err != nil {
			t.Fatal(err)
		}
	}
	for i, server := range servers {
		peer := descriptors[1-i]
		if _, err := server.relaySet.ApplyRelayDiscoveryResponse(peer.APIHTTPSAddr, types.DiscoveryResponse{ProtocolVersion: types.DiscoveryVersion, Relays: []types.RelayDescriptor{peer}}, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	ingress, gateway := servers[0], servers[1]
	listener, err := ingress.relaySet.ListenIVNP(ctx, ingress.ivnpEndpoint, ":"+types.IVNPStreamPort)
	if err != nil {
		t.Fatal(err)
	}
	ingress.ivnpListener = listener
	defer listener.Close()
	go func() { _ = ingress.runIVNP(ctx) }()
	gatewayHTTP := httptest.NewServer(http.HandlerFunc(gateway.handleConnect))
	defer gatewayHTTP.Close()
	record, registered, err := ingress.registry.Register(types.RegisterChallengeRequest{Identity: newTestLeaseIdentity(t, "ivnp")}, "127.0.0.1", "")
	if err != nil {
		t.Fatal(err)
	}

	for _, invalidToken := range []string{"", "invalid"} {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, gatewayHTTP.URL+types.PathSDKConnect, nil)
		req.Header.Set(types.HeaderIVNPDestination, descriptors[0].IVNPDestination)
		req.Header.Set(types.HeaderAccessToken, invalidToken)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("invalid token status = %d", resp.StatusCode)
		}
	}
	address, _ := url.Parse(gatewayHTTP.URL)
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", address.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	req, _ := http.NewRequest(http.MethodGet, gatewayHTTP.URL+types.PathSDKConnect, nil)
	req.Header.Set(types.HeaderIVNPDestination, descriptors[0].IVNPDestination)
	req.Header.Set(types.HeaderAccessToken, registered.AccessToken)
	if err := req.Write(conn); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("connect status = %d", resp.StatusCode)
	}
	session, err := record.stream.Claim(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = session.SetDeadline(time.Now()); _ = session.Close() }()
	marker, err := reader.ReadByte()
	if err != nil || marker != types.MarkerTLSStart {
		t.Fatalf("claim marker = %d: %v", marker, err)
	}
	if _, err := session.Write([]byte("browser")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 7)
	if _, err := io.ReadFull(reader, got); err != nil || string(got) != "browser" {
		t.Fatalf("ingress to sdk = %q: %v", got, err)
	}
	if _, err := conn.Write([]byte("service")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(session, got); err != nil || string(got) != "service" {
		t.Fatalf("sdk to ingress = %q: %v", got, err)
	}
	if len(gateway.registry.records) != 0 {
		t.Fatal("gateway acquired lease state")
	}
}
