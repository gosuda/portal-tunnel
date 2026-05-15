package portal

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/acme"
	"github.com/gosuda/portal-tunnel/v2/portal/auth"
	"github.com/gosuda/portal-tunnel/v2/portal/discovery"
	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/portal/overlay"
	"github.com/gosuda/portal-tunnel/v2/sdk"
	"github.com/gosuda/portal-tunnel/v2/types"
)

type localRelayCluster struct {
	relays []*localRelay
	byIP   map[string]*localRelay
}

type localRelaySpec struct {
	Name              string
	ServerMutator     func(*Server)
	DescriptorMutator func(*types.RelayDescriptor)
}

type localRelay struct {
	name              string
	server            *Server
	apiURL            string
	sniAddr           string
	overlayIP         string
	overlay           *fakeOverlay
	descriptorMutator func(*types.RelayDescriptor)
}

type fakeOverlay struct {
	cfg       overlay.Config
	mu        sync.RWMutex
	syncedIPs map[string]struct{}
}

func (o *fakeOverlay) Config() overlay.Config {
	return o.cfg.Copy()
}

func (o *fakeOverlay) Sync(descriptors []types.RelayDescriptor) error {
	synced := make(map[string]struct{}, len(descriptors))
	for _, desc := range descriptors {
		overlayIP, err := identity.DeriveWireGuardOverlayIPv4(desc.WireGuardPublicKey)
		if err != nil {
			return err
		}
		synced[overlayIP] = struct{}{}
	}
	o.mu.Lock()
	o.syncedIPs = synced
	o.mu.Unlock()
	return nil
}

func (o *fakeOverlay) hasSyncedPeer(overlayIPv4 string) bool {
	o.mu.RLock()
	defer o.mu.RUnlock()
	_, ok := o.syncedIPs[overlayIPv4]
	return ok
}

type fakeHopMux struct {
	cluster *localRelayCluster
	overlay *fakeOverlay
}

func (m *fakeHopMux) OpenStream(ctx context.Context, overlayIPv4, token string) (net.Conn, error) {
	if m == nil || m.cluster == nil {
		return nil, errors.New("fake hop mux is not connected to a cluster")
	}
	if m.overlay == nil || !m.overlay.hasSyncedPeer(overlayIPv4) {
		return nil, fmt.Errorf("fake hop target %q was not synced to overlay", overlayIPv4)
	}
	target := m.cluster.byIP[overlayIPv4]
	if target == nil {
		return nil, fmt.Errorf("fake hop target %q not found", overlayIPv4)
	}
	left, right := net.Pipe()
	go target.bridgeFakeHop(ctx, right, token)
	return left, nil
}

func (r *localRelay) bridgeFakeHop(ctx context.Context, conn net.Conn, token string) {
	r.server.registry.mu.RLock()
	record := r.server.registry.recordByHopToken(token, time.Now())
	r.server.registry.mu.RUnlock()
	if record == nil {
		_ = conn.Close()
		return
	}
	if err := r.server.bridgeLeaseConn(ctx, conn, record); err != nil {
		_ = conn.Close()
	}
}

func newLocalRelayCluster(t *testing.T, names ...string) *localRelayCluster {
	t.Helper()
	specs := make([]localRelaySpec, 0, len(names))
	for _, name := range names {
		specs = append(specs, localRelaySpec{Name: name})
	}
	return newLocalRelayClusterFromSpecs(t, specs...)
}

func newLocalRelayClusterFromSpecs(t *testing.T, specs ...localRelaySpec) *localRelayCluster {
	t.Helper()
	if len(specs) == 0 {
		t.Fatal("local relay cluster requires at least one relay")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cluster := &localRelayCluster{
		relays: make([]*localRelay, 0, len(specs)),
		byIP:   make(map[string]*localRelay, len(specs)),
	}
	t.Cleanup(func() {
		cancel()
		for _, relay := range cluster.relays {
			_ = relay.server.Shutdown(context.Background())
			if err := relay.server.Wait(); err != nil {
				t.Fatalf("relay %s Wait() error = %v", relay.name, err)
			}
		}
	})

	for _, spec := range specs {
		relay := startLocalRelay(t, ctx, spec)
		cluster.relays = append(cluster.relays, relay)
	}
	cluster.seedDiscovery(t)
	return cluster
}

func startLocalRelay(t *testing.T, ctx context.Context, spec localRelaySpec) *localRelay {
	t.Helper()
	name := spec.Name
	if name == "" {
		t.Fatal("local relay spec name is required")
	}
	server, err := NewServer(ServerConfig{
		PortalURL:     "https://localhost:4017",
		IdentityPath:  tempIdentityPath(t),
		ACME:          acme.Config{KeyDir: t.TempDir()},
		APIListenAddr: "127.0.0.1:0",
		SNIListenAddr: "127.0.0.1:0",
	})
	if err != nil {
		t.Fatalf("NewServer(%s) error = %v", name, err)
	}
	if err := server.Start(ctx, nil); err != nil {
		t.Fatalf("Start(%s) error = %v", name, err)
	}

	apiPort := mustPort(t, server.apiListener.Addr().String())
	sniPort := mustPort(t, server.sniListener.Addr().String())
	apiURL := "https://localhost:" + apiPort
	server.cfg.PortalURL = apiURL
	server.cfg.SNIPort = mustAtoi(t, sniPort)
	server.registry.sniPort = server.cfg.SNIPort
	if spec.ServerMutator != nil {
		spec.ServerMutator(server)
	}

	wgPrivate, err := identity.GenerateWireGuardPrivateKey()
	if err != nil {
		t.Fatalf("identity.GenerateWireGuardPrivateKey(%s) error = %v", name, err)
	}
	wgPublic, err := identity.WireGuardPublicKeyFromPrivate(wgPrivate)
	if err != nil {
		t.Fatalf("identity.WireGuardPublicKeyFromPrivate(%s) error = %v", name, err)
	}
	fakeOverlay := &fakeOverlay{cfg: overlay.Config{
		PublicKey:  wgPublic,
		ListenPort: overlay.DefaultListenPort,
	}}
	fakeHopMux := &fakeHopMux{overlay: fakeOverlay}
	server.testHooks = &serverTestHooks{
		overlayConfig:    fakeOverlay.Config,
		syncOverlayPeers: fakeOverlay.Sync,
		openHopStream:    fakeHopMux.OpenStream,
	}
	server.cfg.DiscoveryEnabled = true

	overlayIP, err := identity.DeriveWireGuardOverlayIPv4(wgPublic)
	if err != nil {
		t.Fatalf("identity.DeriveWireGuardOverlayIPv4(%s) error = %v", name, err)
	}
	return &localRelay{
		name:              name,
		server:            server,
		apiURL:            apiURL,
		sniAddr:           net.JoinHostPort("127.0.0.1", sniPort),
		overlayIP:         overlayIP,
		overlay:           fakeOverlay,
		descriptorMutator: spec.DescriptorMutator,
	}
}

func (c *localRelayCluster) seedDiscovery(t *testing.T) {
	t.Helper()
	urls := make([]string, 0, len(c.relays))
	descriptors := make([]types.RelayDescriptor, 0, len(c.relays))
	for _, relay := range c.relays {
		urls = append(urls, relay.apiURL)
		desc, err := relay.server.newSelfDescriptor(time.Now())
		if err != nil {
			t.Fatalf("newSelfDescriptor(%s) error = %v", relay.name, err)
		}
		if relay.descriptorMutator != nil {
			relay.descriptorMutator(&desc)
			desc, err = auth.SignRelayDescriptor(desc, relay.server.authority)
			if err != nil {
				t.Fatalf("SignRelayDescriptor(%s) error = %v", relay.name, err)
			}
		}
		descriptors = append(descriptors, desc)
		c.byIP[relay.overlayIP] = relay
	}
	for _, relay := range c.relays {
		relay.server.relaySet = discovery.NewRelaySet(urls)
		fakeHopMux := &fakeHopMux{cluster: c, overlay: relay.overlay}
		relay.server.testHooks.openHopStream = fakeHopMux.OpenStream
		changed, err := relay.server.relaySet.ApplyRelayDiscoveryResponse(relay.apiURL, types.DiscoveryResponse{
			ProtocolVersion: types.DiscoveryVersion,
			GeneratedAt:     time.Now().UTC(),
			Relays:          descriptors,
		}, time.Now())
		if err != nil {
			t.Fatalf("ApplyRelayDiscoveryResponse(%s) error = %v", relay.name, err)
		}
		if !changed {
			t.Fatalf("ApplyRelayDiscoveryResponse(%s) changed = false, want true", relay.name)
		}
	}
}

func (c *localRelayCluster) relay(index int) *localRelay {
	return c.relays[index]
}

func (c *localRelayCluster) relayURLs() []string {
	out := make([]string, 0, len(c.relays))
	for _, relay := range c.relays {
		out = append(out, relay.apiURL)
	}
	return out
}

func (c *localRelayCluster) exposeMultiHop(t *testing.T, ctx context.Context, name string) *sdk.Exposure {
	t.Helper()
	exposure, err := sdk.Expose(ctx, sdk.ExposeConfig{
		Identity:   types.Identity{Name: name},
		TargetAddr: "127.0.0.1:1",
		MultiHop:   c.relayURLs(),
		BanMITM:    false,
	})
	if err != nil {
		t.Fatalf("sdk.Expose() error = %v", err)
	}
	t.Cleanup(func() {
		_ = exposure.Close()
	})
	return exposure
}

func TestLocalClusterExplicitMultiHopRegistersRoutes(t *testing.T) {
	cluster := newLocalRelayCluster(t, "entry", "middle", "exit")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	exposure := cluster.exposeMultiHop(t, ctx, "local-hop")
	waitForLocalHopRoutes(t, cluster, "local-hop.localhost")

	if got := exposure.ActiveRelayURLs(); len(got) != 1 || got[0] != cluster.relay(2).apiURL {
		t.Fatalf("ActiveRelayURLs() = %v, want exit relay %q", got, cluster.relay(2).apiURL)
	}
	entryRecord, ok := cluster.relay(0).server.registry.Lookup("local-hop.localhost")
	if !ok {
		t.Fatal("entry relay public hostname lookup failed")
	}
	if _, _, hasNext := entryRecord.nextHop(); !hasNext {
		t.Fatal("entry relay route has no next hop")
	}
	if middle := firstRecord(cluster.relay(1).server, func(record *leaseRecord) bool {
		return record.isHopMiddle()
	}); middle == nil {
		t.Fatal("middle relay hop route missing")
	}
	if exit := firstRecord(cluster.relay(2).server, func(record *leaseRecord) bool {
		return record.isHopExit() && record.stream != nil
	}); exit == nil {
		t.Fatal("exit relay stream lease missing")
	}
}

func TestLocalClusterPublicIngressTraversesFakeHopChain(t *testing.T) {
	cluster := newLocalRelayCluster(t, "entry", "middle", "exit")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	exposure := cluster.exposeMultiHop(t, ctx, "local-http")
	handlerReady := make(chan error, 1)
	go func() {
		handlerReady <- exposure.RunHTTP(ctx, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, "local multi-hop ok")
		}), "")
	}()
	waitForLocalHopRoutes(t, cluster, "local-http.localhost")

	body := requestThroughEntry(t, cluster.relay(0), "local-http.localhost")
	if body != "local multi-hop ok" {
		t.Fatalf("public ingress body = %q, want %q", body, "local multi-hop ok")
	}

	cancel()
	if err := <-handlerReady; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("RunHTTP() error = %v", err)
	}
}

func TestLocalClusterDiscoveryStaysLocal(t *testing.T) {
	cluster := newLocalRelayCluster(t, "entry", "middle", "exit")
	want := cluster.relayURLs()
	slices.Sort(want)

	for _, relay := range cluster.relays {
		self, err := relay.server.newSelfDescriptor(time.Now())
		if err != nil {
			t.Fatalf("newSelfDescriptor(%s) error = %v", relay.name, err)
		}
		descriptors := relay.server.relaySet.Descriptors(self)
		got := make([]string, 0, len(descriptors))
		for _, desc := range descriptors {
			got = append(got, desc.APIHTTPSAddr)
		}
		slices.Sort(got)
		if !slices.Equal(got, want) {
			t.Fatalf("discovery relays for %s = %v, want local relays %v", relay.name, got, want)
		}
	}
}

func waitForLocalHopRoutes(t *testing.T, cluster *localRelayCluster, publicHostname string) {
	t.Helper()
	eventually(t, 10*time.Second, func() (bool, string) {
		if _, ok := cluster.relay(0).server.registry.Lookup(publicHostname); !ok {
			return false, "entry public route missing"
		}
		if firstRecord(cluster.relay(1).server, func(record *leaseRecord) bool { return record.isHopMiddle() }) == nil {
			return false, "middle hop route missing"
		}
		if firstRecord(cluster.relay(2).server, func(record *leaseRecord) bool {
			return record.isHopExit() && record.stream != nil && record.stream.ReadyCount() > 0
		}) == nil {
			return false, "exit stream lease not ready"
		}
		return true, ""
	})
}

func firstRecord(server *Server, match func(*leaseRecord) bool) *leaseRecord {
	server.registry.mu.RLock()
	defer server.registry.mu.RUnlock()
	for _, record := range server.registry.records {
		if record != nil && match(record) {
			return record
		}
	}
	return nil
}

func requestThroughEntry(t *testing.T, entry *localRelay, serverName string) string {
	t.Helper()
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", entry.sniAddr, &tls.Config{
		MinVersion:         tls.VersionTLS12,
		ServerName:         serverName,
		InsecureSkipVerify: true,
		NextProtos:         []string{"http/1.1"},
	})
	if err != nil {
		t.Fatalf("dial entry SNI listener: %v", err)
	}
	defer conn.Close()

	req, err := http.NewRequest(http.MethodGet, "https://"+serverName+"/", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	if err := req.Write(conn); err != nil {
		t.Fatalf("write HTTP request: %v", err)
	}
	resp, err := http.ReadResponse(bufioNewReader(conn), req)
	if err != nil {
		t.Fatalf("read HTTP response: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read HTTP response body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET through entry status = %d body=%q, want 200", resp.StatusCode, string(body))
	}
	return string(body)
}

func eventually(t *testing.T, timeout time.Duration, check func() (bool, string)) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last string
	for time.Now().Before(deadline) {
		ok, reason := check()
		if ok {
			return
		}
		last = reason
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("condition not met within %s: %s", timeout, last)
}

func mustPort(t *testing.T, addr string) string {
	t.Helper()
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("SplitHostPort(%q) error = %v", addr, err)
	}
	return port
}

func mustAtoi(t *testing.T, raw string) int {
	t.Helper()
	var out int
	if _, err := fmt.Sscanf(raw, "%d", &out); err != nil {
		t.Fatalf("parse int %q: %v", raw, err)
	}
	return out
}

func bufioNewReader(conn net.Conn) *bufio.Reader {
	return bufio.NewReader(conn)
}
