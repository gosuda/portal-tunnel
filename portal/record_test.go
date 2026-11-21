package portal

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/acme"
	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/portal/transport"
	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestPolicyRevocationDoesNotWaitForDNSCapacity(t *testing.T) {
	authority := identity.NewLocalAuthority(newTestLeaseIdentity(t, "relay"))
	registry, err := newLeaseRegistry(0, 0, "example.com", authority, "https://example.com", 0)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := acme.NewManager(acme.Config{
		BaseDomain: "example.com", KeyDir: t.TempDir(), DNSProvider: acme.TypeCloudflare,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Leave the real DNS worker stopped and fill its queue through its public
	// API. Revocation must remain available regardless of DNS progress.
	server := &Server{registry: registry, acmeManager: manager}
	var records []*leaseRecord
	for _, name := range []string{"first", "second"} {
		owner := newTestLeaseIdentity(t, name)
		record, _, _, err := registry.Register(types.RegisterChallengeRequest{Identity: owner, Namespace: types.LocalTLSNamespaceV1}, netip.Addr{}, "", types.RelayDescriptor{}, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		records = append(records, record)
	}
	fillCtx, cancel := context.WithTimeout(t.Context(), time.Second)
	for {
		err = manager.SyncLeaseHostname(fillCtx, records[0].CanonicalHostname, records[0].Address)
		if err != nil {
			break
		}
	}
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("DNS backpressure: %v", err)
	}
	done := make(chan struct{})
	go func() {
		for _, record := range records {
			server.ApplyServicePolicy(record.ServiceKey(), types.LeaseDenied, 1)
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("policy revocation waited for DNS capacity")
	}
	t.Cleanup(func() { registry.CloseAll() })
	if leases := registry.PolicyLeases(time.Now()); len(leases) != 0 {
		t.Fatalf("DNS backpressure retained revoked leases: %+v", leases)
	}
	// Failed enqueue attempts must retain cleanup for a later janitor pass.
	cleanupCtx, cancel := context.WithCancel(t.Context())
	cancel()
	server.flushLeaseDNSDeletes(cleanupCtx)
	for _, record := range records {
		if _, pending := registry.pendingDNSDeletes[record.CanonicalHostname]; !pending {
			t.Fatal("failed DNS enqueue lost cleanup intent")
		}
	}
	// Reclaim the same canonical hosts before the retry. Even with a full DNS
	// queue, cleanup must discard old withdrawals without touching new owners.
	for _, record := range records {
		server.ApplyServicePolicy(record.ServiceKey(), types.LeaseRoutable, 2)
		if _, _, _, err := registry.Register(types.RegisterChallengeRequest{Identity: record.Identity, Namespace: types.LocalTLSNamespaceV1}, netip.Addr{}, "", types.RelayDescriptor{}, nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	server.flushLeaseDNSDeletes(cleanupCtx)
	if len(registry.pendingDNSDeletes) != 0 {
		t.Fatal("cleanup retained withdrawals for reclaimed DNS hosts")
	}
	if err := manager.Stop(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestRawTCPRejectsConnectionWhileNotRoutable(t *testing.T) {
	record := &leaseRecord{Identity: types.Identity{Name: "demo", Address: "0x1"}, ExpiresAt: time.Now().Add(time.Hour), reverse: transport.NewReversePool(time.Minute, 1)}
	defer record.Close()
	registry := &leaseRegistry{records: []*leaseRecord{record}, blocked: map[types.ServiceIdentityKey]blockedIdentity{record.ServiceKey(): {pushedAt: time.Now(), refusal: errLeaseRejected}}}
	client, inbound := net.Pipe()
	defer client.Close()
	defer inbound.Close()
	if _, err := registry.admitBridge(t.Context(), record, inbound); !errors.Is(err, errLeaseRejected) {
		t.Fatalf("blocked TCP admission = %v", err)
	}
}

func TestLeaseCloseRejectsRawTCPStillStarting(t *testing.T) {
	record := &leaseRecord{ExpiresAt: time.Now().Add(time.Hour), reverse: transport.NewReversePool(time.Minute, 1)}
	defer record.Close()
	registry := &leaseRegistry{records: []*leaseRecord{record}}
	inbound, client := net.Pipe()
	defer client.Close()
	bridge := admitClosingLeaseBridge(t, registry, record, inbound)
	defer record.releaseBridge(bridge)
	reverse, peer := net.Pipe()
	defer peer.Close()
	defer reverse.Close()
	if err := registry.activateBridge(record, bridge, reverse, nil); err != nil {
		t.Fatal(err)
	}
	record.Close()
	checkClosedLeaseDropsEndpoints(t, client, peer)
	checkClosedLeaseBlocksReactivate(t, registry, record, bridge, reverse)
}

func admitClosingLeaseBridge(t *testing.T, registry *leaseRegistry, record *leaseRecord, inbound net.Conn) *leaseBridge {
	t.Helper()
	bridge, err := registry.admitBridge(t.Context(), record, inbound)
	if err != nil {
		t.Fatal(err)
	}
	return bridge
}

func checkClosedLeaseDropsEndpoints(t *testing.T, client, peer net.Conn) {
	t.Helper()
	for _, conn := range []net.Conn{client, peer} {
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
			t.Fatalf("closed lease retained endpoint: %v", err)
		}
	}
}

func checkClosedLeaseBlocksReactivate(t *testing.T, registry *leaseRegistry, record *leaseRecord, bridge *leaseBridge, reverse net.Conn) {
	t.Helper()
	if err := registry.activateBridge(record, bridge, reverse, nil); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed lease activated bridge: %v", err)
	}
}

func TestNamespaceReplacementDNSOwnership(t *testing.T) {
	registry := newTestRegistry(t, false, false)
	owner := newTestLeaseIdentity(t, "blog")
	register := func(namespace string) (*leaseRecord, *leaseRecord) {
		t.Helper()
		record, replaced, _, err := registry.Register(types.RegisterChallengeRequest{Identity: owner, Namespace: namespace}, netip.MustParseAddr("203.0.113.10"), "", types.RelayDescriptor{}, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		return record, replaced
	}
	original, _ := register(types.LocalTLSNamespaceV1)
	replacement, replaced := register(types.LocalTLSNamespaceV1)
	if replaced != original {
		t.Fatal("registration lost replaced DNS owner")
	}
	server := &Server{registry: registry}
	registry.mu.RLock()
	retained := server.isDNSHostnameOwnedLocked(original.CanonicalHostname, time.Now())
	registry.mu.RUnlock()
	if !retained {
		t.Fatal("same-namespace replacement would delete live DNS")
	}
	aliasOnly, replaced := register("")
	if replaced != replacement {
		t.Fatal("downgrade lost retired canonical DNS owner")
	}
	registry.mu.RLock()
	stale := server.isDNSHostnameOwnedLocked(replaced.CanonicalHostname, time.Now())
	retained = server.isDNSHostnameOwnedLocked(aliasOnly.Hostname, time.Now())
	registry.mu.RUnlock()
	if stale || !retained || aliasOnly.CanonicalHostname != "" {
		t.Fatal("alias-only replacement did not isolate retired canonical DNS from the live alias")
	}
	// A newer concurrent registration reclaims the hostname before cleanup.
	newest, _ := register(types.LocalTLSNamespaceV1)
	registry.mu.RLock()
	retained = server.isDNSHostnameOwnedLocked(replaced.CanonicalHostname, time.Now())
	registry.mu.RUnlock()
	if !retained || newest.CanonicalHostname != replaced.CanonicalHostname {
		t.Fatal("late cleanup could delete a reclaimed canonical hostname")
	}
}
