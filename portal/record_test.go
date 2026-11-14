package portal

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/transport"
	"github.com/gosuda/portal-tunnel/v2/types"
)

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
	if err := registry.activateBridge(record, bridge, reverse); err != nil {
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
	if err := registry.activateBridge(record, bridge, reverse); !errors.Is(err, net.ErrClosed) {
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
	legacy, replaced := register("")
	if replaced != replacement {
		t.Fatal("downgrade lost retired canonical DNS owner")
	}
	registry.mu.RLock()
	stale := server.isDNSHostnameOwnedLocked(replaced.CanonicalHostname, time.Now())
	retained = server.isDNSHostnameOwnedLocked(legacy.CanonicalHostname, time.Now())
	registry.mu.RUnlock()
	if stale || !retained {
		t.Fatal("downgrade did not isolate retired DNS from legacy live DNS")
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

func TestNamespaceDNSParentHasSiblingAndLegacyOwners(t *testing.T) {
	registry := newTestRegistry(t, false, false)
	owner := newTestLeaseIdentity(t, "blog")
	register := func(name, namespace string) *leaseRecord {
		t.Helper()
		owner.Name = name
		record, _, _, err := registry.Register(types.RegisterChallengeRequest{Identity: owner, Namespace: namespace}, netip.MustParseAddr("203.0.113.10"), "", types.RelayDescriptor{}, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		return record
	}
	named := register("blog", types.LocalTLSNamespaceV1)
	unnamed := register("", types.LocalTLSNamespaceV1)
	parent := named.dnsAddressParent()
	if parent == "" || parent != unnamed.LegacyCanonicalHostname {
		t.Fatalf("named and unnamed services do not share the legacy address: %q", parent)
	}
	server := &Server{registry: registry}
	owned := func(hostname string) bool {
		registry.mu.RLock()
		defer registry.mu.RUnlock()
		return server.isDNSHostnameOwnedLocked(hostname, time.Now())
	}
	register("", "")
	if owned(unnamed.CanonicalHostname) || !owned(parent) {
		t.Fatal("unnamed downgrade must withdraw its canonical child but preserve legacy address")
	}
	register("blog", "")
	if !owned(parent) {
		t.Fatal("last canonical child withdrawal must preserve the live legacy address")
	}
}
