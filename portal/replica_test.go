package portal

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"testing/synctest"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func registerHTTPReplica(t *testing.T, registry *leaseRegistry, identity types.Identity) (*leaseRecord, types.RegisterResponse) {
	t.Helper()
	record, response, err := registry.Register(types.RegisterChallengeRequest{Identity: identity, Replica: true}, netip.MustParseAddr("203.0.113.10"), "", types.RelayDescriptor{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return record, response
}

func TestReplicaLeaseLifecycleIsIndependent(t *testing.T) {
	registry := newTestRegistry(t, false, false)
	identity := newTestLeaseIdentity(t, "replicas")
	first, firstResponse := registerHTTPReplica(t, registry, identity)
	second, secondResponse := registerHTTPReplica(t, registry, identity)
	if first.id == second.id || firstResponse.CanonicalHostname != secondResponse.CanonicalHostname {
		t.Fatal("replicas must have independent leases at the same hostname")
	}
	for _, response := range []types.RegisterResponse{firstResponse, secondResponse} {
		record, err := registry.admitReverseCapability(response.ReverseEndpoint.Capability)
		if err != nil {
			t.Fatal(err)
		}
		leaseID, ok := registry.verifySigningAccessTokenLease(signLeaseRequest(t, response.AccessToken))
		if !ok || leaseID != record.id {
			t.Fatal("signing and reverse capabilities resolved to different leases")
		}
	}
	secondExpiry, secondSeen := second.ExpiresAt, second.LastSeenAt
	if _, _, err := registry.Renew(types.RenewRequest{AccessToken: firstResponse.AccessToken, TTL: 600}, netip.MustParseAddr("203.0.113.11"), nil); err != nil {
		t.Fatal(err)
	}
	registry.Touch(identity.ServiceKey(), first.id, netip.MustParseAddr("203.0.113.12"), time.Now())
	if !second.ExpiresAt.Equal(secondExpiry) || !second.LastSeenAt.Equal(secondSeen) || second.sourceAddr == first.sourceAddr {
		t.Fatal("renew or reverse activity changed another replica")
	}
	if _, err := registry.Unregister(types.UnregisterRequest{AccessToken: firstResponse.AccessToken}); err != nil {
		t.Fatal(err)
	}
	if _, ok := registry.verifySigningAccessTokenLease(signLeaseRequest(t, firstResponse.AccessToken)); ok {
		t.Fatal("removed replica retained signing authority")
	}
	if _, _, err := registry.Renew(types.RenewRequest{AccessToken: secondResponse.AccessToken}, netip.Addr{}, nil); err != nil {
		t.Fatalf("removing one replica invalidated the other: %v", err)
	}
}

func TestExclusiveRegistrationReplacesAllReplicas(t *testing.T) {
	registry := newTestRegistry(t, false, false)
	identity := newTestLeaseIdentity(t, "exclusive")
	_, first := registerHTTPReplica(t, registry, identity)
	_, second := registerHTTPReplica(t, registry, identity)
	_, exclusive, err := registry.Register(types.RegisterChallengeRequest{Identity: identity}, netip.Addr{}, "", types.RelayDescriptor{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, previous := range []types.RegisterResponse{first, second} {
		if _, _, err := registry.Renew(types.RenewRequest{AccessToken: previous.AccessToken}, netip.Addr{}, nil); !errors.Is(err, errUnauthorized) {
			t.Fatalf("replaced token remains valid: %v", err)
		}
	}
	if _, _, err := registry.Register(types.RegisterChallengeRequest{Identity: identity, Replica: true}, netip.Addr{}, "", types.RelayDescriptor{}, nil, nil); !errors.Is(err, errReplicaConflict) {
		t.Fatalf("replica joined exclusive lease: %v", err)
	}
	if _, _, err := registry.Renew(types.RenewRequest{AccessToken: exclusive.AccessToken}, netip.Addr{}, nil); err != nil {
		t.Fatalf("rejected replica changed exclusive lease: %v", err)
	}
}

func TestReplicaChurnPreservesSharedBandwidthCredit(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		registry := newTestRegistry(t, false, false)
		identity := newTestLeaseIdentity(t, "bandwidth")
		first, _ := registerHTTPReplica(t, registry, identity)
		key := identity.ServiceKey()
		registry.bps.SetServiceIdentityBPSLimits(map[types.ServiceIdentityKey]int64{key: 100})
		_, limiter := registry.bps.identityLimiter(key)
		if wait := limiter.reserve(10, 100); wait != 100*time.Millisecond {
			t.Fatalf("initial credit: %v", wait)
		}
		_, second := registerHTTPReplica(t, registry, identity)
		first.ExpiresAt = time.Now().Add(-time.Second)
		registry.cleanupExpired(time.Now())
		_, limiter = registry.bps.identityLimiter(key)
		if wait := limiter.reserve(10, 100); wait != 200*time.Millisecond {
			t.Fatalf("replica churn reset shared credit: %v", wait)
		}
		if _, err := registry.Unregister(types.UnregisterRequest{AccessToken: second.AccessToken}); err != nil {
			t.Fatal(err)
		}
		_, limiter = registry.bps.identityLimiter(key)
		if wait := limiter.reserve(10, 100); wait != 100*time.Millisecond {
			t.Fatalf("last replica did not release ephemeral credit: %v", wait)
		}
	})
}

func TestReplicaSelectionUsesReadyRoutableLeases(t *testing.T) {
	registry := newTestRegistry(t, false, false)
	identity := newTestLeaseIdentity(t, "selection")
	first, _ := registerHTTPReplica(t, registry, identity)
	second, _ := registerHTTPReplica(t, registry, identity)
	empty, _ := registerHTTPReplica(t, registry, identity)
	for _, record := range []*leaseRecord{first, second} {
		server, client := net.Pipe()
		t.Cleanup(func() { _ = client.Close() })
		if err := record.reverse.Offer(server); err != nil {
			t.Fatal(err)
		}
	}
	key := identity.ServiceKey()
	selected := registry.selectReplica(key, nil, true)
	if selected == nil || selected == empty {
		t.Fatal("selected a replica without a ready reverse stream")
	}
	stream, err := selected.reverse.TryAcquire(context.Background())
	if err != nil || stream == nil {
		t.Fatalf("claim ready stream: %v", err)
	}
	_ = stream.Close()
	stream, err = selected.reverse.TryAcquire(context.Background())
	if err != nil || stream != nil {
		t.Fatalf("empty pool must permit immediate failover: %v", err)
	}
	next := registry.selectReplica(key, map[string]bool{selected.id: true}, true)
	if next == nil || next == selected || next == empty {
		t.Fatal("did not select the other ready replica")
	}
	if waitOn := registry.selectReplica(key, map[string]bool{first.id: true, second.id: true}, false); waitOn != empty {
		t.Fatal("a burst with no ready replica must wait on a live replica")
	}
	if public := registry.PublicLeases(time.Now()); len(public) != 1 || public[0].Ready != 1 {
		t.Fatalf("directory must contain one service with aggregate readiness: %+v", public)
	}
	policyLeases := registry.PolicyLeases(time.Now())
	if len(policyLeases) != 3 || policyLeases[0].LeaseID == policyLeases[1].LeaseID {
		t.Fatal("admin listing lost independent lease identities")
	}
	registry.setIdentityAccess(key, types.LeaseDenied, 1)
	if registry.selectReplica(key, nil, false) != nil || len(registry.PublicLeases(time.Now())) != 0 {
		t.Fatal("identity denial did not cover all replicas")
	}
}

func TestReplicaRegistrationIsBoundedPerIdentity(t *testing.T) {
	registry := newTestRegistry(t, false, false)
	identity := newTestLeaseIdentity(t, "bounded")
	for range defaultReplicaLimit {
		record, _ := registerHTTPReplica(t, registry, identity)
		t.Cleanup(record.Close)
	}
	_, _, err := registry.Register(types.RegisterChallengeRequest{Identity: identity, Replica: true}, netip.MustParseAddr("203.0.113.10"), "", types.RelayDescriptor{}, nil, nil)
	if !errors.Is(err, errReplicaLimit) {
		t.Fatalf("replica beyond the per-identity limit: %v", err)
	}
}

func TestReplicaRegistrationRejectsUnsupportedTransports(t *testing.T) {
	registry := newTestRegistry(t, true, true)
	identity := newTestLeaseIdentity(t, "unsupported")
	for _, request := range []types.RegisterChallengeRequest{
		{Replica: true, UDPEnabled: true},
		{Replica: true, TCPEnabled: true},
		{Replica: true, Cache: true},
		{Replica: true, Overlay: true},
	} {
		request.Identity = identity
		if _, _, err := registry.Register(request, netip.Addr{}, "", types.RelayDescriptor{}, nil, nil); !errors.Is(err, errReplicaMode) {
			t.Fatalf("unsupported replica request accepted: %+v, %v", request, err)
		}
	}
}
