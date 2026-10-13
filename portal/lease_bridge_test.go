package portal

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/transport"
	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestLeaseBridgeCapacityAndRevocation(t *testing.T) {
	record := &leaseRecord{Identity: types.Identity{Name: "lease", Address: "0x1"}, ExpiresAt: time.Now().Add(time.Hour), reverse: transport.NewReversePool(time.Minute, 1)}
	defer record.Close()
	registry := &leaseRegistry{records: []*leaseRecord{record}, blocked: make(map[types.ServiceIdentityKey]time.Time)}
	var bridges []*leaseBridge
	for index := range defaultLeaseBridgeLimit {
		inbound, peer := net.Pipe()
		t.Cleanup(func() { _ = peer.Close() })
		bridge, err := registry.admitBridge(t.Context(), record, inbound)
		if err != nil {
			t.Fatal(err)
		}
		if index < 16 {
			reverse, other := net.Pipe()
			t.Cleanup(func() { _ = other.Close() })
			if err := registry.activateBridge(record, bridge, reverse); err != nil {
				t.Fatal(err)
			}
		}
		bridges = append(bridges, bridge)
		defer record.releaseBridge(bridge)
	}
	excess, peer := net.Pipe()
	defer excess.Close()
	defer peer.Close()
	if _, err := registry.admitBridge(t.Context(), record, excess); !errors.Is(err, errLeaseRejected) {
		t.Fatalf("capacity admission = %v", err)
	}
	registry.setIdentityRoutable(record.ServiceKey(), false, 1)
	registry.setIdentityRoutable(record.ServiceKey(), true, 2)
	for _, bridge := range bridges {
		if !errors.Is(bridge.ctx.Err(), context.Canceled) {
			t.Fatal("deny did not cancel bridge")
		}
		reverse, peer := net.Pipe()
		err := registry.activateBridge(record, bridge, reverse)
		_ = reverse.Close()
		_ = peer.Close()
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("allow revived old reservation: %v", err)
		}
	}
	if _, err := registry.admitBridge(t.Context(), record, excess); !errors.Is(err, errLeaseRejected) {
		t.Fatalf("revoked workers prematurely released capacity: %v", err)
	}
	record.releaseBridge(bridges[0])
	fresh, err := registry.admitBridge(t.Context(), record, excess)
	if err != nil {
		t.Fatalf("capacity not recovered: %v", err)
	}
	record.releaseBridge(fresh)
}

func TestLeaseBridgeRejectsExpiredAdmissionAfterWait(t *testing.T) {
	record := &leaseRecord{ExpiresAt: time.Now().Add(time.Hour), reverse: transport.NewReversePool(time.Minute, 1)}
	defer record.Close()
	registry := &leaseRegistry{records: []*leaseRecord{record}}
	inbound, peer := net.Pipe()
	defer peer.Close()
	bridge, err := registry.admitBridge(t.Context(), record, inbound)
	if err != nil {
		t.Fatal(err)
	}
	defer record.releaseBridge(bridge)
	registry.mu.Lock()
	record.ExpiresAt = time.Now().Add(-time.Second)
	registry.mu.Unlock()
	reverse, other := net.Pipe()
	defer reverse.Close()
	defer other.Close()
	if err := registry.activateBridge(record, bridge, reverse); !errors.Is(err, errLeaseNotFound) {
		t.Fatalf("expired activation=%v", err)
	}
}

func TestLeaseConcurrentRenewAndBridgeAdmission(t *testing.T) {
	registry := newTestRegistry(t, false, false)
	record, registered, err := registry.Register(types.RegisterChallengeRequest{Identity: newTestLeaseIdentity(t, "renew-bridge")}, netip.MustParseAddr("127.0.0.1"), "", types.RelayDescriptor{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	workers.Go(func() {
		for range 100 {
			if _, _, err := registry.Renew(types.RenewRequest{AccessToken: registered.AccessToken, TTL: 120}, netip.Addr{}); err != nil {
				t.Error(err)
				return
			}
		}
	})
	workers.Go(func() {
		for range 100 {
			inbound, peer := net.Pipe()
			bridge, err := registry.admitBridge(t.Context(), record, inbound)
			if err != nil {
				_ = inbound.Close()
				_ = peer.Close()
				t.Error(err)
				return
			}
			reverse, other := net.Pipe()
			if err := registry.activateBridge(record, bridge, reverse); err != nil {
				t.Error(err)
			}
			record.releaseBridge(bridge)
			_ = peer.Close()
			_ = other.Close()
		}
	})
	workers.Wait()
}
