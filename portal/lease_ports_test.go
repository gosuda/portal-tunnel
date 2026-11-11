package portal

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestPortPoolRollbackReturnsPortWithoutReservation(t *testing.T) {
	first := &leaseRecord{Identity: types.Identity{Name: "first", Address: "0x1"}}
	other := &leaseRecord{Identity: types.Identity{Name: "other", Address: "0x2"}}
	pool := newPortPool(10000, 10000, time.Minute)
	port, err := pool.allocate(first)
	if err != nil {
		t.Fatal(err)
	}
	pool.rollback(port, first)
	if len(pool.reserved) != 0 {
		t.Fatalf("rollback created %d sticky reservations", len(pool.reserved))
	}
	reused, err := pool.allocate(other)
	if err != nil || reused != port {
		t.Fatalf("different owner did not immediately reuse rolled-back port: %d, %v", reused, err)
	}
	pool.rollback(port, first)
	if pool.inUse[port].record != other {
		t.Fatal("stale rollback released another owner's port")
	}
}

func TestLeaseHostnameConflictRollsBackRawPorts(t *testing.T) {
	registry := newTestRegistry(t, true, true)
	request := types.RegisterChallengeRequest{
		Identity:   newTestLeaseIdentity(t, "conflict"),
		UDPEnabled: true,
		TCPEnabled: true,
	}
	if _, _, err := registry.Register(request, netip.Addr{}, "", types.RelayDescriptor{}, nil, nil); err != nil {
		t.Fatal(err)
	}
	checkHostnameConflictFreesPorts(t, registry, request)
	request.Identity = newTestLeaseIdentity(t, "accepted")
	if _, _, err := registry.Register(request, netip.Addr{}, "", types.RelayDescriptor{}, nil, nil); err != nil {
		t.Fatalf("rejected identities exhausted raw ports: %v", err)
	}
}

func checkHostnameConflictFreesPorts(t *testing.T, registry *leaseRegistry, request types.RegisterChallengeRequest) {
	t.Helper()
	for i := range 3 {
		request.Identity = newTestLeaseIdentity(t, "conflict")
		if _, _, err := registry.Register(request, netip.Addr{}, "", types.RelayDescriptor{}, nil, nil); !errors.Is(err, errHostnameConflict) {
			t.Fatalf("rejected registration %d error = %v, want hostname conflict", i, err)
		}
		if len(registry.udpPorts.available) != 1 || len(registry.tcpPorts.available) != 1 ||
			len(registry.udpPorts.reserved) != 0 || len(registry.tcpPorts.reserved) != 0 {
			t.Fatalf("rejected registration %d retained ports: UDP=%+v TCP=%+v", i, registry.udpPorts, registry.tcpPorts)
		}
	}
}

func TestPortPoolRollbackPreservesReconnectReservation(t *testing.T) {
	first := &leaseRecord{Identity: types.Identity{Name: "first", Address: "0x1"}}
	other := &leaseRecord{Identity: types.Identity{Name: "other", Address: "0x2"}}
	pool := newPortPool(10000, 10000, time.Minute)
	port, err := pool.allocate(first)
	if err != nil {
		t.Fatal(err)
	}
	pool.release(port, first)
	original := pool.reserved[first.ServiceKey()]
	if reclaimed, err := pool.allocate(first); err != nil || reclaimed != port {
		t.Fatalf("reclaim = %d, %v", reclaimed, err)
	}
	pool.rollback(port, first)
	if restored := pool.reserved[first.ServiceKey()]; restored != original {
		t.Fatalf("reservation changed after rejected reconnect: got %+v, want %+v", restored, original)
	}
	if _, err := pool.allocate(other); !errors.Is(err, errPortExhausted) {
		t.Fatalf("another identity consumed the reconnect reservation: %v", err)
	}
	pool.cleanupExpired(original.expiresAt.Add(time.Nanosecond))
	if reused, err := pool.allocate(other); err != nil || reused != port {
		t.Fatalf("expired reservation was not returned: %d, %v", reused, err)
	}
}

func TestLeaseCapacityRejectionRollsBackRawPorts(t *testing.T) {
	for _, tc := range []struct {
		name      string
		limitUDP  bool
		wantError error
	}{
		{name: "UDP", limitUDP: true, wantError: errUDPCapacityExceeded},
		{name: "TCP", wantError: errTCPPortCapacityExceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			registry := newTestRegistry(t, true, true)
			request := types.RegisterChallengeRequest{
				Identity:   newTestLeaseIdentity(t, "owner"),
				UDPEnabled: true,
				TCPEnabled: true,
			}
			if _, _, err := registry.Register(request, netip.Addr{}, "", types.RelayDescriptor{}, nil, nil); err != nil {
				t.Fatal(err)
			}
			if tc.limitUDP {
				registry.setTransportPolicy(true, 1, true, 0)
			} else {
				registry.setTransportPolicy(true, 0, true, 1)
			}
			checkCapacityRejectionFreesPorts(t, registry, request, tc.wantError)
			registry.setTransportPolicy(true, 2, true, 2)
			request.Identity = newTestLeaseIdentity(t, "accepted")
			if _, _, err := registry.Register(request, netip.Addr{}, "", types.RelayDescriptor{}, nil, nil); err != nil {
				t.Fatalf("capacity rejection exhausted raw ports: %v", err)
			}
		})
	}
}

func checkCapacityRejectionFreesPorts(t *testing.T, registry *leaseRegistry, request types.RegisterChallengeRequest, wantError error) {
	t.Helper()
	for i := range 3 {
		request.Identity = newTestLeaseIdentity(t, fmt.Sprintf("rejected-%d", i))
		if _, _, err := registry.Register(request, netip.Addr{}, "", types.RelayDescriptor{}, nil, nil); !errors.Is(err, wantError) {
			t.Fatalf("rejected registration %d error = %v, want %v", i, err, wantError)
		}
		if len(registry.udpPorts.available) != 1 || len(registry.tcpPorts.available) != 1 ||
			len(registry.udpPorts.reserved) != 0 || len(registry.tcpPorts.reserved) != 0 {
			t.Fatalf("rejected registration %d retained ports: UDP=%+v TCP=%+v", i, registry.udpPorts, registry.tcpPorts)
		}
	}
}

func TestLeaseTCPPortExhaustionRollsBackAllocatedUDPPort(t *testing.T) {
	registry := newTestRegistry(t, true, true)
	seedLeaseTCPPortsExhaustionPair(t, registry)
	both := types.RegisterChallengeRequest{
		Identity:   newTestLeaseIdentity(t, "both"),
		UDPEnabled: true,
		TCPEnabled: true,
	}
	rejectExhaustedTCPFreesUDP(t, registry, both)
	acceptUDPOnlyAfterExhaustion(t, registry, both)
}

func seedLeaseTCPPortsExhaustionPair(t *testing.T, registry *leaseRegistry) {
	t.Helper()
	for i := range 2 {
		request := types.RegisterChallengeRequest{
			Identity:   newTestLeaseIdentity(t, fmt.Sprintf("tcp-%d", i)),
			TCPEnabled: true,
		}
		if _, _, err := registry.Register(request, netip.Addr{}, "", types.RelayDescriptor{}, nil, nil); err != nil {
			t.Fatal(err)
		}
	}
}

func rejectExhaustedTCPFreesUDP(t *testing.T, registry *leaseRegistry, both types.RegisterChallengeRequest) {
	t.Helper()
	if _, _, err := registry.Register(both, netip.Addr{}, "", types.RelayDescriptor{}, nil, nil); !errors.Is(err, errTCPPortExhausted) {
		t.Fatalf("Register() error = %v, want TCP port exhaustion", err)
	}
	if len(registry.udpPorts.available) != 2 || len(registry.udpPorts.reserved) != 0 {
		t.Fatalf("failed TCP allocation retained a UDP port: %+v", registry.udpPorts)
	}
}

func acceptUDPOnlyAfterExhaustion(t *testing.T, registry *leaseRegistry, both types.RegisterChallengeRequest) {
	t.Helper()
	both.TCPEnabled = false
	both.Identity = newTestLeaseIdentity(t, "udp")
	if _, _, err := registry.Register(both, netip.Addr{}, "", types.RelayDescriptor{}, nil, nil); err != nil {
		t.Fatalf("failed TCP allocation exhausted UDP ports: %v", err)
	}
}

func TestPortPoolReservesReleasedPortForOwner(t *testing.T) {
	first := &leaseRecord{Identity: types.Identity{Name: "demo", Address: "0x1"}}
	other := &leaseRecord{Identity: types.Identity{Name: "demo", Address: "0x2"}}
	pool := newPortPool(10000, 10000, time.Minute)
	port, err := pool.allocate(first)
	if err != nil {
		t.Fatal(err)
	}
	pool.release(port, first)
	if _, err := pool.allocate(other); !errors.Is(err, errPortExhausted) {
		t.Fatalf("another owner consumed reserved port: %v", err)
	}
	if reclaimed, err := pool.allocate(first); err != nil || reclaimed != port {
		t.Fatalf("owner reclaim = %d, %v", reclaimed, err)
	}
}

func TestPortPoolReusesPortAfterReservationExpires(t *testing.T) {
	first := &leaseRecord{Identity: types.Identity{Name: "demo", Address: "0x1"}}
	other := &leaseRecord{Identity: types.Identity{Name: "demo", Address: "0x2"}}
	pool := newPortPool(10000, 10000, -time.Second)
	port, err := pool.allocate(first)
	if err != nil {
		t.Fatal(err)
	}
	pool.release(port, first)
	if reused, err := pool.allocate(other); err != nil || reused != port {
		t.Fatalf("expired reservation = %d, %v", reused, err)
	}
}

func TestLeasePortsStayWithServiceIdentityAcrossReconnect(t *testing.T) {
	registry := newTestRegistry(t, true, true)
	firstIdentity := newTestLeaseIdentity(t, "shared")
	request := types.RegisterChallengeRequest{AllowCanonicalFallback: true, Identity: firstIdentity, UDPEnabled: true, TCPEnabled: true}
	firstRecord, first := registerFirstStickyLease(t, registry, request)
	rejectStickyPortsOtherOwner(t, registry, request, first)
	reconnectStickyLeaseKeepsPorts(t, registry, request, first)
	verifyStaleCleanupKeepsPorts(t, registry, firstRecord, request)
}

func registerFirstStickyLease(t *testing.T, registry *leaseRegistry, request types.RegisterChallengeRequest) (*leaseRecord, types.RegisterResponse) {
	t.Helper()
	firstRecord, first, err := registry.Register(request, netip.Addr{}, "", types.RelayDescriptor{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Unregister(types.UnregisterRequest{AccessToken: first.AccessToken}); err != nil {
		t.Fatal(err)
	}
	return firstRecord, first
}

func rejectStickyPortsOtherOwner(t *testing.T, registry *leaseRegistry, request types.RegisterChallengeRequest, first types.RegisterResponse) {
	t.Helper()
	request.Identity = newTestLeaseIdentity(t, "shared")
	_, other, err := registry.Register(request, netip.Addr{}, "", types.RelayDescriptor{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, firstUDP, _ := net.SplitHostPort(first.UDPAddr)
	_, firstTCP, _ := net.SplitHostPort(first.TCPAddr)
	_, otherUDP, _ := net.SplitHostPort(other.UDPAddr)
	_, otherTCP, _ := net.SplitHostPort(other.TCPAddr)
	if firstUDP == otherUDP || firstTCP == otherTCP {
		t.Fatalf("same-name identity inherited a sticky port: first=%s/%s, other=%s/%s", firstUDP, firstTCP, otherUDP, otherTCP)
	}
}

func reconnectStickyLeaseKeepsPorts(t *testing.T, registry *leaseRegistry, request types.RegisterChallengeRequest, first types.RegisterResponse) {
	t.Helper()
	_, reconnected, err := registry.Register(request, netip.Addr{}, "", types.RelayDescriptor{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if reconnected.UDPAddr != first.UDPAddr || reconnected.TCPAddr != first.TCPAddr {
		t.Fatalf("reconnect lost reserved addresses: got %s/%s, want %s/%s", reconnected.UDPAddr, reconnected.TCPAddr, first.UDPAddr, first.TCPAddr)
	}
}

func verifyStaleCleanupKeepsPorts(t *testing.T, registry *leaseRegistry, firstRecord *leaseRecord, request types.RegisterChallengeRequest) {
	t.Helper()
	registry.closeRecord(firstRecord)
	request.Identity = newTestLeaseIdentity(t, "third")
	if _, _, err := registry.Register(request, netip.Addr{}, "", types.RelayDescriptor{}, nil, nil); !errors.Is(err, errUDPPortExhausted) {
		t.Fatalf("stale cleanup released a live UDP port: %v", err)
	}
	request.UDPEnabled = false
	if _, _, err := registry.Register(request, netip.Addr{}, "", types.RelayDescriptor{}, nil, nil); !errors.Is(err, errTCPPortExhausted) {
		t.Fatalf("stale cleanup released a live TCP port: %v", err)
	}
}

func TestLeaseRegistrationFailureReleasesPorts(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			registry := newTestRegistry(t, true, true)
			request := types.RegisterChallengeRequest{Identity: newTestLeaseIdentity(t, "retry"), UDPEnabled: true, TCPEnabled: true}
			port := registry.tcpPorts.available[0]
			var occupied io.Closer
			if network == "tcp" {
				occupied = listenOccupiedTCPPort(t, port)
			} else {
				occupied = listenOccupiedUDPPort(t, port)
			}
			defer occupied.Close()
			rejectOccupiedPortWithoutReserve(t, registry, request)
			registerOtherIdentitySucceeds(t, registry, request)
			_ = occupied.Close()
			reuseRecoveredPortAfterClose(t, registry, request, port)
		})
	}
}

func listenOccupiedTCPPort(t *testing.T, port int) io.Closer {
	t.Helper()
	occupied, err := net.ListenTCP("tcp", &net.TCPAddr{Port: port})
	if err != nil {
		t.Fatal(err)
	}
	return occupied
}

func listenOccupiedUDPPort(t *testing.T, port int) io.Closer {
	t.Helper()
	occupied, err := net.ListenUDP("udp", &net.UDPAddr{Port: port})
	if err != nil {
		t.Fatal(err)
	}
	return occupied
}

func rejectOccupiedPortWithoutReserve(t *testing.T, registry *leaseRegistry, request types.RegisterChallengeRequest) {
	t.Helper()
	if _, _, err := registry.Register(request, netip.Addr{}, "", types.RelayDescriptor{}, nil, nil); err == nil {
		t.Fatal("registration succeeded with an occupied port")
	}
	if len(registry.udpPorts.reserved) != 0 || len(registry.tcpPorts.reserved) != 0 {
		t.Fatal("socket start failure created sticky port reservations")
	}
}

func registerOtherIdentitySucceeds(t *testing.T, registry *leaseRegistry, request types.RegisterChallengeRequest) {
	t.Helper()
	request.Identity = newTestLeaseIdentity(t, "different")
	if _, _, err := registry.Register(request, netip.Addr{}, "", types.RelayDescriptor{}, nil, nil); err != nil {
		t.Fatalf("occupied port prevented another identity using free ports: %v", err)
	}
}

func reuseRecoveredPortAfterClose(t *testing.T, registry *leaseRegistry, request types.RegisterChallengeRequest, port int) {
	t.Helper()
	request.Identity = newTestLeaseIdentity(t, "recovered")
	_, response, err := registry.Register(request, netip.Addr{}, "", types.RelayDescriptor{}, nil, nil)
	if err != nil {
		t.Fatalf("registration could not reuse ports after the socket was closed: %v", err)
	}
	_, actual, _ := net.SplitHostPort(response.TCPAddr)
	if actual != fmt.Sprint(port) {
		t.Fatalf("registration leaked its TCP port: got %s, want %d", actual, port)
	}
	_, actual, _ = net.SplitHostPort(response.UDPAddr)
	if actual != fmt.Sprint(port) {
		t.Fatalf("registration leaked its UDP port: got %s, want %d", actual, port)
	}
}
