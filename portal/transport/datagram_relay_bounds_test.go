package transport

import (
	"math"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestRelayDatagramActiveFlowCountConcurrentWithLifecycle(t *testing.T) {
	d := NewRelayDatagram(types.NewServiceIdentityKey("lease", "stats"), 0)
	t.Cleanup(d.Close)
	if got := d.ActiveFlowCount(); got != 0 {
		t.Fatalf("initial flow count = %d", got)
	}
	exerciseConcurrentFlowCount(t, d)
	if got := d.ActiveFlowCount(); got != 0 {
		t.Fatalf("final flow count = %d", got)
	}
}

func exerciseConcurrentFlowCount(t *testing.T, d *RelayDatagram) {
	t.Helper()
	var readers sync.WaitGroup
	for range 4 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			probeConcurrentFlowCount(t, d)
		}()
	}
	churnConcurrentFlows(t, d)
	readers.Wait()
}

func probeConcurrentFlowCount(t *testing.T, d *RelayDatagram) {
	t.Helper()
	for range 100 {
		if got := d.ActiveFlowCount(); got < 0 || got > 1 {
			t.Errorf("active flow count = %d", got)
		}
	}
}

func churnConcurrentFlows(t *testing.T, d *RelayDatagram) {
	t.Helper()
	addr := netip.MustParseAddrPort("127.0.0.1:1234")
	for range 50 {
		id, _, ok := d.touchFlow(addr, time.Now())
		if !ok {
			t.Fatal("flow rejected")
		}
		d.forgetFlow(id)
	}
}

func TestRelayDatagramAdmissionPreservesEstablishedFlows(t *testing.T) {
	d := NewRelayDatagram(types.NewServiceIdentityKey("lease", "bounds"), 0)
	t.Cleanup(d.Close)
	now := time.Now()
	addr := netip.MustParseAddrPort("127.0.0.1:1")
	first := admitFirstFlow(t, d, addr, now)
	fillNewFlowBurst(t, d, addr, now)
	checkBurstFlowLimit(t, d, addr, first, now)
	now = fillFlowsToCapacity(t, d, addr, now)
	now = checkFlowsAtCapacity(t, d, addr, first, now)
	reclaimFlowsAfterExpiry(t, d, addr, now)
}

func admitFirstFlow(t *testing.T, d *RelayDatagram, addr netip.AddrPort, now time.Time) uint32 {
	t.Helper()
	first, _, ok := d.touchFlow(addr, now)
	if !ok {
		t.Fatal("first flow rejected")
	}
	return first
}

func fillNewFlowBurst(t *testing.T, d *RelayDatagram, addr netip.AddrPort, now time.Time) {
	t.Helper()
	for port := 2; port <= defaultUDPNewFlowBurst; port++ {
		if _, _, ok := d.touchFlow(netip.AddrPortFrom(addr.Addr(), uint16(port)), now); !ok {
			t.Fatalf("flow %d within burst rejected", port)
		}
	}
}

func checkBurstFlowLimit(t *testing.T, d *RelayDatagram, addr netip.AddrPort, first uint32, now time.Time) {
	t.Helper()
	if _, _, ok := d.touchFlow(netip.MustParseAddrPort("127.0.0.1:65535"), now); ok {
		t.Fatal("new flow admitted beyond burst")
	}
	if got, fresh, ok := d.touchFlow(addr, now); !ok || fresh || got != first {
		t.Fatal("established flow rejected by new-flow budget")
	}
}

func fillFlowsToCapacity(t *testing.T, d *RelayDatagram, addr netip.AddrPort, now time.Time) time.Time {
	t.Helper()
	for port := defaultUDPNewFlowBurst + 1; port <= types.DefaultUDPMaxFlows; port++ {
		now = now.Add(time.Second)
		if _, _, ok := d.touchFlow(netip.AddrPortFrom(addr.Addr(), uint16(port)), now); !ok {
			t.Fatalf("flow %d below capacity rejected", port)
		}
	}
	return now
}

func checkFlowsAtCapacity(t *testing.T, d *RelayDatagram, addr netip.AddrPort, first uint32, now time.Time) time.Time {
	t.Helper()
	now = now.Add(time.Second)
	if _, _, ok := d.touchFlow(netip.MustParseAddrPort("127.0.0.1:65535"), now); ok {
		t.Fatal("new flow admitted beyond capacity")
	}
	if got, fresh, ok := d.touchFlow(addr, now); !ok || fresh || got != first {
		t.Fatal("established flow rejected at capacity")
	}
	if len(d.flowTable) != types.DefaultUDPMaxFlows || len(d.addrIndex) != types.DefaultUDPMaxFlows {
		t.Fatal("flow indexes exceeded capacity or diverged")
	}
	return now
}

func reclaimFlowsAfterExpiry(t *testing.T, d *RelayDatagram, addr netip.AddrPort, now time.Time) {
	t.Helper()
	d.expireIdleFlows(now.Add(types.DefaultUDPFlowIdleTimeout + time.Nanosecond))
	if len(d.flowTable) != 0 || len(d.addrIndex) != 0 {
		t.Fatal("idle flows retained")
	}
	if _, _, ok := d.touchFlow(addr, now.Add(types.DefaultUDPFlowIdleTimeout+time.Second)); !ok {
		t.Fatal("capacity was not recovered after expiry")
	}
}

func TestRelayDatagramFlowIDWrapPreservesLiveMappings(t *testing.T) {
	d := NewRelayDatagram(types.NewServiceIdentityKey("lease", "wrap"), 0)
	t.Cleanup(d.Close)
	now := time.Now()
	firstAddr := netip.MustParseAddrPort("127.0.0.1:1")
	first, _, _ := d.touchFlow(firstAddr, now)
	d.nextFlow = math.MaxUint32
	for port := uint16(2); port <= 4; port++ {
		addr := netip.AddrPortFrom(firstAddr.Addr(), port)
		id, _, ok := d.touchFlow(addr, now)
		if !ok || id == first || d.flowTable[id].addr != addr {
			t.Fatalf("wrapped flow %d overwrote an existing mapping", id)
		}
	}
	if len(d.flowTable) != 4 || len(d.addrIndex) != 4 || d.flowTable[first].addr != firstAddr {
		t.Fatal("wrap corrupted flow indexes")
	}
}

func TestRelayDatagramDisconnectedIngressRetainsNoFlows(t *testing.T) {
	d := NewRelayDatagram(types.NewServiceIdentityKey("lease", "disconnected"), 0)
	t.Cleanup(d.Close)
	d.SetEnabled(true)
	for port := uint16(1); port <= types.DefaultUDPMaxFlows*2; port++ {
		d.forwardDatagram(netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port), []byte("packet"))
	}
	if len(d.flowTable) != 0 || len(d.addrIndex) != 0 {
		t.Fatal("disconnected ingress retained flow state")
	}
}
