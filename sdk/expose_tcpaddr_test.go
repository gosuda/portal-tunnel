package sdk

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/discovery"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func newTCPTestExposure(tcpEnabled bool, listeners map[string]*listener) *Exposure {
	return &Exposure{
		done:           make(chan struct{}),
		cfg:            utils.NewSnapshot(ExposeConfig{TCPEnabled: tcpEnabled}),
		relayListeners: listeners,
	}
}

func tcpLeaseListener(addr string) *listener {
	return &listener{lease: utils.NewSnapshot(listenerSnapshot{
		accessToken: "test-token",
		tcpAddr:     addr,
	})}
}

func TestActiveTCPAddrsDedupesAndSorts(t *testing.T) {
	e := newTCPTestExposure(true, map[string]*listener{
		"https://relay-b.example": tcpLeaseListener("relay-b.example:7001"),
		"https://relay-a.example": tcpLeaseListener("relay-a.example:7000"),
		"https://relay-c.example": tcpLeaseListener("relay-a.example:7000"), // duplicate address
		"https://relay-d.example": tcpLeaseListener(""),                     // lease without tcp addr
		"https://relay-nil":       nil,
	})

	got := e.ActiveTCPAddrs()
	want := []string{"relay-a.example:7000", "relay-b.example:7001"}
	if len(got) != len(want) {
		t.Fatalf("ActiveTCPAddrs() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ActiveTCPAddrs() = %v, want %v", got, want)
		}
	}
}

func TestActiveTCPAddrsSkipsUnregisteredLease(t *testing.T) {
	e := newTCPTestExposure(true, map[string]*listener{
		// tcpAddr set but no access token: registration not completed.
		"https://relay-pending.example": {lease: utils.NewSnapshot(listenerSnapshot{
			tcpAddr: "relay-pending.example:7000",
		})},
	})

	if got := e.ActiveTCPAddrs(); len(got) != 0 {
		t.Fatalf("ActiveTCPAddrs() = %v, want empty for unregistered lease", got)
	}
}

func TestWaitTCPReadyReturnsAllocatedAddrs(t *testing.T) {
	e := newTCPTestExposure(true, map[string]*listener{
		"https://relay-a.example": tcpLeaseListener("relay-a.example:7000"),
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	addrs, err := e.WaitTCPReady(ctx)
	if err != nil {
		t.Fatalf("WaitTCPReady() error = %v", err)
	}
	if len(addrs) != 1 || addrs[0] != "relay-a.example:7000" {
		t.Fatalf("WaitTCPReady() = %v, want [relay-a.example:7000]", addrs)
	}
}

func TestWaitTCPReadyRejectsTCPDisabled(t *testing.T) {
	e := newTCPTestExposure(false, map[string]*listener{
		"https://relay-a.example": tcpLeaseListener("relay-a.example:7000"),
	})

	if _, err := e.WaitTCPReady(context.Background()); err == nil {
		t.Fatal("WaitTCPReady() must error when tcp is not enabled")
	}
}

func TestWaitTCPReadyHonorsContextCancel(t *testing.T) {
	e := newTCPTestExposure(true, map[string]*listener{})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := e.WaitTCPReady(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("WaitTCPReady() error = %v, want context.Canceled", err)
	}
}

func TestSnapshotIncludesRelayTCPAddr(t *testing.T) {
	e := newTCPTestExposure(true, map[string]*listener{
		"https://relay-a.example": {
			lease: utils.NewSnapshot(listenerSnapshot{
				accessToken: "test-token",
				tcpAddr:     "relay-a.example:7000",
			}),
			route:          discovery.NewRoute([]string{"https://relay-a.example"}, true),
			releaseVersion: "v2.4.0",
		},
	})

	snap := e.Snapshot()
	if len(snap.Relays) != 1 {
		t.Fatalf("Snapshot().Relays = %+v, want exactly one relay", snap.Relays)
	}
	relay := snap.Relays[0]
	if relay.TCPAddr != "relay-a.example:7000" {
		t.Fatalf("Snapshot().Relays[0].TCPAddr = %q, want %q", relay.TCPAddr, "relay-a.example:7000")
	}
}
