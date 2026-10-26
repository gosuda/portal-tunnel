package portal

import (
	"context"
	"net"
	"testing"
	"testing/synctest"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestBPSWaitRetainsAccruedCredit(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var limiter bpsLimiter
		if wait := limiter.reserve(10, 100); wait != 100*time.Millisecond {
			t.Fatalf("initial wait = %v, want 100ms", wait)
		}
		synctest.Sleep(60 * time.Millisecond)
		if wait := limiter.reserve(10, 100); wait != 40*time.Millisecond {
			t.Fatalf("remaining wait = %v, want 40ms", wait)
		}
		synctest.Sleep(40 * time.Millisecond)
		if wait := limiter.reserve(10, 100); wait != 0 {
			t.Fatalf("10 bytes still throttled after 100ms at 100 B/s: %v", wait)
		}
	})
}

func TestBridgeCancellationInterruptsThrottle(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		left, client := net.Pipe()
		right, peer := net.Pipe()
		defer client.Close()
		defer peer.Close()
		bps := NewBPSManager()
		key := types.NewServiceIdentityKey("lease", "0x1")
		bps.SetIdentityBPS(key, 1)
		done := make(chan struct{})
		go func() { defer close(done); var p proxy; p.bridge(ctx, left, right, key, bps, nil, nil) }()
		go func() { _, _ = client.Write([]byte("throttled")) }()
		synctest.Wait()
		cancel()
		synctest.Wait()
		select {
		case <-done:
		default:
			t.Fatal("bridge retained workers while throttle canceled")
		}
	})
}
