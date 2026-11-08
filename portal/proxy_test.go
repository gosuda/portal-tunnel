package portal

import (
	"context"
	"net"
	"testing"
	"testing/synctest"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestIdentityBPSDefaultAndOverrides(t *testing.T) {
	manager := NewBPSManager(types.DefaultIdentityBPS)
	key := types.NewServiceIdentityKey("tenant", "address")
	other := types.NewServiceIdentityKey("other", "address")
	if got := manager.IdentityBPS(key); got != types.DefaultIdentityBPS {
		t.Fatalf("new identity limit = %d, want %d", got, types.DefaultIdentityBPS)
	}
	manager.SetIdentityBPS(key, 4*types.DefaultIdentityBPS)
	if manager.IdentityBPS(key) != 4*types.DefaultIdentityBPS || manager.IdentityBPS(other) != types.DefaultIdentityBPS {
		t.Fatal("individual override changed the default for other identities")
	}
	manager.SetIdentityBPS(key, 0)
	if got := manager.IdentityBPS(key); got != 0 {
		t.Fatalf("explicit unlimited inherited default: %d", got)
	}
	manager.SetServiceIdentityBPSLimits(map[types.ServiceIdentityKey]int64{key: 0})
	if got := manager.IdentityBPS(key); got != 0 {
		t.Fatalf("bulk policy update lost explicit unlimited: %d", got)
	}
	manager.SetServiceIdentityBPSLimits(nil)
	if got := manager.IdentityBPS(key); got != types.DefaultIdentityBPS {
		t.Fatalf("absent override did not inherit default: %d", got)
	}
}

// Reapplying unrelated policy must not discard a default-limited identity's
// accrued credit; the identity has no entry in the override map.
func TestDefaultBPSRetainsCreditAcrossPolicyUpdates(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		manager := NewBPSManager(100)
		key := types.NewServiceIdentityKey("tenant", "address")
		done := make(chan int, 1)
		go func() {
			n, err := manager.ThrottleIdentityBPS(t.Context(), key, 10)
			if err != nil {
				t.Error(err)
			}
			done <- n
		}()
		synctest.Wait()
		synctest.Sleep(60 * time.Millisecond)
		manager.SetServiceIdentityBPSLimits(nil)
		synctest.Sleep(40 * time.Millisecond)
		synctest.Wait()
		select {
		case n := <-done:
			if n != 10 {
				t.Fatalf("throttle returned %d bytes, want 10", n)
			}
		default:
			t.Fatal("default-limited identity lost credit during policy update")
		}
	})
}

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

func TestReplacingBPSLimitsPreservesAccruedCredit(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		manager := NewBPSManager(0)
		key := types.NewServiceIdentityKey("tenant", "address")
		manager.SetIdentityBPS(key, 100)
		done := make(chan int, 1)
		go func() {
			n, err := manager.ThrottleIdentityBPS(ctx, key, 10)
			if err != nil {
				n = -1
			}
			done <- n
		}()
		synctest.Wait()
		synctest.Sleep(60 * time.Millisecond)
		manager.SetServiceIdentityBPSLimits(map[types.ServiceIdentityKey]int64{key: 100})
		synctest.Sleep(40 * time.Millisecond)
		synctest.Wait()
		select {
		case n := <-done:
			if n != 10 {
				t.Fatalf("throttle returned %d bytes, want 10", n)
			}
		default:
			t.Fatal("reapplying the limit discarded already accrued bandwidth credit")
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
		bps := NewBPSManager(0)
		key := types.NewServiceIdentityKey("lease", "0x1")
		bps.SetIdentityBPS(key, 1)
		done := make(chan struct{})
		go func() { defer close(done); var p proxy; p.bridge(ctx, left, right, key, bps) }()
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
