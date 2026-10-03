package portal

import (
	"testing"
	"testing/synctest"
	"time"
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
