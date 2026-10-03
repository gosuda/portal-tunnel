package policy

import (
	"testing"
	"time"
)

func TestWeightedAdmissionIsolatesSourcesAndRefills(t *testing.T) {
	limiter := NewSourceLimiter(10, 20, 600, 200)
	now := time.Now()
	limiter.clock = func() time.Time { return now }
	// Three complete registrations behind one NAT fit the startup burst.
	for range 3 {
		for _, cost := range []int{1, 5} {
			if retry, _ := limiter.Allow("192.0.2.1", cost); retry != 0 {
				t.Fatal("normal startup burst rejected")
			}
		}
	}
	if retry, layer := limiter.Allow("::ffff:192.0.2.1", 5); retry != 18*time.Second || layer != "source" {
		t.Fatalf("weighted rejection = %v, %q", retry, layer)
	}
	if retry, _ := limiter.Allow("192.0.2.2", 5); retry != 0 {
		t.Fatal("unrelated source rejected")
	}
	now = now.Add(18 * time.Second)
	if retry, _ := limiter.Allow("192.0.2.1", 5); retry != 0 {
		t.Fatal("continuous refill failed")
	}
}

func TestGlobalAdmissionBoundsRotatingSources(t *testing.T) {
	limiter := NewSourceLimiter(10, 20, 10, 5)
	now := time.Now()
	limiter.clock = func() time.Time { return now }
	if retry, _ := limiter.Allow("192.0.2.1", 5); retry != 0 {
		t.Fatal("first source rejected")
	}
	if retry, layer := limiter.Allow("192.0.2.2", 1); retry != 6*time.Second || layer != "global" {
		t.Fatalf("global rejection = %v, %q", retry, layer)
	}
	now = now.Add(6 * time.Second)
	if retry, _ := limiter.Allow("192.0.2.2", 1); retry != 0 {
		t.Fatal("global budget did not refill")
	}
}

func TestSourceRejectionDoesNotSpendGlobalBudget(t *testing.T) {
	limiter := NewSourceLimiter(1, 1, 10, 2)
	if retry, _ := limiter.Allow("192.0.2.1", 1); retry != 0 {
		t.Fatal("first request rejected")
	}
	if retry, layer := limiter.Allow("192.0.2.1", 1); retry == 0 || layer != "source" {
		t.Fatal("source budget not enforced")
	}
	if retry, _ := limiter.Allow("192.0.2.2", 1); retry != 0 {
		t.Fatal("rejected source drained global capacity")
	}
}

func TestSourceLimiterBoundsStorageAndExpiresIdleSources(t *testing.T) {
	limiter := NewSourceLimiter(60, 1, 0, 0)
	limiter.maxBucketCount = 1
	now := time.Now()
	limiter.clock = func() time.Time { return now }
	if retry, _ := limiter.Allow("10.0.0.1", 1); retry != 0 {
		t.Fatal("first source rejected")
	}
	if retry, _ := limiter.Allow("10.0.0.2", 1); retry == 0 {
		t.Fatal("storage ceiling not enforced")
	}
	now = now.Add(sourceLimiterIdleTTL + time.Second)
	if retry, _ := limiter.Allow("10.0.0.2", 1); retry != 0 {
		t.Fatal("idle source did not release storage")
	}
}

// Failed pre-auth attempts bill exactly the endpoint weight, and a rejected
// attempt pays nothing, so premature retries never deepen the debt and the
// returned retry window is exact.
func TestPreAuthRejectionChargesNoFailurePenalty(t *testing.T) {
	limiter := NewSourceLimiter(10, 20, 600, 200)
	now := time.Now()
	limiter.clock = func() time.Time { return now }
	for range 4 {
		if retry, layer := limiter.Allow("192.0.2.1", 5); retry != 0 || layer != "" {
			t.Fatalf("register-weighted attempt rejected: %v %q", retry, layer)
		}
	}
	var guidance time.Duration
	for range 3 {
		retry, layer := limiter.Allow("192.0.2.1", 1)
		if retry == 0 || layer != "source" {
			t.Fatalf("exhausted source admitted cost-1 attempt: %v %q", retry, layer)
		}
		if guidance == 0 {
			guidance = retry
		} else if retry != guidance {
			t.Fatalf("rejected attempt changed retry guidance to %v, want stable %v", retry, guidance)
		}
	}
	if guidance != 6*time.Second {
		t.Fatalf("retry guidance = %v, want 6s for cost 1 at 10/min", guidance)
	}
	now = now.Add(guidance)
	if retry, layer := limiter.Allow("192.0.2.1", 1); retry != 0 || layer != "" {
		t.Fatalf("post-retry admission = %v %q, want admitted", retry, layer)
	}
}
