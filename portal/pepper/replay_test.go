package pepper

import (
	"testing"
	"time"
)

func TestReplayCacheRejectsDuplicateBundleIdentities(t *testing.T) {
	t.Parallel()

	cache, err := NewReplayCache(2*time.Second, time.Second, 16)
	if err != nil {
		t.Fatalf("new replay cache: %v", err)
	}
	now := time.Unix(100, 0)
	if duplicate := cache.SeenOrAdd([]byte("bundle-1"), now); duplicate {
		t.Fatal("first bundle identity should not be duplicate")
	}
	if duplicate := cache.SeenOrAdd([]byte("bundle-1"), now.Add(500*time.Millisecond)); !duplicate {
		t.Fatal("expected duplicate bundle identity to be rejected")
	}
}

func TestReplayCacheExpiresOldIdentities(t *testing.T) {
	t.Parallel()

	cache, err := NewReplayCache(2*time.Second, time.Second, 16)
	if err != nil {
		t.Fatalf("new replay cache: %v", err)
	}
	now := time.Unix(100, 0)
	if duplicate := cache.SeenOrAdd([]byte("bundle-1"), now); duplicate {
		t.Fatal("first bundle identity should not be duplicate")
	}
	if duplicate := cache.SeenOrAdd([]byte("bundle-1"), now.Add(3*time.Second)); duplicate {
		t.Fatal("expired bundle identity should no longer be duplicate")
	}
}
