package acme

import (
	"testing"
	"time"
)

func TestNextSyncDelay(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name                string
		consecutiveFailures int
		want                time.Duration
	}{
		{"synced zone follows the regular cadence", 0, defaultDNSRetryInterval},
		{"negative failures clamp to the regular cadence", -3, defaultDNSRetryInterval},
		{"first failure retries in five seconds", 1, 5 * time.Second},
		{"second failure retries in fifteen seconds", 2, 15 * time.Second},
		{"third failure retries in thirty seconds", 3, 30 * time.Second},
		{"fourth failure retries in one minute", 4, time.Minute},
		{"fifth failure retries in two minutes", 5, 2 * time.Minute},
		{"sixth failure retries in five minutes", 6, 5 * time.Minute},
		{"exhausted schedule settles into the regular cadence", 7, defaultDNSRetryInterval},
		{"far beyond the schedule keeps the regular cadence", 42, defaultDNSRetryInterval},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := nextSyncDelay(tc.consecutiveFailures); got != tc.want {
				t.Fatalf("nextSyncDelay(%d) = %s, want %s", tc.consecutiveFailures, got, tc.want)
			}
		})
	}
}
