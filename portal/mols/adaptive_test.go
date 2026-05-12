package mols

import (
	"testing"
	"time"
)

func TestPoolRTTStatsMean(t *testing.T) {
	candidates := []Candidate{
		{RTT: 100 * time.Millisecond, RTTAt: time.Now()},
		{RTT: 200 * time.Millisecond, RTTAt: time.Now()},
		{RTT: 300 * time.Millisecond, RTTAt: time.Now()},
	}
	mean, _ := poolRTTStats(candidates)
	if mean != 200*time.Millisecond {
		t.Fatalf("mean = %v, want 200ms", mean)
	}
}

func TestPoolRTTStatsCVUniform(t *testing.T) {
	candidates := []Candidate{
		{RTT: 100 * time.Millisecond, RTTAt: time.Now()},
		{RTT: 100 * time.Millisecond, RTTAt: time.Now()},
		{RTT: 100 * time.Millisecond, RTTAt: time.Now()},
	}
	_, cv := poolRTTStats(candidates)
	if cv != 0 {
		t.Fatalf("cv = %v, want 0 for uniform distribution", cv)
	}
}

func TestPoolRTTStatsCVHigh(t *testing.T) {
	candidates := []Candidate{
		{RTT: 10 * time.Millisecond, RTTAt: time.Now()},
		{RTT: 2000 * time.Millisecond, RTTAt: time.Now()},
	}
	_, cv := poolRTTStats(candidates)
	if cv <= DefaultCVThreshold {
		t.Fatalf("cv = %v, want > %v for high-variance distribution", cv, DefaultCVThreshold)
	}
}

func TestPoolRTTStatsSkipsMissingRTT(t *testing.T) {
	candidates := []Candidate{
		{RTT: 100 * time.Millisecond, RTTAt: time.Now()},
		{RTT: 999 * time.Second}, // no RTTAt → excluded
	}
	mean, _ := poolRTTStats(candidates)
	if mean != 100*time.Millisecond {
		t.Fatalf("mean = %v, want 100ms (excluded candidate with zero RTTAt)", mean)
	}
}

func TestIsFallbackHighRTT(t *testing.T) {
	c := Candidate{
		RTT:   DefaultFallbackRTTThreshold + time.Millisecond,
		RTTAt: time.Now(),
	}
	if !isFallback(c, DefaultFallbackRTTThreshold) {
		t.Fatal("expected high-RTT candidate to be classified as fallback")
	}
}

func TestIsFallbackNormalRTT(t *testing.T) {
	c := Candidate{
		RTT:   200 * time.Millisecond,
		RTTAt: time.Now(),
	}
	if isFallback(c, DefaultFallbackRTTThreshold) {
		t.Fatal("expected normal-RTT candidate not to be classified as fallback")
	}
}

func TestDefaultAdaptivePartitionPromotesFallbacks(t *testing.T) {
	cfg := DefaultConfig()
	candidates := []Candidate{
		{ID: "f1", RTT: 3 * time.Second, RTTAt: time.Now()},
		{ID: "f2", RTT: 4 * time.Second, RTTAt: time.Now()},
	}
	var s DefaultAdaptiveStrategy
	active, fallback := s.Partition(candidates, cfg)
	if len(active) != 2 {
		t.Fatalf("expected both fallbacks promoted to active, got active=%d fallback=%d", len(active), len(fallback))
	}
}

func TestDefaultAdaptivePartitionKeepsHealthyActive(t *testing.T) {
	cfg := DefaultConfig()
	candidates := []Candidate{
		{ID: "a1", RTT: 100 * time.Millisecond, RTTAt: time.Now(), Healthy: true},
		{ID: "a2", RTT: 150 * time.Millisecond, RTTAt: time.Now(), Healthy: true},
		{ID: "f1", RTT: 3 * time.Second, RTTAt: time.Now()},
	}
	var s DefaultAdaptiveStrategy
	active, fallback := s.Partition(candidates, cfg)
	if len(active) != 2 || len(fallback) != 1 {
		t.Fatalf("expected active=2 fallback=1, got active=%d fallback=%d", len(active), len(fallback))
	}
	if fallback[0].ID != "f1" {
		t.Fatalf("expected fallback f1, got %s", fallback[0].ID)
	}
}
