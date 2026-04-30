package discovery

import (
	"errors"
	"math"
	"sync"
	"testing"
	"time"
)

// tolerance for float64 EWMA assertions.
const ewmaTol = 1e-6

func floatNear(got, want, tol float64) bool {
	return math.Abs(got-want) < tol
}

// TestLifecycleSampleLoadZeroInit verifies that a zero-value RelayState has
// LoadFactor == 0 and that after SampleLoad(1.0, now) on a zero LastUpdated
// (first sample, no decay) LoadFactor == 1.0.
func TestLifecycleSampleLoadZeroInit(t *testing.T) {
	lc := NewLifecycle()
	state := RelayState{}

	if state.LoadFactor != 0 {
		t.Fatalf("initial LoadFactor = %v, want 0", state.LoadFactor)
	}

	now := time.Now().UTC()
	state = lc.SampleLoad(state, 1.0, now)

	if !floatNear(state.LoadFactor, 1.0, ewmaTol) {
		t.Errorf("LoadFactor after first sample = %v, want 1.0 (no decay on zero LastUpdated)", state.LoadFactor)
	}
	if state.LastUpdated != now {
		t.Errorf("LastUpdated = %v, want %v", state.LastUpdated, now)
	}
}

// TestLifecycleSampleLoadDeltaPerEvent verifies that two consecutive samples
// with dt < tau produce the expected accumulated value:
//
//	after sample1: LoadFactor = sample1
//	after sample2: LoadFactor ≈ sample1*decay + sample2
func TestLifecycleSampleLoadDeltaPerEvent(t *testing.T) {
	lc := NewLifecycleWithConfig(LifecycleConfig{
		LoadTau:     defaultLoadTau,
		FailureTau:  defaultFailureTau,
		FailureBeta: defaultFailureBeta,
	})
	state := RelayState{}

	t0 := time.Now().UTC()
	state = lc.SampleLoad(state, 2.0, t0)
	if !floatNear(state.LoadFactor, 2.0, ewmaTol) {
		t.Fatalf("after first sample LoadFactor = %v, want 2.0", state.LoadFactor)
	}

	// dt = tau/3, well below tau so decay is significant but < 1.
	dt := defaultLoadTau / 3
	t1 := t0.Add(dt)
	state = lc.SampleLoad(state, 3.0, t1)

	decay := math.Exp(-float64(dt) / float64(defaultLoadTau))
	want := 2.0*decay + 3.0
	if !floatNear(state.LoadFactor, want, ewmaTol) {
		t.Errorf("LoadFactor after second sample = %v, want %v (decay=%.6f)", state.LoadFactor, want, decay)
	}
}

// TestLifecycleSampleLoadDecayAtTau verifies that after one sample at t=0, a
// zero-sample at t=tau leaves LoadFactor at approximately e^(-1) ≈ 0.368 of
// the original value. Tolerance: 1e-6.
func TestLifecycleSampleLoadDecayAtTau(t *testing.T) {
	lc := NewLifecycle()
	state := RelayState{}

	t0 := time.Now().UTC()
	const original = 1.0
	state = lc.SampleLoad(state, original, t0)

	// One tau later, zero-sample: LoadFactor = original * e^(-1) + 0.
	tTau := t0.Add(defaultLoadTau)
	state = lc.SampleLoad(state, 0.0, tTau)

	wantDecay := original * math.Exp(-1.0)
	if !floatNear(state.LoadFactor, wantDecay, ewmaTol) {
		t.Errorf("LoadFactor at t=tau = %v, want e^(-1) ≈ %v (tol %v)", state.LoadFactor, wantDecay, ewmaTol)
	}
}

// TestLifecycleSampleLoadConcurrentSafe spawns N goroutines each calling
// SampleLoad under a shared test mutex (simulating RelaySet.mu ownership).
// It verifies:
//   - LoadFactor is non-NaN after all updates (no torn float write)
//   - LastUpdated is non-zero
//   - LastUpdated never goes backward (monotonically non-decreasing across
//     observed snapshots captured while holding the mutex)
func TestLifecycleSampleLoadConcurrentSafe(t *testing.T) {
	const N = 50
	lc := NewLifecycle()

	var mu sync.Mutex
	state := RelayState{}

	// Collect each LastUpdated value in order of lock acquisition so we can
	// assert monotonicity after all goroutines complete.
	updates := make([]time.Time, 0, N)

	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			mu.Lock()
			now := time.Now().UTC() // captured under lock so timestamps are lock-acquisition-ordered
			state = lc.SampleLoad(state, 1.0, now)
			updates = append(updates, state.LastUpdated)
			mu.Unlock()
		}()
	}
	wg.Wait()

	mu.Lock()
	finalLoadFactor := state.LoadFactor
	finalLastUpdated := state.LastUpdated
	capturedUpdates := append([]time.Time(nil), updates...)
	mu.Unlock()

	if math.IsNaN(finalLoadFactor) {
		t.Errorf("LoadFactor is NaN after concurrent SampleLoad calls")
	}
	if finalLastUpdated.IsZero() {
		t.Errorf("LastUpdated is zero after concurrent SampleLoad calls")
	}
	// LastUpdated must be non-decreasing across observed lock acquisitions.
	for i := 1; i < len(capturedUpdates); i++ {
		if capturedUpdates[i].Before(capturedUpdates[i-1]) {
			t.Errorf("LastUpdated went backward at index %d: %v < %v",
				i, capturedUpdates[i], capturedUpdates[i-1])
		}
	}
}

// TestLifecycleOnSuccessDecaysFailureRate verifies that OnSuccess decays a
// previously set FailureRate toward zero without bumping it.
//
// To guarantee a measurable decay without relying on wall-clock elapsed time,
// we set state.LastUpdated to one failureTau in the past before calling
// OnSuccess. At dt == failureTau, decay == e^(-1) ≈ 0.368, so the resulting
// FailureRate must be strictly less than the initial value.
func TestLifecycleOnSuccessDecaysFailureRate(t *testing.T) {
	lc := NewLifecycle()
	state := RelayState{}

	// Bump FailureRate via OnDiscoveryFailure (budget = 999 so no backoff).
	// LastUpdated is zero before this call, so no decay is applied and
	// FailureRate becomes exactly 1.0.
	state, _, _ = lc.OnDiscoveryFailure(state, errors.New("err"), 999)
	initialFailureRate := state.FailureRate
	if initialFailureRate <= 0 {
		t.Fatalf("FailureRate after OnDiscoveryFailure = %v, want > 0", initialFailureRate)
	}

	// Wind LastUpdated back by one failureTau so OnSuccess sees a guaranteed
	// positive dt and applies a meaningful decay (e^(-1) ≈ 0.368 factor).
	state.LastUpdated = time.Now().UTC().Add(-defaultFailureTau)

	state = lc.OnSuccess(state)
	if state.FailureRate >= initialFailureRate {
		t.Errorf("FailureRate after OnSuccess = %v, want < %v (should decay)", state.FailureRate, initialFailureRate)
	}
	if state.FailureRate < 0 {
		t.Errorf("FailureRate after OnSuccess = %v, want >= 0", state.FailureRate)
	}
}

// TestLifecycleOnFailureBumpsFailureRate verifies that both OnDiscoveryFailure
// and OnActiveFailure each increment FailureRate by a measurable amount.
func TestLifecycleOnFailureBumpsFailureRate(t *testing.T) {
	lc := NewLifecycle()

	// OnDiscoveryFailure on a zero state (no decay on first call because
	// LastUpdated is zero) must produce FailureRate == 1.0.
	state1 := RelayState{}
	state1, _, _ = lc.OnDiscoveryFailure(state1, errors.New("disc fail"), 999)
	if !floatNear(state1.FailureRate, 1.0, ewmaTol) {
		t.Errorf("OnDiscoveryFailure: FailureRate = %v, want 1.0", state1.FailureRate)
	}

	// OnActiveFailure on a zero state must similarly produce FailureRate == 1.0.
	state2 := RelayState{}
	state2, _, _ = lc.OnActiveFailure(state2, errors.New("active fail"), 999)
	if !floatNear(state2.FailureRate, 1.0, ewmaTol) {
		t.Errorf("OnActiveFailure: FailureRate = %v, want 1.0", state2.FailureRate)
	}

	// A second failure on the same state (dt ≈ 0 between the two calls in
	// the same test) bumps FailureRate further; it must be > 1.0.
	priorRate := state1.FailureRate
	state1, _, _ = lc.OnDiscoveryFailure(state1, errors.New("disc fail 2"), 999)
	if state1.FailureRate <= priorRate {
		t.Errorf("second OnDiscoveryFailure: FailureRate = %v, want > %v", state1.FailureRate, priorRate)
	}
}
