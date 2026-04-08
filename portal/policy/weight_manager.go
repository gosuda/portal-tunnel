package policy

// Package policy — weight_manager.go
//
// WeightManager collects per-protocol load contributions and merges them into a
// NodeLoad for OLS scoring.  The design decouples the scoring logic from any
// specific transport protocol (WireGuard, raw TCP, HTTPS, …) by classifying
// contributors into two groups:
//
//  1. Immediate contributors — protocols whose application-layer payloads can
//     be parsed by the relay (currently HTTP/S).  These populate both the
//     network-observable fields and the application-level fields (ErrorRate,
//     P99LatencyMs), and their changes are reflected in the OLS load score
//     immediately on the next Collect call.
//
//  2. Deferred contributors — opaque transports (WireGuard, plain TCP, etc.)
//     whose application payloads the relay cannot interpret.  These only fill
//     the network-observable fields (BurstScore, DelayMs, JitterMs), which are
//     derived from externally visible behaviour such as inter-arrival jitter,
//     RTT measurements, or token-bucket fullness.  They must never read or
//     expose transport-internal configuration (WireGuard keys, peer IPs, …).
//
// Callers register named contributor functions via Register and retrieve the
// merged NodeLoad via Collect.  The zero WeightManager (no contributors) returns
// a zero NodeLoad so that callers do not need to nil-check.

import (
	"math"
	"sync"
	"sync/atomic"
	"time"
)

// PartialLoad is the per-observation load contribution returned by a single
// contributor function.  Fields are split by observability class so that
// contributors can only populate the fields appropriate for their protocol.
type PartialLoad struct {
	// --- Network-observable (all protocols) ---

	// BurstScore is a normalised 0–1 estimate of current burst traffic
	// intensity.  Callers derive this from inter-arrival time variance, queue
	// depth, or token-bucket fill level.  0 = idle, 1 = fully saturated.
	BurstScore float64

	// DelayMs is the latest observed one-way or round-trip delay in
	// milliseconds.  0 means no measurement is available.
	DelayMs float64

	// JitterMs is the variance of recent delay samples in milliseconds.
	// Higher jitter indicates an unstable or congested path.
	JitterMs float64

	// --- Application-observable (immediate contributors / HTTP-S only) ---

	// ErrorRate is the fraction of recent requests that returned a 4xx or
	// 5xx status code.  Range: 0 (no errors) … 1 (all requests failed).
	// Deferred contributors must leave this at zero.
	ErrorRate float64

	// P99LatencyMs is the 99th-percentile request latency in milliseconds
	// over the most recent observation window.  Deferred contributors must
	// leave this at zero.
	P99LatencyMs float64
}

// ContributorFunc is the callback signature for a registered contributor.
// Each function is called once per Collect invocation and must return its
// latest PartialLoad without blocking.  A zero PartialLoad is valid and
// means "no data available yet".
type ContributorFunc func() PartialLoad

// WeightManager aggregates PartialLoad values from all registered contributors
// and fuses them into a NodeLoad.
//
// Thread-safety: Register and Collect may be called concurrently.
type WeightManager struct {
	mu           sync.RWMutex
	contributors map[string]ContributorFunc
}

// NewWeightManager returns an empty, ready-to-use WeightManager.
func NewWeightManager() *WeightManager {
	return &WeightManager{
		contributors: make(map[string]ContributorFunc),
	}
}

// Register adds or replaces the contributor identified by name.
// Passing fn == nil removes the contributor with that name.
func (m *WeightManager) Register(name string, fn ContributorFunc) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if fn == nil {
		delete(m.contributors, name)
		return
	}
	m.contributors[name] = fn
}

// Collect polls every registered contributor and fuses the results into a
// NodeLoad.  Only AvgLatencyMs is populated; the counters (ActiveConns,
// BytesIn, BytesOut, ConnRate) are owned by LoadManager and must be merged
// by the caller.
//
// Fusion rules applied in order:
//
//  1. Base latency  ← arithmetic mean of all non-zero DelayMs values.
//  2. P99 override  ← if any immediate contributor reports P99LatencyMs,
//     base latency is raised to max(base, mean_P99).
//  3. Jitter penalty ← base += mean(JitterMs) × 0.5 (half average jitter).
//  4. Error penalty  ← base += mean(ErrorRate) × 200 ms (1 % error ≈ +2 ms).
//  5. Burst penalty  ← base += max(BurstScore) × 50 ms (full burst ≈ +50 ms).
func (m *WeightManager) Collect() NodeLoad {
	m.mu.RLock()
	fns := make([]ContributorFunc, 0, len(m.contributors))
	for _, fn := range m.contributors {
		fns = append(fns, fn)
	}
	m.mu.RUnlock()

	if len(fns) == 0 {
		return NodeLoad{}
	}

	var (
		delaySum   float64
		delayCount int
		jitterSum  float64
		errorSum   float64
		p99Sum     float64
		p99Count   int
		burstMax   float64
	)

	for _, fn := range fns {
		pl := fn()
		if pl.DelayMs > 0 {
			delaySum += pl.DelayMs
			delayCount++
		}
		jitterSum += pl.JitterMs
		errorSum += pl.ErrorRate
		if pl.P99LatencyMs > 0 {
			p99Sum += pl.P99LatencyMs
			p99Count++
		}
		if pl.BurstScore > burstMax {
			burstMax = pl.BurstScore
		}
	}

	// len(fns) > 0 is guaranteed by the early-return above; n is safe to divide by.
	n := float64(len(fns))

	// 1. Base latency from network-level delay observations.
	base := 0.0
	if delayCount > 0 {
		base = delaySum / float64(delayCount)
	}

	// 2. Raise base to the mean P99 when application-level data is available.
	if p99Count > 0 {
		base = math.Max(base, p99Sum/float64(p99Count))
	}

	// 3. Jitter penalty.
	base += (jitterSum / n) * 0.5

	// 4. Error-rate penalty: each 1 % error rate contributes ~2 ms.
	base += (errorSum / n) * 200

	// 5. Burst penalty: up to 50 ms extra for a fully saturated path.
	base += burstMax * 50

	return NodeLoad{AvgLatencyMs: base, JitterMs: jitterSum / n}
}

// ---------------------------------------------------------------------------
// Built-in contributor implementations
// ---------------------------------------------------------------------------

// HTTPContributor is an immediate contributor for HTTP/S traffic.  It records
// per-request status codes and latencies and exposes a ContributorFunc for use
// with WeightManager.Register.
//
// Typical usage:
//
//	c := policy.NewHTTPContributor(30 * time.Second)
//	weightMgr.Register("https", c.Observe)
//	// In HTTP handler:
//	c.RecordRequest(resp.StatusCode, latencyMs)
type HTTPContributor struct {
	mu      sync.Mutex
	window  time.Duration // sliding window duration
	samples []httpSample
}

type httpSample struct {
	at         time.Time
	latencyMs  float64
	statusCode int
}

// NewHTTPContributor returns a contributor that retains samples within window.
func NewHTTPContributor(window time.Duration) *HTTPContributor {
	return &HTTPContributor{window: window}
}

// RecordRequest records a completed HTTP request.  statusCode is the HTTP
// response status (e.g. 200, 500).  latencyMs is the total request latency
// in milliseconds.
func (c *HTTPContributor) RecordRequest(statusCode int, latencyMs float64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.samples = append(c.samples, httpSample{
		at:         time.Now(),
		latencyMs:  latencyMs,
		statusCode: statusCode,
	})
}

// Observe returns the PartialLoad for the current window.  It is safe to use
// as a ContributorFunc.
func (c *HTTPContributor) Observe() PartialLoad {
	c.mu.Lock()
	defer c.mu.Unlock()

	cutoff := time.Now().Add(-c.window)
	// Discard expired samples in-place.
	valid := c.samples[:0]
	for _, s := range c.samples {
		if s.at.After(cutoff) {
			valid = append(valid, s)
		}
	}
	c.samples = valid

	if len(valid) == 0 {
		return PartialLoad{}
	}

	// Sort-free P99: collect latencies, then select.
	lats := make([]float64, len(valid))
	errors := 0
	for i, s := range valid {
		lats[i] = s.latencyMs
		if s.statusCode >= 400 {
			errors++
		}
	}
	p99 := percentile99(lats)

	return PartialLoad{
		P99LatencyMs: p99,
		ErrorRate:    float64(errors) / float64(len(valid)),
	}
}

// percentile99 returns an approximation of the 99th percentile without
// sorting: it uses a single-pass algorithm that is O(n) in time and O(1)
// in additional space (reservoir with fixed size 100).
func percentile99(data []float64) float64 {
	if len(data) == 0 {
		return 0
	}
	// For small samples just scan for max, which is a reasonable P99 proxy.
	if len(data) < 10 {
		max := data[0]
		for _, v := range data[1:] {
			if v > max {
				max = v
			}
		}
		return max
	}
	// Use a fixed-size top-k reservoir to approximate P99.
	// P99 of n samples ≈ the element at rank ceil(n*0.99).
	k := int(math.Ceil(float64(len(data)) * 0.01)) // keep top 1%
	if k < 1 {
		k = 1
	}
	// Simple O(n) selection: find the k-th largest by maintaining a min-heap
	// of size k using a slice (avoids importing container/heap).
	top := make([]float64, 0, k+1)
	for _, v := range data {
		top = append(top, v)
		if len(top) > k {
			// Remove the minimum from top to keep only the k largest.
			minIdx := 0
			for i, x := range top {
				if x < top[minIdx] {
					minIdx = i
				}
			}
			top[minIdx] = top[len(top)-1]
			top = top[:len(top)-1]
		}
	}
	// The smallest element in the top-k set is our P99 estimate.
	p99 := top[0]
	for _, v := range top[1:] {
		if v < p99 {
			p99 = v
		}
	}
	return p99
}

// ---------------------------------------------------------------------------

// NetworkContributor is a deferred contributor for opaque transports (e.g.
// WireGuard tunnels, plain TCP).  It exposes only network-observable signals:
// RTT delay, jitter, and burst intensity.  It must not read or expose any
// transport-internal state.
//
// Typical usage:
//
//	c := policy.NewNetworkContributor()
//	weightMgr.Register("wireguard-overlay", c.Observe)
//	// When an RTT measurement arrives:
//	c.RecordRTT(rttMs)
//	// When burst intensity changes:
//	c.RecordBurst(burstScore)
type NetworkContributor struct {
	// Atomic fields for lock-free reads in the hot path.
	burstScore   uint64 // math.Float64bits
	lastDelayMs  uint64 // math.Float64bits
	lastJitterMs uint64 // math.Float64bits
}

// NewNetworkContributor returns a NetworkContributor with all zeroes.
func NewNetworkContributor() *NetworkContributor {
	return &NetworkContributor{}
}

// RecordRTT records a round-trip time measurement in milliseconds.  Jitter is
// computed as the absolute deviation from the previous recorded RTT using the
// RFC 3550 formula.
func (c *NetworkContributor) RecordRTT(rttMs float64) {
	if rttMs < 0 {
		rttMs = 0
	}
	prev := math.Float64frombits(atomic.LoadUint64(&c.lastDelayMs))
	// RFC 3550 jitter: J += (|D| - J) / 16
	prevJitter := math.Float64frombits(atomic.LoadUint64(&c.lastJitterMs))
	d := math.Abs(rttMs - prev)
	newJitter := prevJitter + (d-prevJitter)/16
	atomic.StoreUint64(&c.lastDelayMs, math.Float64bits(rttMs))
	atomic.StoreUint64(&c.lastJitterMs, math.Float64bits(newJitter))
}

// RecordBurst updates the burst-intensity estimate.  score must be in [0, 1].
func (c *NetworkContributor) RecordBurst(score float64) {
	if score < 0 {
		score = 0
	} else if score > 1 {
		score = 1
	}
	atomic.StoreUint64(&c.burstScore, math.Float64bits(score))
}

// Observe returns the current PartialLoad snapshot.  It is safe to use as a
// ContributorFunc.
func (c *NetworkContributor) Observe() PartialLoad {
	return PartialLoad{
		BurstScore: math.Float64frombits(atomic.LoadUint64(&c.burstScore)),
		DelayMs:    math.Float64frombits(atomic.LoadUint64(&c.lastDelayMs)),
		JitterMs:   math.Float64frombits(atomic.LoadUint64(&c.lastJitterMs)),
	}
}
