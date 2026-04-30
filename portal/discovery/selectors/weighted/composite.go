package weighted

// Composite wraps an inner Selector and applies a load-aware additive penalty.
//
// # Final Ranking Score
//
//	final[i] = mols_position[i] + lambda * tier_load(state[i])
//
// where tier_load is the load factor quantized to a discrete tier:
//
//	tier_load = floor(load_factor / epsilon) * epsilon
//
// load_factor reads RelayState.LoadFactor + RelayState.FailureRate*beta. The
// per-relay state already smooths via EWMA tau (Lifecycle owns that), so this
// layer only adds within-tier quantization to suppress sub-tier rank flap.
//
// # Bootstrap-Pin Invariant
//
// Bootstrap relays remain in the inner pool (Lifecycle guarantees), but the
// load penalty applies uniformly here — a bootstrap relay can demote out of
// top-K when overloaded.
//
// # Deferred: Power-of-Two-Choices (P2C)
//
// When adjacent final scores lie within one epsilon tier, a P2C tiebreak
// sampling two candidates and picking the one with fewer active_tunnels would
// further reduce imbalance. Active-tunnel gauge values are not programmatically
// readable on the hot path in Stage 4, so P2C is deferred to Stage 5.
// Within-tier quantization already suppresses most flapping; P2C is a future
// hardening step.
//
// # Trace Contract
//
// SelectPriority and SelectMultiHop shallow-copy the inner SelectionTrace and
// replace OutputURLs with the post-penalty ordering. The inner trace fields
// (Ranked, Suppressed, Reasons, etc.) are not re-sorted; they reflect MOLS
// scoring only. Callers inspecting Ranked must cross-reference OutputURLs for
// the final weighted order.
//
// NOTE: Trace is a shallow copy — Reasons (map) and Ranked/Suppressed (slices)
// are aliased to inner's return value. Do not mutate these fields on the returned
// trace; doing so would race with no locking on the shared backing arrays.

import (
	"context"
	"math"
	"sort"

	"github.com/gosuda/portal-tunnel/v2/portal/discovery"
)

// Compile-time assertion: *Composite must satisfy discovery.Selector.
var _ discovery.Selector = (*Composite)(nil)

// Composite wraps an inner Selector and applies a load-aware additive penalty
// to produce a post-ordered relay list. See package doc for details.
type Composite struct {
	inner   discovery.Selector
	lambda  float64
	epsilon float64
	beta    float64
}

// Option is a functional option for Composite.
type Option func(*Composite)

// WithLambda sets the additive penalty weight applied to tier_load.
// Higher values amplify the effect of load on final ranking.
// Default: 1.0.
func WithLambda(lambda float64) Option {
	return func(c *Composite) { c.lambda = lambda }
}

// WithEpsilon sets the tier width for load quantization.
// Loads within the same tier produce identical tier_load values, suppressing
// sub-tier rank flap. A value of 0 disables quantization (raw load used).
// Default: 0.1.
func WithEpsilon(epsilon float64) Option {
	return func(c *Composite) { c.epsilon = epsilon }
}

// WithBeta sets the multiplier on FailureRate when composing load_factor.
// load = RelayState.LoadFactor + RelayState.FailureRate * beta.
// Default: 1.0.
func WithBeta(beta float64) Option {
	return func(c *Composite) { c.beta = beta }
}

// New returns a Composite wrapping inner.
// Defaults: lambda=1.0, epsilon=0.1, beta=1.0.
// Pass mols.New() (or any other Selector) as inner.
func New(inner discovery.Selector, opts ...Option) *Composite {
	c := &Composite{
		inner:   inner,
		lambda:  1.0,
		epsilon: 0.1,
		beta:    1.0,
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// Name returns the canonical name of this selector.
func (c *Composite) Name() string { return "weighted" }

// tierLoad quantizes the raw load value to the nearest tier boundary below it.
func (c *Composite) tierLoad(rawLoad float64) float64 {
	if c.epsilon > 0 {
		return math.Floor(rawLoad/c.epsilon) * c.epsilon
	}
	return rawLoad
}

// weightedEntry holds per-relay data for sorting.
type weightedEntry struct {
	url      string
	position int     // original inner-selector position (0-based)
	tierLoad float64 // quantized load
	final    float64 // position + lambda * tierLoad
}

// applyPenalty computes the weighted ordering over inner_urls using pool state.
func (c *Composite) applyPenalty(innerURLs []string, pool []discovery.RelayState) []string {
	if len(innerURLs) == 0 {
		return innerURLs
	}

	// Build URL -> RelayState map for O(1) load lookup.
	stateByURL := make(map[string]discovery.RelayState, len(pool))
	for _, s := range pool {
		stateByURL[s.Descriptor.APIHTTPSAddr] = s
	}

	ws := make([]weightedEntry, len(innerURLs))
	for i, u := range innerURLs {
		s := stateByURL[u]
		rawLoad := s.LoadFactor + s.FailureRate*c.beta
		tl := c.tierLoad(rawLoad)
		ws[i] = weightedEntry{
			url:      u,
			position: i,
			tierLoad: tl,
			final:    float64(i) + c.lambda*tl,
		}
	}

	// Stable sort by final ascending; ties preserve original (inner) order.
	sort.SliceStable(ws, func(a, b int) bool { return ws[a].final < ws[b].final })

	out := make([]string, len(ws))
	for i, w := range ws {
		out[i] = w.url
	}
	return out
}

// SelectPriority implements discovery.Selector. It calls the inner selector for
// MOLS-position ranking, then applies the load-penalty reordering. The returned
// trace reflects inner scoring with OutputURLs replaced by the weighted order.
func (c *Composite) SelectPriority(ctx context.Context, pool []discovery.RelayState, client discovery.ClientState) ([]string, discovery.SelectionTrace) {
	innerURLs, innerTrace := c.inner.SelectPriority(ctx, pool, client)
	out := c.applyPenalty(innerURLs, pool)

	// Shallow-copy the trace; only OutputURLs is replaced (see package doc).
	trace := innerTrace
	trace.OutputURLs = out
	return out, trace
}

// SelectMultiHop implements discovery.Selector. It calls the inner selector for
// MOLS-position ranking, then applies the load-penalty reordering. The returned
// trace reflects inner scoring with OutputURLs replaced by the weighted order.
func (c *Composite) SelectMultiHop(ctx context.Context, pool []discovery.RelayState, client discovery.ClientState) ([]string, discovery.SelectionTrace) {
	innerURLs, innerTrace := c.inner.SelectMultiHop(ctx, pool, client)
	out := c.applyPenalty(innerURLs, pool)

	// Shallow-copy the trace; only OutputURLs is replaced (see package doc).
	trace := innerTrace
	trace.OutputURLs = out
	return out, trace
}
