package telemetry

// metrics.go — Phase 1 Prometheus telemetry surface for portal/discovery.
//
// Registers 8 low-cardinality metrics on prometheus.DefaultRegisterer via
// promauto. Provides EmitFromTrace(SelectionTrace) to update counter/histogram/
// gauge metrics from a completed selection invocation.
//
// Cardinality discipline:
//   - NO per-client labels (no client_hash, no local_address).
//   - Relay-label cardinality capped at maxRelayLabelCardinality unique URLs;
//     additional URLs are bucketed under relay="other".
//
// See /home/alpha/.claude/plans/sophisticate-and-rationalize-discovery-rosy-parnas.md
// (Phase 1 — Telemetry only) for rationale.

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// MaxRelayLabelCardinality is the hard cap on distinct relay-URL values used as
// Prometheus labels. URLs beyond the first 64 distinct values are bucketed as
// relay="other" to prevent unbounded cardinality.
const MaxRelayLabelCardinality = 64

// relayBudget guards relay-URL cardinality with a single mutex so that the
// membership set and the count are always updated atomically. This prevents
// the race where two goroutines each see "URL not present" and both increment
// the counter, prematurely exhausting the 64-label budget.
var relayBudget = struct {
	mu   sync.Mutex
	seen map[string]struct{}
}{
	seen: make(map[string]struct{}),
}

// BoundedRelay returns url unchanged when the URL is already known or when
// the distinct-URL count is below MaxRelayLabelCardinality.
// Any URL that would exceed the cap is returned as "other".
func BoundedRelay(url string) string {
	relayBudget.mu.Lock()
	defer relayBudget.mu.Unlock()
	if _, ok := relayBudget.seen[url]; ok {
		return url
	}
	if len(relayBudget.seen) >= MaxRelayLabelCardinality {
		return "other"
	}
	relayBudget.seen[url] = struct{}{}
	return url
}

// --------------------------------------------------------------------------
// Metric registrations
// --------------------------------------------------------------------------

// RelaySelectedTotal counts relay-selection events by (relay, reason).
// reason ∈ {explicit, auto, fallback, congestion-promoted, variant-grid}.
var RelaySelectedTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "portal_discovery_relay_selected_total",
		Help: "Total relays selected by reason.",
	},
	[]string{"relay", "reason"},
)

// RelayPoolSize is a gauge of auto-pool size partitioned by state.
// state ∈ {total, active, banned, expired, suppressed, fallback}.
var RelayPoolSize = promauto.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "portal_discovery_relay_pool_size",
		Help: "Auto-pool size by state.",
	},
	[]string{"state"},
)

// RTTSeconds is a histogram of per-relay discovery RTT observations.
// label: relay. Buckets: 10 ms … 5 s.
var RTTSeconds = promauto.NewHistogramVec(
	prometheus.HistogramOpts{
		Name:    "portal_discovery_rtt_seconds",
		Help:    "Discovery RTT per relay (seconds).",
		Buckets: []float64{0.010, 0.050, 0.100, 0.250, 0.500, 1.0, 2.0, 5.0},
	},
	[]string{"relay"},
)

// ActiveTunnelsPerRelay is a gauge of tunnel count for each relay.
// SDK-local measurement: tracks this process's tunnel distribution only.
var ActiveTunnelsPerRelay = promauto.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "portal_discovery_active_tunnels_per_relay",
		Help: "SDK-local; measures this exposure's tunnel distribution, not relay-wide load.",
	},
	[]string{"relay"},
)

// SelectionDurationSeconds is a histogram of wall time per selection call.
// No labels; uses prometheus default buckets.
var SelectionDurationSeconds = promauto.NewHistogram(
	prometheus.HistogramOpts{
		Name: "portal_discovery_selection_duration_seconds",
		Help: "Wall time of a single relay-selection invocation.",
		// Default prometheus buckets (.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10).
	},
)

// SelectionSkippedTotal counts relays excluded from selection by reason.
// reason ∈ {expired, require_udp, require_tcp, suppressed, banned, no_descriptor, no_overlay_peer}.
var SelectionSkippedTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "portal_discovery_selection_skipped_total",
		Help: "Relays skipped during selection by reason.",
	},
	[]string{"reason"},
)

// FailuresTotal counts discovery and active-path failures per relay.
// labels: relay, kind ∈ {discovery, active}.
var FailuresTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "portal_discovery_failures_total",
		Help: "Discovery and active failures per relay.",
	},
	[]string{"relay", "kind"},
)

// CongestionMode is a gauge encoding the current congestion state.
// 0 = normal, 1 = congested (no variant-grid), 2 = variant-grid active.
var CongestionMode = promauto.NewGauge(
	prometheus.GaugeOpts{
		Name: "portal_discovery_congestion_mode",
		Help: "Active congestion mode (0=normal, 1=congested, 2=variant-grid).",
	},
)
