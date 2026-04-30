package discovery

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

// maxRelayLabelCardinality is the hard cap on distinct relay-URL values used as
// Prometheus labels. URLs beyond the first 64 distinct values are bucketed as
// relay="other" to prevent unbounded cardinality.
const maxRelayLabelCardinality = 64

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

// boundedRelay returns url unchanged when the URL is already known or when
// the distinct-URL count is below maxRelayLabelCardinality.
// Any URL that would exceed the cap is returned as "other".
func boundedRelay(url string) string {
	relayBudget.mu.Lock()
	defer relayBudget.mu.Unlock()
	if _, ok := relayBudget.seen[url]; ok {
		return url
	}
	if len(relayBudget.seen) >= maxRelayLabelCardinality {
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

// DiversityRelaxedTotal counts diversity-constraint relaxations during
// multi-hop selection. reason has exactly 2 values:
//   - "anonymity_grade": AnonymityGrade constraint (Subnet16 + Family dedup)
//     was relaxed due to pool shortfall.
//   - "role_separation": URL-uniqueness (role-separation) constraint was
//     relaxed due to pool shortfall; inner result returned unchanged.
var DiversityRelaxedTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "portal_discovery_diversity_relaxed_total",
		Help: "Diversity-constraint relaxations during multi-hop selection.",
	},
	[]string{"reason"},
)

// --------------------------------------------------------------------------
// EmitFromTrace
// --------------------------------------------------------------------------

// EmitFromTrace updates relevant Prometheus metrics from a completed
// SelectionTrace. It is safe to call concurrently.
//
// Metrics updated:
//   - relay_selected_total{relay, reason} — one increment per OutputURL.
//   - selection_duration_seconds — one observation for the whole invocation.
//   - congestion_mode — set according to Congested + NonLinear.
//   - selection_skipped_total{reason} — one increment per suppressed URL that
//     has a reason entry.
//   - rtt_seconds{relay} — one observation per Ranked entry with non-zero RTT.
//
// Metrics NOT updated here (wired by later phases / other code paths):
//   - relay_pool_size — set by RelaySet pool management.
//   - active_tunnels_per_relay — incremented/decremented at tunnel accept/close.
//   - failures_total — incremented on discovery/active failure events.
func EmitFromTrace(t SelectionTrace) {
	// --- relay_selected_total ---
	reason := selectionReason(t)
	for _, url := range t.OutputURLs {
		RelaySelectedTotal.WithLabelValues(boundedRelay(url), reason).Inc()
	}

	// --- selection_duration_seconds ---
	SelectionDurationSeconds.Observe(t.SelectionTook.Seconds())

	// --- congestion_mode ---
	CongestionMode.Set(congestionModeValue(t.Congested, t.NonLinear))

	// --- selection_skipped_total ---
	// Build suppressed set for O(1) lookup.
	suppressedSet := make(map[string]struct{}, len(t.Suppressed))
	for _, url := range t.Suppressed {
		suppressedSet[url] = struct{}{}
	}
	for url, reason := range t.Reasons {
		if _, ok := suppressedSet[url]; ok {
			SelectionSkippedTotal.WithLabelValues(reason).Inc()
		}
	}

	// --- rtt_seconds ---
	for _, entry := range t.Ranked {
		if entry.RTT != 0 {
			RTTSeconds.WithLabelValues(boundedRelay(entry.URL)).Observe(entry.RTT.Seconds())
		}
	}
}

// selectionReason derives the reason label for relay_selected_total from the
// trace flags. Explicit/fallback semantics are wired by later phases; this
// function defaults to "auto" for uninstrumented call sites.
func selectionReason(t SelectionTrace) string {
	switch {
	case t.NonLinear:
		return "variant-grid"
	case t.Congested:
		return "congestion-promoted"
	default:
		return "auto"
	}
}

// congestionModeValue maps the Congested + NonLinear pair to the metric value.
// 0 = normal, 1 = congested without variant-grid, 2 = variant-grid active.
func congestionModeValue(congested, nonLinear bool) float64 {
	switch {
	case nonLinear:
		return 2
	case congested:
		return 1
	default:
		return 0
	}
}
