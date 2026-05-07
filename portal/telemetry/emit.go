package telemetry

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
		RelaySelectedTotal.WithLabelValues(BoundedRelay(url), reason).Inc()
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
			RTTSeconds.WithLabelValues(BoundedRelay(entry.URL)).Observe(entry.RTT.Seconds())
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
