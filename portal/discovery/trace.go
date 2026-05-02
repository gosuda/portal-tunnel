package discovery

// SelectionTrace records observability data for a single relay-selection
// invocation. The struct is populated by SelectPriorityWithTrace /
// SelectMultiHopWithTrace on MOLSRelayPolicy and by the matching siblings on
// RelaySet, and consumed by:
//
//   - portal/telemetry/metrics.go — emits low-cardinality fields to Prometheus
//     (no per-client labels: ClientHash never becomes a metric label).
//   - sampled debug logs (zerolog) — ClientHash carried; LocalAddress
//     intentionally NOT carried in the trace (PII-leak surface; ClientHash is
//     sufficient for log correlation).
//
// The trace is not part of the public RelaySet API; it is consumed in-process
// only.
//
// See /home/alpha/.claude/plans/sophisticate-and-rationalize-discovery-rosy-parnas.md
// (Phase 1 — Telemetry only) for the rationale.

